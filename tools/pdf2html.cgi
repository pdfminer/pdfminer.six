#!/usr/bin/python
#
# pdf2html.cgi - Gateway for converting PDF into HTML.
#
# Security consideration for public access:
#
#   Limit the process size and/or running time.
#   The process should be chrooted.
#   The user should be imposed quota.
#
# Setup:
#   $ mkdir $CGIDIR
#   $ mkdir $CGIDIR/var
#   $ python setup.py install_lib --install-dir=$CGIDIR
#   $ cp pdfminer/tools/pdf2html.cgi $CGIDIR
#

import sys
# comment out at runtime.
import cgitb; cgitb.enable()
import os, os.path, re, cgi, time, random, codecs, logging, traceback
from pdfminer.pdfinterp import PDFResourceManager, process_pdf
from pdfminer.converter import HTMLConverter, TextConverter
from pdfminer.layout import LAParams


# quote HTML metacharacters
def q(x):
    return x.replace('&','&amp;').replace('>','&gt;').replace('<','&lt;').replace('"','&quot;')

# encode parameters as a URL
Q = re.compile(r'[^a-zA-Z0-9_.-=]')
def url(base, **kw):
    r = []
    for (k,v) in kw.iteritems():
        v = Q.sub(lambda m: '%%%02X' % ord(m.group(0)), encoder(q(v), 'replace')[0])
        r.append('%s=%s' % (k, v))
    return base+'&'.join(r)


##  convert
##
class FileSizeExceeded(ValueError): pass
def convert(outfp, infp, path, codec='utf-8',
            maxpages=0, maxfilesize=0, pagenos=None,
            html=True):
    # save the input file.
    src = file(path, 'wb')
    nbytes = 0
    while 1:
        data = infp.read(4096)
        nbytes += len(data)
        if maxfilesize and maxfilesize < nbytes:
            raise FileSizeExceeded(maxfilesize)
        if not data: break
        src.write(data)
    src.close()
    infp.close()
    # perform conversion and
    # send the results over the network.
    rsrc = PDFResourceManager()
    laparams = LAParams()
    if html:
        device = HTMLConverter(rsrc, outfp, codec=codec, laparams=laparams)
    else:
        device = TextConverter(rsrc, outfp, codec=codec, laparams=laparams)
    fp = file(path, 'rb')
    process_pdf(rsrc, device, fp, pagenos, maxpages=maxpages)
    fp.close()
    return


##  PDF2HTMLApp
##
class PDF2HTMLApp(object):

    APPURL = '/convert'
    MAXFILESIZE = 5000000
    MAXPAGES = 10

    def __init__(self, outfp=sys.stdout, codec='utf-8'):
        self.outfp = outfp
        self.codec = codec
        self.remote_addr = os.environ.get('REMOTE_ADDR')
        self.path_info = os.environ.get('PATH_INFO')
        self.method = os.environ.get('REQUEST_METHOD', 'GET')
        self.server = os.environ.get('SERVER_SOFTWARE', '')
        self.logpath = os.environ.get('LOG_PATH', './var/log')
        self.tmpdir = os.environ.get('TEMP', './var/')
        self.debug = os.environ.get('DEBUG')
        self.content_type = 'text/html; charset=%s' % codec
        self.cur_time = time.time()
        return

    def put(self, *args):
        for x in args:
            if isinstance(x, str):
                self.outfp.write(x)
            elif isinstance(x, unicode):
                self.outfp.write(x.encode(self.codec, 'xmlcharrefreplace'))
        return

    def http_200(self):
        if self.server.startswith('cgi-httpd'):
            # required for cgi-httpd
            self.outfp.write('HTTP/1.0 200 OK\r\n')
        self.outfp.write('Content-type: %s\r\n' % self.content_type)
        self.outfp.write('Connection: close\r\n\r\n')
        return

    def http_404(self):
        if self.server.startswith('cgi-httpd'):
            # required for cgi-httpd
            self.outfp.write('HTTP/1.0 404 Not Found\r\n')
        self.outfp.write('Content-type: text/html\r\n')
        self.outfp.write('Connection: close\r\n\r\n')
        self.outfp.write('<html><body>page does not exist</body></body>\n')
        return

    def http_301(self, url):
        if self.server.startswith('cgi-httpd'):
            # required for cgi-httpd
            self.outfp.write('HTTP/1.0 301 Moved\r\n')
        self.outfp.write('Location: %s\r\n\r\n' % url)
        return

    def coverpage(self):
        self.put(
          '<html><head><title>pdf2html demo</title></head><body>\n',
          '<h1>pdf2html demo</h1><hr>\n',
          '<form method="POST" action="%s" enctype="multipart/form-data">\n' % q(self.APPURL),
          '<p>Upload PDF File: <input name="f" type="file" value="">\n',
          '&nbsp; Page numbers (comma-separated):\n',
          '<input name="p" type="text" size="10" value="">\n',
          '<p>(Text extraction is limited to maximum %d pages.\n' % self.MAXPAGES,
          'Maximum file size for input is %d bytes.)\n' % self.MAXFILESIZE,
          '<p><input type="submit" name="c" value="Convert to HTML">\n',
          '<input type="submit" name="c" value="Convert to TEXT">\n',
          '<input type="reset" value="Reset">\n',
          '</form><hr>\n',
          '<p>Powered by <a href="http://www.unixuser.org/~euske/python/pdfminer/">PDFMiner</a>\n',
          '</body></html>\n',
          )
        return

    def run(self, argv):
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
        if self.debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.ERROR,
                                filename=self.logpath, filemode='a')
        if self.path_info == '/':
            self.http_200()
            self.coverpage()
            return
        if self.path_info != self.APPURL:
            self.http_404()
            return
        if not os.path.isdir(self.tmpdir):
            self.bummer('error')
            return
        form = cgi.FieldStorage()
        if 'f' not in form:
            self.http_301('/')
            return
        if 'c' not in form:
            self.http_301('/')
            return
        item = form['f']
        if not (item.file and item.filename):
            self.http_301('/')
            return
        cmd = form.getvalue('c')
        html = (cmd == 'Convert to HTML')
        pagenos = []
        if 'p' in form:
            for m in re.finditer(r'\d+', form.getvalue('p')):
                try:
                    pagenos.append(int(m.group(0)))
                except ValueError:
                    pass
        logging.info('process: host=%s, name=%r, pagenos=%r' %
                     (self.remote_addr, item.filename, pagenos))
        h = abs(hash((random.random(), self.remote_addr, item.filename)))
        tmppath = os.path.join(self.tmpdir, '%08x%08x.pdf' % (self.cur_time, h))
        try:
            try:
                if not html:
                    self.content_type = 'text/plain; charset=%s' % self.codec
                self.http_200()
                convert(sys.stdout, item.file, tmppath, pagenos=pagenos, codec=self.codec,
                        maxpages=self.MAXPAGES, maxfilesize=self.MAXFILESIZE, html=html)
            except Exception, e:
                self.put('<p>Sorry, an error has occured: %s' % q(repr(e)))
                logging.error('error: %r: path=%r: %s' % (e, tmppath, traceback.format_exc()))
        finally:
            try:
                os.remove(tmppath)
            except:
                pass
        return


# main
if __name__ == '__main__': sys.exit(PDF2HTMLApp().run(sys.argv))
