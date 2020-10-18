import sys
import warnings


__version__ = '20201018'

if sys.version_info < (3, 6):
    warnings.warn('Python 3.4 and 3.5 are deprecated. '
                  'Please upgrade to Python 3.6 or newer.')

if __name__ == '__main__':
    print(__version__)
