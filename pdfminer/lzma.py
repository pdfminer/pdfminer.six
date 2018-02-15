try:
    from lzma import *
except ImportError:
    try: 
        from backports.lzma import *
    except ImportError:
        from pylzma import *
