import os

def getpath(name):
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(here, name)
