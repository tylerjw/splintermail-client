from urllib import request
import urllib.error
from sys import argv,exit,stderr
from zipfile import ZipFile
from io import BytesIO
import traceback

# nssm.exe is the Non-Sucking Service Manager
# see https://nssm.cc

if __name__ == '__main__':
    print('asking splintermail which version of nssm we want...',file=stderr)
    try:
        req = request.urlopen('https://splintermail.com/downloads/latest_nssm.txt')
    except:
        traceback.print_exc()
        exit(2)
    nssm_path = req.read().strip().decode('utf8')

    print('downloading nssm.exe...',file=stderr)
    # get the nssm build directly from nssm.cc
    try:
        req = request.urlopen('https://nssm.cc'+nssm_path)
    except:
        traceback.print_exc()
        exit(2)
    bio = BytesIO(req.read())
    # extract nssm.exe directly from zip file
    z = ZipFile(bio,'r')
    with open('nssm.exe','wb') as f:
        f.write(z.read(z.namelist()[0]+'win32/nssm.exe'))
    z.close()
