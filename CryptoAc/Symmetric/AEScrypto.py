from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from hashlib import md5
from os import urandom

class AESencryption(object):

    def __init__(self,key,iv):
        self.key=key
        self.iv = iv
        self.cipher = AES.new(self.key,AES.MODE_CBC,self.iv)
        self.cipher2 = AES.new(self.key,AES.MODE_CBC,self.iv)
#         self.cipher=AES.new(key, AES.MODE_CBC, iv)
#         self.cipher2 = AES.new(key, AES.MODE_CBC, iv)


    def padData(self,data):
        return data + bytes(len(data)%16) + bytes([len(data)%16])

    def encrypt(self,data):
        return self.cipher2.encrypt(pad(data,AES.block_size))

    def decrypt(self,encrypted_data):
        self.cipher.IV = self.randomIv(self.cipher.IV)
        return unpad(
            self.cipher.decrypt(encrypted_data),
            AES.block_size
        )
    
    def randomIv(self,oldIv):
        return md5(oldIv).digest()
    
    def randomKey(self):
        return urandom(32)