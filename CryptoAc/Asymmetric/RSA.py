from .Primes import Primes
from .Euclids import Euclids
from hashlib import sha256

class RSA(object):
    
    def __init__(self):
        self.prime = Primes()
        self.nBit=1024
        
  
    def genKey(self,nBit):
        assert (nBit >= 512)
        e = 65537
        p = self.prime.get_prime(nBit)
        q = self.prime.get_prime(nBit)
        n = p*q
        phi = (p-1)*(q-1)
        _,x,_ = Euclids().gcdx(e,phi)
        assert (e*(phi+x)%phi==1)
        d = phi+x
        private = {'d':d,'n':n,'e':e,'p':p,'q':q}
        public = {'n':n,'e':e}
        return {"private":private,'public':public}
    
    def __intToBytes__(self,n):
        p = (n.bit_length()+7)//8
        b = n.to_bytes(p, 'big')
        return b
    
    
    def __intFromBytes__(self,_bytes):
        return int.from_bytes(_bytes, 'big')
    
    def __encrypt__(self,m,e,n):
        return pow(m,e,n)
    
    def __decrypt__(self,m,d,n):
        return pow(m,d,n)
    
    def __getNbit__(self,n):
        c=3
        while True:
            if (2**c) // n > 0:
                return c
            c+=1
            
    def encrypt(self,public,message):
        n = public['n']
        message = self.__intFromBytes__(message)
        if message >= n:
            raise Exception ('Data must be smaller than or equal to  '+str(self.__getNbit__(n)//8)+' bytes')
        e = public['e']
        return self.__intToBytes__(self.__encrypt__(message,e,n))
    
    def decrypt(self,private,message):
        d=private['d']
        n=private['n']
        e=private['e']
        m = self.__intFromBytes__(message)
        return self.__intToBytes__(self.__decrypt__(m,d,n))
    
    def signature(self,private,message):
        h = sha256(message).digest()
        hs= self.__intFromBytes__(h)
        d = private['d']
        n = private['n']
        return self.__intToBytes__(pow(hs,d,n))
    
    def verify_signature(self,public,signature,message):
        h = sha256(message).digest()
        e,n = public['e'],public['n']
        if self.__intToBytes__(pow(self.__intFromBytes__(signature),e,n))==h:
            return True
        return False
        
        
