class Euclids(object):
        
    def gcd(self,a,b):
        while True:
            if a==0 or b==0:
                break
            a,b = a % b, b % a
            r = b + a
        return r
    
    def gcdx(self,a,b):
        if a==0:
            return b,0,1
        r = b % a
        r,x1,y1= self.gcdx(r,a)
        x = y1 - (b//a) * x1
        y = x1
        return r,x,y