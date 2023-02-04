import random


class Primes(object):

    def __div2__(self,n):
        e = n-1
        m = 0
        while e % 2 == 0:
            e //= 2
            m += 1
        return e, m

    def __iterat__(self, a, e, m, n):
        if pow(a, e, n) == 1:
            return True

        for i in range(m):
            if pow(a,2**i*e,n)==n-1:
                return True
        return False

    def milerRabin(self,n):
        e, m = self.__div2__(n)
        for i in range(20):
            a = random.randrange(2, n)
            if self.__iterat__(a,e,m,n):
                continue
            else:
                return False
        return True

    def __randomBit__(self,n):
        return(random.randrange(2**(n-1)+1, 2**n-1))

    def isprime(self,num):
        primes=[2,3,5]
        if num==0:
            return False
        if num==1:
            return False
        if num in primes:
            return True
        elif num < 5:
            return False

        if num%(num//2)==0:
            return False

        else:
             for i in range(2,int(num**0.5)+1):
                if num%i==0:
                    return False
        return True


    def get_prime(self,n):
        primes=[]
        for i in range(1000):
            if self.isprime(i):
                primes.append(i)
        while True:
            p = self.__randomBit__(n)
            c=0
            for i in primes:
                if p%i==0:
                    c=1
                    break
            if c==0:
                if self.milerRabin(p):
                    return p    