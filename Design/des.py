import colorama
import time
import pyfiglet



colorama.init()

class Color(object):
    def __init__(self):
        self.lgreen = colorama.Fore.LIGHTGREEN_EX
        self.lYellow = colorama.Fore.LIGHTYELLOW_EX
        self.lRed = colorama.Fore.LIGHTRED_EX

    def inuptCommand(self,ip,hostname,priv):
        print()
        test = f"""{self.lRed}┌─[{self.lgreen}{ip}@{self.lYellow}{hostname}{self.lRed}]─[{priv}]
        └──╼> """.replace('    ','')
        out =  input(test+self.lgreen)
        print(colorama.Style.RESET_ALL)
        return out

    def scan(self,text):
        return input(self.lgreen+text+self.lgreen)

    def printg(self,out,end='\n'):
        print(self.lgreen+out+colorama.Style.RESET_ALL,end=end)


    def printr(self,out,end='\n'):
        print(self.lRed+out+colorama.Style.RESET_ALL,end=end)


    def loading(self,content,t,r):
        for x in range(r):
            print(self.lRed+'━' * (x) + content, '', end='\r')
            time.sleep(t)
        print(colorama.Style.RESET_ALL)

    def printy(self,out,end='\n'):
        print(self.lYellow+out+colorama.Style.RESET_ALL,end=end)

    def printCommand(self,out):
        if out[:12] == '=A+Z-E^R^O&R':
            print(self.lRed+out[12:])
        else:
            print(self.lgreen+out)
    
    def wellcome(self):
        result=pyfiglet.figlet_format("Enigma", font = "doh", width = 1500)
        import time
        for i in result.splitlines():
            print(colorama.Fore.LIGHTRED_EX+i)
            time.sleep(0.04)

    def getTools(self,tools):
        print()
        print(f"{colorama.Fore.LIGHTRED_EX}========loading Tools=========")
        for i in tools:
            print(
                f"  {self.lRed}---->> {self.lgreen}{i}{' '*(30-(len(i)+15))}   {self.lYellow}{'[+]'}"
            )
        print()