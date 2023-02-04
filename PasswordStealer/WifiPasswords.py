from Design.des import Color,colorama


class WifiPass(object):
    
    def __getPassUsers__(self,out):
        users,pswd = list(), list()
        for i in out.splitlines():
            i = i.split('     :    ')
            users.append(i[0])
            pswd.append(i[-1])
        return users,pswd

    def sortCollored(self,out):
        res,l,r,g,rs = str(),Color().lYellow, Color().lRed, Color().lgreen, colorama.Style.RESET_ALL
        users,pswd = self.__getPassUsers__(out)
        res+= r+("="*13+' Wifi Passwords '+'='*13)+'\n'
        for i in range(len(users)):
            res+=f"{l+users[i]:<30}{g+pswd[i]:<50}{rs}\n"
        return res