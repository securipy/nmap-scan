#!/usr/bin/python
#-*-coding:utf-8-*-

class CalcIP:

    def str2list(self, STRing):    # each element separed by dot
        parts = STRing.split('.')    # parts=['0','1','2','3']
        List = []
        List.append(int(parts[0]))
        List.append(int(parts[1]))
        List.append(int(parts[2]))
        List.append(int(parts[3]))
        return List        #  list=[0,1,2,3], int elements

    def list2string(self, List):
        return '%s.%s.%s.%s' %(List[0],List[1],List[2],List[3])

    def bits2cero(self, numeroConvertir,numBits2cero):
        # converts to 0 x number of bits of numeroConvertir starting at rigth (x=numBits2cero)
        numeroConvertir = int(numeroConvertir) # make sure is an integer
        for i in range(numBits2cero):
            numeroConvertir=numeroConvertir&(255<<(i+1)) # 255=11111111->not elimiate left numbers of numeroConvertir
        return numeroConvertir

    def bits2one(self, numeroConvertir,numBits2one):
        # converts to 1 x number of bits of numeroConvertir starting at rigth (x=numBits2one)
        numeroConvertir = int(numeroConvertir) # make sure is an integer
        for i in range(numBits2one):
            numeroConvertir=numeroConvertir|1<<i # all ones
        return numeroConvertir

    def makeBase(self, ip, bits4hosts): # ip[=]list
        ipBase=list(ip)
        if bits4hosts<=8:
            ipBase[3]=self.bits2cero(ip[3],bits4hosts)
        elif bits4hosts<=16:
            ipBase[3]=self.bits2cero(ip[3],8)
            ipBase[2]=self.bits2cero(ip[2],bits4hosts-8)
        elif bits4hosts<=24:
            ipBase[3]=self.bits2cero(ip[3],8)
            ipBase[2]=self.bits2cero(ip[2],8)
            ipBase[1]=self.bits2cero(ip[1],bits4hosts-16)
        else:
            ipBase[3]=self.bits2cero(ip[3],8)
            ipBase[2]=self.bits2cero(ip[2],8)
            ipBase[1]=self.bits2cero(ip[1],8)
            ipBase[0]=self.bits2cero(ip[0],bits4hosts-24)
        # list of integers
        ipBase = [int(ipBase[0]), int(ipBase[1]), int(ipBase[2]), int(ipBase[3])]
        return ipBase

    def makeBroadcast(self, ip, bits4hosts): # ip[=]list
        ipBroadcast=list(ip)
        if bits4hosts<=8:
            ipBroadcast[3]=self.bits2one(ip[3],bits4hosts)
        elif bits4hosts<=16:
            ipBroadcast[3]=self.bits2one(ip[3],8)
            ipBroadcast[2]=self.bits2one(ip[2],bits4hosts-8)
        elif bits4hosts<=24:
            ipBroadcast[3]=self.bits2one(ip[3],8)
            ipBroadcast[2]=self.bits2one(ip[2],8)
            ipBroadcast[1]=self.bits2one(ip[1],bits4hosts-16)
        else:
            ipBroadcast[3]=self.bits2one(ip[3],8)
            ipBroadcast[2]=self.bits2one(ip[2],8)
            ipBroadcast[1]=self.bits2one(ip[1],8)
            ipBroadcast[0]=self.bits2one(ip[0],bits4hosts-24)
        ipBroadcast = [int(ipBroadcast[0]), int(ipBroadcast[1]), int(ipBroadcast[2]), int(ipBroadcast[3])]
        return ipBroadcast

    def makeMaskHexList(self,mask):
        if '.' in mask: # mask parts separated by dot
            try:
                maskList = mask.split('.') # list of strings
            except:
                return -1
        else:
            try:
                maskList = [mask[0:2], mask[2:4], mask[4:6], mask[6:8]] # list of strings
            except:
                return -1
        if self.checkMaskHexSyntax(maskList) == 1:
            return maskList
        else:
            return -1

    def makeMaskDecimalList(self,mask):
        maskList = self.str2list(mask)
        if self.checkMaskDecimalSyntax(maskList) == 1:
            return maskList
        else:
            return -1

    def makeMask(self, mask):
        maskNotation = self.retrieveMaskNotation(mask)
        if maskNotation == 'hexadecimal':
            maskListHex = self.makeMaskHexList(mask)
            if maskListHex == -1:
                mask = -1
                bits4hosts = -1
            else:
                maskListDecimal = self.makeMaskHex2decimal(maskListHex)
                bits4hosts = self.bits4hosts(maskListDecimal)
                mask = 32-bits4hosts
        elif maskNotation == 'CIDR':
            if len(mask) <= 2:
                bits4hosts = 32-int(mask)
            else:
                mask = -1
                bits4hosts = -1
        elif maskNotation == 'decimal':
            maskList = self.makeMaskDecimalList(mask)
            if maskList == -1:
                mask = -1
                bits4hosts = -1
            else:
                bits4hosts = self.bits4hosts(maskList)
                mask = 32-bits4hosts
        else:
            mask = -1
            bits4hosts = -1
        return mask, bits4hosts

    def makeMaskHex2decimal(self,maskHexList):
        partDecimal1 = int(maskHexList[0],16) # int
        partDecimal2 = int(maskHexList[1],16)
        partDecimal3 = int(maskHexList[2],16)
        partDecimal4 = int(maskHexList[3],16)
        maskDecimalList = [partDecimal1, partDecimal2, partDecimal3, partDecimal4] # list of integers
        return maskDecimalList

    def makeIPandMask(self, ip_mask):
        # separate ip and mask
        try:
            separateParts = ip_mask.split('/')
            # get each part
            ip = separateParts[0]    # ip = '0.1.2.3'
            ipParts = self.retrieveIPparts(ip) # ipParts = ['0','1','2','3']
            mask = separateParts[1]    # mask = '24', string
        except:
            ipParts = -1
            mask = -1
        # return results
        return ipParts, mask

    def retrieveMaskNotation(self,mask):
        if self.checkHexCharacter(mask) == 1:
            return 'hexadecimal'
        elif self.checkCharacterInStr(mask) == -1:
            if '.' in mask:
                return 'decimal'
            else:
                return 'CIDR'
        else:
            return -1

    def retrieveIPparts(self, ip):
        # check if there are 4 parts and are strings represents integers
        check4parts = self.check4partsByDot(ip)
        if check4parts == 1:
            ipParts = ip.split('.') # get parts separated by dot
            checkIntStrings = self.checkListIntStrings(ipParts)
            if checkIntStrings == 1:
                return ipParts
        return -1

    def checkHexCharacter(self, string2study):
         # if one of these characters is in the string, it returns 1
        hexadecimalCharacters = 'abcdef'
        chars = set(hexadecimalCharacters)
        if any((str_ch in chars) for str_ch in string2study):
            return 1
        else:
            return -1

    def checkHexCharacterNumbers(self, string2study):
        # if any mask character is not ones of the hexadecimal characters the syntax is wrong
        hexadecimalCharacters = 'abcdef0123456789'
        chars = set(hexadecimalCharacters)
        if any((str_ch not in chars) for str_ch in string2study):
            return -1
        else:
            return 1

    def checkMaskHexSyntax(self, maskList):
        # check if mask in hexadecimal notation is correct
        # check number of parts
        if len(maskList) != 4:
            return -1
        # check each part
        for part in maskList:
            # check syntax
            if self.checkHexCharacterNumbers(part) == -1:
                return -1
            # check lengt
            if len(part) != 2:
                return -1
        return 1

    def checkMaskDecimalSyntax(self, maskList):
        # check if mask in hexadecimal notation is correct
        # check number of parts
        if len(maskList) != 4:
            return -1
        # check each part
        for part in maskList:
            part = str(part) # make sure is a string (sometimes is an integer)
            # check syntax
            if self.checkCharacterInStr(part) == 1:
                return -1
        return 1

    def checkCharacterInStr(self, string2study):
        # if a character is in a string, it returns 1
        chars = set('abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMÑNOPQRSTUVWXYZ')
        if any((str_ch in chars) for str_ch in string2study):
            return 1
        else:
            return -1

    def check4partsByDot(self, string2study):
        # check if there are four parts separated by three dots
        parts = string2study.split('.') # get parts separated by dot
        if len(parts) == 4:
            return 1
        else:
            return -1

    def checkListIntStrings(self, list2study):
        # check if strings in a list are integers
        # it detects, for example, if a number is not indicated. Example: 192.168.1.
        for part in list2study:
            try:
                int(part) # string contains an integer
            except:
                return -1
        return 1

    def bits4hostsInAPart(self, maskPart):    # maskPart = 8bits
        # searchs number of 0's, started at rigth
        hostsBits = 0
        multi = 1    # searchs 0's at mask
        while (len(bin(multi))-2)<=8:    # bin(multi)='0b..'
            if maskPart&multi==0:
                hostsBits += 1
            else:
                return hostsBits
            multi = multi << 1
        return hostsBits

    def bits4hosts(self, maskList):     #mask=part0.part1.part2.part3, each part = 8bits
        maskPart = 3
        hostsBits = self.bits4hostsInAPart(maskList[maskPart])
        while hostsBits%8 == 0 and maskPart>0:
            maskPart -= 1
            hostsBits += self.bits4hostsInAPart(maskList[maskPart])
        return hostsBits

    def calculateNumberHosts(self, bits4hosts):
        numberHosts = 2**bits4hosts - 2 # base IP and broadcast IP are not for hosts
        return numberHosts

    def calculate_ip(self, ip_mask):
        #try:
        ipList, mask = self.makeIPandMask(ip_mask)
        if ipList == -1:
            print 'Invalid syntax: IP'
            return -1
        else:
            if mask == -1:
                print 'Invalid syntax: mask'
                return -1
            else:
                mask, bits4hosts = self.makeMask(mask)
                if mask ==-1 or bits4hosts == -1:
                    print 'Invalid syntax: mask'
                    return -1
                else:
                    numberHosts = self.calculateNumberHosts(bits4hosts)
                    ipBaseList = self.makeBase(ipList,bits4hosts)
                    ipHost1List= ipBaseList[:] # get value, not refere
                    ipHost1List[-1]=ipHost1List[-1]+1
                    ipBroadcastList = self.makeBroadcast(ipList,bits4hosts)
                    ipHostUltimoList= list(ipBroadcastList)
                    ipHostUltimoList[-1]=ipBroadcastList[-1]-1
                    # convert to string
                    ipBase = self.list2string(ipBaseList)
                    ipHost1 = self.list2string(ipHost1List)
                    ipHostUltimo = self.list2string(ipHostUltimoList)
                    ipBroadcast = self.list2string(ipBroadcastList)
                    return [ipBase, ipHost1, ipHostUltimo, ipBroadcast, mask, numberHosts]


    def askAndCalculate(self):
        print 'Write your ipv4/mask, e.g. 192.168.1.5/255.255.255.0 or /24 or /ffffff00 or /ff.ff.ff.00'
        ip_mask = ""
        while ip_mask == "":
            ip_mask = raw_input('>> ')
            results = self.calculate_ip(ip_mask)
            if results == -1:
                print 'ERROR. Invalid syntax'
                ip_mask = ""
            else:
                [ipBase, ipHost1, ipHostUltimo, ipBroadcast, mask, numberHosts]=self.calculate_ip(ip_mask)
                print 'base ip / mask: '+ str(ipBase)+'/'+str(mask)
                print 'first host ip: ' + str(ipHost1)
                print 'last host ip: ' + str(ipHostUltimo)
                print 'broadcast ip: '+ str(ipBroadcast)
                print 'maximum number of hosts: ' + str(numberHosts)