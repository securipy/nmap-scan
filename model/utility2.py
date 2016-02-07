#!/usr/bin/python
#-*-coding:utf-8-*-

import sys, re
from teco import color, style

class CalcIP:

    def str2list(self, STRing):    # each element separed by dot
        parts = STRing.split('.')    # parts=['0','1','2','3']
        List = []
        List.append(int(parts[0]))
        List.append(int(parts[1]))
        List.append(int(parts[2]))
        List.append(int(parts[3]))
        return List        #  list=[0,1,10,11], int elements

    def list2string(self, List):
        return '%s.%s.%s.%s' %(List[0],List[1],List[2],List[3])

    def bits2cero(self, numeroConvertir,numBits2cero):
        # converts to 0 x number of bits of numeroConvertir starting at rigth (x=numBits2cero)
        for i in range(numBits2cero):
            numeroConvertir=numeroConvertir&(255<<(i+1)) # 255=11111111->not elimiate left numbers of numeroConvertir
        return numeroConvertir

    def bits2one(self, numeroConvertir,numBits2one):
        # converts to 1 x number of bits of numeroConvertir starting at rigth (x=numBits2one)
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
        return ipBroadcast

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

    def calculate_ip(self, ip_mask):
        try:
            ip = ip_mask.split('/')[0]    # ip = '0.1.2.3'
            mask = ip_mask.split('/')[1]    # mask = '24', string
            ipList = self.str2list(ip)
            if len(mask)<=2: # mask as CIDR
                bits4Hosts = 32-int(mask)
            else: # mask at decimal notation
                maskList = self.str2list(mask)
                bits4Hosts = self.bits4hosts(maskList)
                mask = 32-bits4Hosts
            ipBaseList = self.makeBase(ipList,bits4Hosts)
            ipHost1List= list(ipBaseList)
            ipHost1List[-1]=ipHost1List[-1]+1
            ipBroadcastList = self.makeBroadcast(ipList,bits4Hosts)
            ipHostUltimoList= list(ipBroadcastList)
            ipHostUltimoList[-1]=ipBroadcastList[-1]-1
            ipBase = self.list2string(ipBaseList)
            ipHost1 = self.list2string(ipHost1List)
            ipHostUltimo = self.list2string(ipHostUltimoList)
            ipBroadcast = self.list2string(ipBroadcastList)
            return [ipBase, ipHost1, ipHostUltimo, ipBroadcast, mask]
        except:
            pass

class ChangeFormat:

    def __init__(self):
        self.cIP = CalcIP()
        self.ck = Check()

    def IP2scan(self,introduced):
        # work with class C ip
        # example '192.168.1.1-5,199-201' -> ('192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5', '192.168.1.199', '192.168.1.200', '192.168.1.201')
        if self.ck.checkCharacter(introduced) == 1:
            print color('rojo', 'Invalid syntax')
            return -1
        else:
            # separators
            separate_dash = re.compile('-')
            # separate_slash = re.compile('/')
            separate_dot = re.compile('\.')
            try:
                # separate hosts ip introduced
                # create a list formed with parts separated by comas
                ip2scan = [] # save hosts IP at complete format
                # ip range indicated using slash
                if len(re.findall("/",introduced)): # detects if any slash is has been used
                    [ipBase, ipFirstHost, ipLastHost, ipBroadcast, mask]=self.cIP.calculate_ip(introduced)
                    ip2scan.extend(self.createRange(ipFirstHost, ipLastHost))
                else: # if no slash used, then a dash can be used
                    partsComa = self.createListComaParts(introduced) # '192.168.1.1,5,10-12' -> ['192.168.1.1','5','10-12'] or '192.168.1.1' -> ['192.168.1.1']
                    [ipAsList, firstRange] = self.retrieveIPListAndFirstRange(partsComa[0], separate_dash, separate_dot)  # save first IP, it is at complete format only before the first coma
                    ip2scan.extend(firstRange) # save first IP to scan
                    # work with each part separated by coma
                    for partComa in partsComa[1:]: # first part already included
                        # IP range indicated with dash (-)
                        if len(re.findall("-",partComa)) >= 1:
                            rangeDashParts = separate_dash.split(partComa)
                            range_dash = self.rangeWorkWithDashPart(ipAsList, rangeDashParts)
                            ip2scan.extend(range_dash)
                        # only one number indicated, example: '192.168.1.1,33', 33 in this example
                        else:
                            # example: '192.168.1.1,33' -> ['192.168.1.1', '192.168.1.33']
                            ip2add = '%s.%s.%s.%s' %(ipAsList[0],ipAsList[1],ipAsList[2], partComa)
                            ip2scan.append(ip2add)
                #ip2scan = list(set(ip2scan)) # eliminate repeated values
                #ip2scan.reverse() # eliminate repeated values inverts list order
                return tuple(ip2scan) # example: ['192.168.1.50', '192.168.1.51', '192.168.1.52'] -> ('192.168.1.50', '192.168.1.51', '192.168.1.52')
            except:
                print color('rojo', 'Invalid syntax')
                return -1

    def createRange(self, first_ip, last_ip): # ip [=] string '1.2.3.4'
        # for ip class C
        # example: first_ip = '192.168.1.1' and last_ip = '192.168.1.4' -> range_ip = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']
        first_ip_ListParts = re.compile('\.').split(first_ip) # ['1','2','3','4']
        last_ip_ListParts = re.compile('\.').split(last_ip)
        ip_beginning = '%s.%s.%s.' %(first_ip_ListParts[0],first_ip_ListParts[1],first_ip_ListParts[2]) # ip class C
        ipRange = []
        for number in range(int(first_ip_ListParts[-1]),int(last_ip_ListParts[-1])+1):
            ipRange.append(ip_beginning+str(number))
        return ipRange

    def createListComaParts(self, strIntroduced):
        # example: '192.168.1.1,5,10-12' -> ['192.168.1.1','5','10-12']
        # example 2: '192.168.1.1' -> ['192.168.1.1']
        # example 3: '192.168.1.1-2' -> ['192.168.1.1-2']
        separate_coma = re.compile(',') # separator
        if len(re.findall(",",strIntroduced)) >= 1: # any coma introduced
            comaParts = separate_coma.split(strIntroduced)
        else:
            comaParts = [strIntroduced]
        return comaParts

    def retrieveIPListAndFirstRange(self, firstComaPart, separate_dash, separate_dot):
        # detected if a dash is used
        if len(re.findall("-",firstComaPart)) >= 1:
            rangeParts = separate_dash.split(firstComaPart) # ['192.168.1.1-3'] -> ['192.168.1.1','3']
            firstIP = rangeParts[0]
            # get first IP as list, it's 3 first numbers are important because they are only at the first ip indicated before the first coma
            firstIPAsList = separate_dot.split(firstIP) # ['192.168.1.1'] -> ['192','168','1','1'])
            firstRange = self.rangeWorkWithDashPart(firstIPAsList, [firstIPAsList[3], rangeParts[1]])
        else: # only one IP introduced
            # get first IP as list, it's 3 first numbers are important because they are only at the first ip indicated before the first coma
            firstIPAsList = separate_dot.split(firstComaPart) # ['192.168.1.1'] -> ['192','168','1','1'])
            firstRange = firstComaPart
        return [firstIPAsList, firstRange]

    def rangeWorkWithDashPart(self, completeIPAsList, rangeIP):
        # class C ip
        # example 1: '192.168.1.3-5' -> ['192.168.1.3', '192.168.1.4', '192.168.1.5']
        # example 2: '3-5' neccesary to introduce first parts of the ip: '3-5' -> ['x.x.x.3', 'x.x.x.4', 'x.x.x.5']
        # rangeIP: ['3','5']
        # completeIPAsList: ['x','x','x','1'] (1 is an example)
        first_ip = '%s.%s.%s.%s' %(completeIPAsList[0],completeIPAsList[1],completeIPAsList[2], rangeIP[0])
        last_ip = '%s.%s.%s.%s' %(completeIPAsList[0],completeIPAsList[1],completeIPAsList[2], rangeIP[1])
        range_ip = self.createRange(first_ip, last_ip)
        return range_ip


    def hosts2nmapFormat (self, IPList):
        # converts a list to the NMap required format
        # for class C
        # example ['192.168.1.1', '192.168.1.200', '192.168.1.33'] to '192.168.1.1,200,33'
        separate_dot = re.compile('\.') # separador
        ipReturn = IPList[0]
        for ip in IPList[1:]:
            ip_partes = separate_dot.split(ip)
            ipReturn = '%s,%s' %(ipReturn,ip_partes[3])
        return ipReturn

    # sql queries do not accept some characters
    def eliminateCharacters (self, string2change):
        rmCh1 = string2change.replace("{", "")
        rmCh2 = rmCh1.replace("}", "")
        rmCh3 = rmCh2.replace('"', "")
        stringFinal = rmCh3.replace("'", "")
        return stringFinal

    def convertSring2ListWitchAllValues(self, ports):
        # example '1,2,4-6,7,10-12,13,15' to ['1', '2', '4', '5', '6', '7', '10', '11', '12', '13', '15']
        portsReturn = []
        # first take each port under comas
        if len(re.findall(",",ports)) >= 1: # check if there are comas (,)
            portsSeparateComa = re.compile(',').split(ports)
            for port in portsSeparateComa:
                # form ports indicates by hiphen
                if len(re.findall("-",port)) >= 1: # check if ther are hiphens (-)
                    [firstNumber,lastNumber]=re.compile('-').split(port)
                    portsSeparateHiphen = [str(i) for i in range(int(firstNumber),int(lastNumber)+1)] # each list element is type int
                    # portsSeparateHiphen = range(int(firstNumber),int(lastNumber)+1) # each list element is type int
                    # [str(i) for i in portsSeparateHiphen] # each list element is type string
                    portsReturn.extend(portsSeparateHiphen)
                else:
                    portsReturn.append(port)
        # if no ports separated by comas, search ports separated by hiphens
        elif len(re.findall("-",ports)) >= 1: # check if ther are hiphens (-)
            [firstNumber,lastNumber]=re.compile('-').split(ports)
            portsSeparateHiphen = [str(i) for i in range(int(firstNumber),int(lastNumber)+1)] # each list element is type int
            # portsSeparateHiphen = range(int(firstNumber),int(lastNumber)+1) # each list element is type int
            # [str(i) for i in portsSeparateHiphen] # each list element is type string
            portsReturn.extend(portsSeparateHiphen)
        # only one port introduced
        else:
            portsReturn.append(ports)
        return portsReturn


    def convertDictionary2String(self, dictionary):
        # save dictionary values in a list
        list = []
        for key, value in dictionary.iteritems():
            value2add = '%s: %s' %(key, value)
            list.append(value2add)
        # convert list to string
        str = ' \n'.join(list)
        # eliminate characters that can produce error at a sql statement
        str = self.eliminateCharacters(str)
        return str

    def eliminateTuplesAtList(self, listTuples):
        # example 1, list of one tuple: [(13,)] -> 13
        # example 2, list of tuples: [(13,), (13,), (14,)] -> [13, 13, 14]
        if len(listTuples) == 1:
            return listTuples[0][0]
        else:
            listInt = []
            for tuple in listTuples:
                listInt.append(tuple[0])
            return listInt

class Check:

    def checkInt(self, string, message=1):
        try:
            int(string)
            return 1
        except:
            if message == 1:
                print 'Introduce a number'
            return -1

    def checkListEmpty (self, list):
        if list == []:
            return 1
        else:
            return -1

    def checkCharacter(self, string):
         # if a character is in a string, it returns 1
        chars = set('abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMÑNOPQRSTUVWXYZ')
        if any((str_ch in chars) for str_ch in string):
            return 1
        else:
            return -1