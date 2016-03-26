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

    from utility_convert2nmapFormat import utility_convert2nmapFormat

    def __init__(self):
        self.cIP = CalcIP()
        self.ck = Check()

    def hosts2completeFormat(self,hostsIPnmapFormat):
        # variables:
        # - input
        # -- hostsIPnmapFormat: string. Hosts ip at nmap format
        # - output
        # -- ip2scan: touple of strings. Hosts ip at complete format
        # example 1. hosts ip of class C: '192.168,169.1.1-3,199' -> ('192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.199', '192.169.1.1', '192.169.1.2', '192.169.1.3', '192.169.1.199')
        # example 2. hosts ip of any class: '190-191,193.168.1.3,4' -> ('190.168.1.3', '190.168.1.4', '191.168.1.3', '191.168.1.4', '193.168.1.3', '193.168.1.4')
        if self.ck.checkCharacter(hostsIPnmapFormat) == 1:
            print color('rojo', 'Invalid syntax')
            return -1
        if self.ck.checkSlash(hostsIPnmapFormat) == -1 and self.ck.checkComa(hostsIPnmapFormat) == -1 and self.ck.checkDash(hostsIPnmapFormat) == -1:
            # only one IP has been introduced
            ip2scan = self.convertsString2List(hostsIPnmapFormat)
            return ip2scan
        else:
            try:
                # separate hosts ip introduced
                # create a list formed with parts separated by comas
                ip2scan = [] # save hosts IP at complete format
                if self.ck.checkSlash(hostsIPnmapFormat) == 1: # detects if any slash has been used
                    # ip range indicated using slash
                    [ipBase, ipFirstHost, ipLastHost, ipBroadcast, mask]=self.cIP.calculate_ip(hostsIPnmapFormat)
                    ip2scan.extend(self.createRange4completeIP(ipFirstHost, ipLastHost))
                else: # if no slash used, then a dash can be used
                    # separators
                    separate_coma = re.compile(',')
                    separate_dash = re.compile('-')
                    # separate_slash = re.compile('/')
                    separate_dot = re.compile('\.')
                    # obtain each part of the ip introduced: ip = ip1.ip2.ip3.ip4
                    [ip1, ip2, ip3, ip4] = separate_dot.split(hostsIPnmapFormat)
                    # get list of numbers range for each part of the IP:
                    ip1_listNumbers = self.createRange4ipPart(ip1, separate_coma, separate_dash)
                    ip2_listNumbers = self.createRange4ipPart(ip2, separate_coma, separate_dash)
                    ip3_listNumbers = self.createRange4ipPart(ip3, separate_coma, separate_dash)
                    ip4_listNumbers = self.createRange4ipPart(ip4, separate_coma, separate_dash)
                    # create a list with all hosts ip to scan
                    for ip1 in ip1_listNumbers:
                        for ip2 in ip2_listNumbers:
                            for ip3 in ip3_listNumbers:
                                for ip4 in ip4_listNumbers:
                                    ip2add = '%s.%s.%s.%s' %(ip1,ip2,ip3, ip4)
                                    ip2scan.append(ip2add)
                    # ip2scan = list(set(ip2scan)) # eliminate repeated values
                    # ip2scan.reverse() # eliminate repeated values inverts list order
                return ip2scan
            except:
                print color('rojo', 'Invalid syntax')
                return -1

    def createRange4ipPart(self, string, separate_coma, separate_dash):
        # example: '1-3,5,10-12' = [1,2,3,5,10,11,12]
        # parts separated with comas
        comaParts = self.createListComaParts(string, separate_coma)
        # parts separated with dash
        rangeNumbers = self.createListRangeDashParts(comaParts, separate_dash)
        return rangeNumbers

    def createRange4completeIP(self, first_ip, last_ip): # ip [=] string '1.2.3.4'
        # for ip class C
        # example: first_ip = '192.168.1.1' and last_ip = '192.168.1.4' -> range_ip = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']
        first_ip_ListParts = re.compile('\.').split(first_ip) # ['1','2','3','4']
        last_ip_ListParts = re.compile('\.').split(last_ip)
        ip_beginning = '%s.%s.%s.' %(first_ip_ListParts[0],first_ip_ListParts[1],first_ip_ListParts[2]) # ip class C
        ipRange = []
        for number in range(int(first_ip_ListParts[-1]),int(last_ip_ListParts[-1])+1):
            ipRange.append(ip_beginning+str(number))
        return ipRange

    def createListDotParts(self, str2convert):
        # example: '192.168.1.0' -> ['192','168','1','0']
        # variables:
        # - input: string
        # - output: list of str
        separate_dot = re.compile('\.') # separator
        list2return = separate_dot.split(str2convert)
        return list2return

    def createListComaParts(self, strIntroduced, separate_coma):
        # example: '5,10-12' -> ['5','10-12']
        # example 2: '1' = ['1']
        if self.ck.checkComa(strIntroduced) == 1: # any coma introduced
            comaParts = separate_coma.split(strIntroduced)
        else:
            comaParts = [strIntroduced]
        return comaParts

    def createListRangeDashParts (self, listComaParts, separate_dash):
        # example: ['1','3-5'] -> ['1','3','4','5']
        dashParts = []
        for comaPart in listComaParts:
            if self.ck.checkDash(comaPart) == 1:
                dashNumbers = separate_dash.split(comaPart) # example dashNumbers = ['3', '6']
                add2dash = self.createListRange4dashPart(dashNumbers)
                dashParts.extend(add2dash)
            else:
                dashParts.append(comaPart)
        return dashParts

    def createListRange4dashPart(self, dashNumbers):
        # example dashNumbers = ['1','4']
        # example: ['1','4'] = ['1', '2', '3', '4']
        listRangeDash = []
        for number in range(int(dashNumbers[0]),int(dashNumbers[1])+1):
            listRangeDash.append(str(number))
        return listRangeDash


    def hosts2nmapFormat (self, IPTupleCompleteIP):
        # converts a tuple to the Nmap required format
        # example: ('192.168.1.1', '192.168.1.61', '193.168.1.1', '193.168.1.61') -> '192-193.168.1.1,61'
        # works with hosts ip of any class
        # variables
        # - input. IPTupleCompleteIP: tuple
        # - output. hostsIPnmapFormat: string
        hostsIPnmapFormat = str(self.utility_convert2nmapFormat(IPTupleCompleteIP)) # convert to string, if not it is instace type
        return hostsIPnmapFormat

    def eliminateCharacters (self, string2change):
        # sql queries do not accept some characters
        rmCh1 = string2change.replace("{", "")
        rmCh2 = rmCh1.replace("}", "")
        rmCh3 = rmCh2.replace('"', "")
        stringFinal = rmCh3.replace("'", "")
        return stringFinal

    def convertsString2List(self, string):
        # example: '192.168.1.1' -> ['192.168.1.1']
        list = string.split()
        return list

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

    def eliminateMyIPInAList(self, hosts2scan_longFormat, myIP):
        # hosts2scan: list of strings of IP at complete format
        # return a list of strings
        # avoid options 'Versions' and 'Script' to use our host's IP
        # hosts IP at hosts2scan must be in complete format, example '192.168.1.1'
        if not isinstance(hosts2scan_longFormat,list): # check if is not a list
            hosts2scan_longFormat = self.convertsString2List(hosts2scan_longFormat) # necessary to work with a list
        if myIP in hosts2scan_longFormat:
            hosts2scan_longFormat.remove(myIP)
        return hosts2scan_longFormat


class Check:

    import re

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

    def checkCharacter(self, string2study):
         # if a character is in a string, it returns 1
        chars = set('abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMÑNOPQRSTUVWXYZ')
        if any((str_ch in chars) for str_ch in string2study):
            return 1
        else:
            return -1

    def checkInString(self, string2study, what2searchList):
        # check if 'what2search' is in 'string2study'
        # case sensitive
        # variables:
        # - inputs:
        # -- string2study: string we want to revise
        # -- what2searchList: string or list of strings to find in string2study
        # - outputs:
        # -- 1: 'what2study' is in 'string2study'
        # -- -1: 'what2study' is not in 'string2study'
        if type(what2searchList) == str:    # convert what2search in a list if it is a string
            what2searchList = what2searchList.split()
        for what2search in what2searchList:
            if what2search in string2study:
                return 1
        return -1

    def checkIPparts(self, string2study):
        # check if the hosts IP introduced have 4 parts
        # example: '192.168.1' is incorrect, '192.168.1.1,33' is correct
        separate_dot = re.compile('\.')
        if len(separate_dot.split(string2study)) == 4:
            return 1
        else:
            return -1

    def checkSlash(self, string):
        # check if the string has a slash
        if len(re.findall("/",string)) >= 1:
            return 1
        else:
            return -1

    def checkComa(self, string):
        # check if the string has a coma
        if len(re.findall(",",string)) >= 1:
            return 1
        else:
            return -1

    def checkDash(self, string):
        # check if the string has a dash
        if len(re.findall("-",string)) >= 1:
            return 1
        else:
            return -1

    def checkAnyIs1(self, list2study):
        # check if any of the elements in the list2study is equals 1
        for element in list2study:
            if element == 1:
                return 1
        return -1

    def checkAllIs1(self, list2study):
        # check if all of the elements in the list2study is equals 1
        for element in list2study:
            if element != 1:
                return -1
        return 1

    def checkIPstartsWith127(self, ip):
    # if ip = 127.x.x.x -> no network connection
        ipList = re.compile('\.').split(ip) # ip ->['ip1', 'ip2', 'ip3', 'ip4']
        ip1 = ipList[0]
        if ip1 == str(127):
            return -1
        else:
            return 1