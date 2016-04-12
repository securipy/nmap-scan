#!/usr/bin/python
#-*-coding:utf-8-*-

import sys, re
from teco import color, style
from utility_calculatorIP import CalcIP
from utility_convert2nmapFormat import Utility_convert2nmapFormat

class ChangeFormat:

    def __init__(self):
        self.cIP = CalcIP()
        self.ck = Check()
        self.cfNmap = Utility_convert2nmapFormat()

    def detectPorts(self, parameters):
        # input: parameters for the Nmap scan
        # output: string with indicated ports
        # obtain each part of the Nmap parameters introduced
        parametersParts = self.createListSpaceParts(parameters)
        portsShortFormat = self.detectPortsPart(parametersParts) # example ['20', '21', '22, '80']
        if portsShortFormat == None:
            portsLongFormat = None
        else:
            portsLongFormat = self.convertSring2ListWitchAllValues(portsShortFormat)  # example ['20', '21', '22, '80']
        return [portsShortFormat, portsLongFormat]

    def detectPortsPart(self, parametersParts):
        # input. parametersParts: list of strings
        # ouput. string that has ports (string without characters and dots)
        for part in parametersParts:
            if self.ck.checkCharacter(part) == -1:  # search parts without this
                if self.ck.checkDot(part) == -1:
                    return part  # string without the search characters is part with ports
        return None # no ports in parametersParts

    def getShortLongFormatFromLongFormat(self, hostsIP_longFormat, myIP):
        # variables:
        # - input
        # -- hostsIP_longFormat: hosts ip at complete format
        # -- myIP: string
        # - output (without myIP):
        # -- hostsIP_shortFormat: hosts ip at nmap format
        # -- hostsIP_longFormat: hosts ip at complete format
        hostsIP_longFormat = tuple(self.eliminateMyIPInAList(hostsIP_longFormat, myIP)) # tuple for SQL queries
        hostsIP_shortFormat = self.hosts2nmapFormat(hostsIP_longFormat)
        return hostsIP_shortFormat,hostsIP_longFormat


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
            ip2scan = self.convertString2List(hostsIPnmapFormat)
            return ip2scan
        else:
            try:
                # separate hosts ip introduced
                # create a list formed with parts separated by comas
                ip2scan = [] # save hosts IP at complete format
                if self.ck.checkSlash(hostsIPnmapFormat) == 1: # detects if any slash has been used
                    # ip range indicated using slash
                    [ipBase, ipFirstHost, ipLastHost, ipBroadcast, mask, numberHosts]=self.cIP.calculate_ip(hostsIPnmapFormat)
                    ip2scan.extend(self.createRange4completeIP(ipFirstHost, ipLastHost))
                else: # if no slash used, then a dash can be used
                    # obtain each part of the ip introduced: ip = ip1.ip2.ip3.ip4
                    [ip1, ip2, ip3, ip4] = self.createListDotParts(hostsIPnmapFormat)
                    # get list of numbers range for each part of the IP:
                    ip1_listNumbers = self.createRange4ipPart(ip1)
                    ip2_listNumbers = self.createRange4ipPart(ip2)
                    ip3_listNumbers = self.createRange4ipPart(ip3)
                    ip4_listNumbers = self.createRange4ipPart(ip4)
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

    def createRange4ipPart(self, string):
        # example: '1-3,5,10-12' = [1,2,3,5,10,11,12]
        # parts separated with comas
        comaParts = self.createListComaParts(string)
        # parts separated with dash
        rangeNumbers = self.createListRangeDashParts(comaParts)
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
        separator = '\.' # separator
        list2return = self.createSeparation(separator, str2convert)
        return list2return

    def createListComaParts(self, strIntroduced):
        # example: '5,10-12' -> ['5','10-12']
        # example 2: '1' = ['1']
        separator = ','
        if self.ck.checkComa(strIntroduced) == 1: # any coma introduced
            comaParts = self.createSeparation(separator, strIntroduced)
        else:
            comaParts = [strIntroduced]
        return comaParts

    def createListSpaceParts(self, strIntroduced):
        # example: 'nmap -p 20,80 192.168.1.1' -> ['nmap', '-p', '20,80', '192.168.1.1']
        separator = ' '
        spaceParts = self.createSeparation(separator, strIntroduced)
        return spaceParts

    def createListSlashParts(self, strIntroduced):
        # example: '192.168.1.0/24' -> ['192.168.1.0', '24']
        separator = '/'
        spaceParts = self.createSeparation(separator, strIntroduced)
        return spaceParts

    def createListRangeDashParts (self, listComaParts):
        # example: ['1','3-5'] -> ['1','3','4','5']
        separator = ('-')
        dashParts = []
        for comaPart in listComaParts:
            if self.ck.checkDash(comaPart) == 1:
                dashNumbers = self.createSeparation(separator, comaPart) # example dashNumbers = ['3', '6']
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

    def createSeparation(self, separator, str2separate):
        separate = re.compile(separator)
        listParts = separate.split(str2separate)
        return listParts

    def hosts2nmapFormat (self, IPTupleCompleteIP):
        # converts a tuple to the Nmap required format
        # example: ('192.168.1.1', '192.168.1.61', '193.168.1.1', '193.168.1.61') -> '192-193.168.1.1,61'
        # works with hosts ip of any class
        # variables
        # - input. IPTupleCompleteIP: tuple
        # - output. hostsIPnmapFormat: string
        hostsIPnmapFormat = str(self.cfNmap.convert2nmapFormat(IPTupleCompleteIP)) # convert to string, if not it is instace type
        return hostsIPnmapFormat

    def eliminateCharacters (self, string2change):
        # sql queries do not accept some characters
        rmCh1 = string2change.replace("{", "")
        rmCh2 = rmCh1.replace("}", "")
        rmCh3 = rmCh2.replace('"', "")
        stringFinal = rmCh3.replace("'", "")
        return stringFinal

    def eliminateIndicatedCharacters(self, string2change, what2eliminate):
        newString = string2change.replace(what2eliminate,"")
        return newString

    def convertString2Int (self,string2convert):
        # input: type string
        # output: type int
        intConverted = int(string2convert)
        return intConverted

    def convertString2List(self, string):
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

    def eliminateTuplesAtList(self, listTuples, returnAlwaysList=-1):
        # output: int or list of integers
        # example 1, list of one tuple: [(13,)] -> 13 (if returnAlwaysList = -1)
        # example 2, list of tuples: [(13,), (13,), (14,)] -> [13, 13, 14]
        if listTuples == -1:
            return -1
        else:
            if len(listTuples) == 1 and returnAlwaysList == -1:
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
            hosts2scan_longFormat = self.convertString2List(hosts2scan_longFormat) # necessary to work with a list
        if myIP in hosts2scan_longFormat:
            hosts2scan_longFormat.remove(myIP)
        return hosts2scan_longFormat

    def addIndentation(self, string2change, indentationSymbol):
        # add indentation with - in each new line
        # input:
        # - string2change: string
        # - indentationSymbol: string
        # output: string
        stringChanged = string2change.replace('\n', '\n'+indentationSymbol+' ')  # each line stars with -
        stringChanged = '\n'+indentationSymbol+' '+stringChanged  # first line stars with -
        return stringChanged


class Check:

    def checkStrIsInt(self, string, message=1):
        try:
            int(string)
            return 1
        except:
            if message == 1:
                print 'Introduce a number'
            return -1

    def checkListEmpty (self, list2study):
        if list2study == []:
            return 1
        else:
            return -1

    def checkListNotEmpty (self, list2study):
        return -1*self.checkListEmpty(list2study)

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

    def checkDot(self, string):
        # check if the string has a dot
        if len(re.findall("\.",string)) >= 1:
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

    def checkFileExists(self, filePathAndName):
        try:
            open(filePathAndName,'r')
            return 1
        except:
            return -1

class Message:

    def adviseInvalidSyntax(self):
        print color('rojo', 'Invalid syntax \n')

    def adviseInvalidOption(self):
        print color('rojo', 'Invalid option')

    def adviseNotInDB4revision(self, whatNotInDB, moreInfo=None):
        if moreInfo != None:
            print color('rojo', '%s %s not at database for this revision\n' %(whatNotInDB, moreInfo))
        else:
            print color('rojo', '%s not at database for this revision\n' %whatNotInDB)

    def adviseFileCreated(self, fileName):
        # input: fileName type string
        print 'File created: ' + fileName