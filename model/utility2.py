#!/usr/bin/python

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
        self.cIP =CalcIP()

    def formatRange(self, ip_primero, ip_ultimo): # ip [=] string '1.2.3.4'
        # for ip class C
        ip_primero_partesLista = re.compile('\.').split(ip_primero) # ['1','2','3','4']
        ip_ultimo_partesLista = re.compile('\.').split(ip_ultimo)
        ip_inicio = '%s.%s.%s.' %(ip_primero_partesLista[0],ip_primero_partesLista[1],ip_primero_partesLista[2]) # ip class C
        IP_rango = []
        for numero in range(int(ip_primero_partesLista[-1]),int(ip_ultimo_partesLista[-1])+1):
            IP_rango.append(ip_inicio+str(numero))
        return IP_rango

    def formatPorts(self, ports): # converts example '1,2,4-6,7,10-12,13,15' to ['1', '2', '4', '5', '6', '7', '10', '11', '12', '13', '15']
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

    def IP2scan(self,introducido):
        # separadores
        separar_coma = re.compile(',')
        separar_guion = re.compile('-')
        #separar_barra = re.compile('/')
        separar_punto = re.compile('\.')
        # ip
        ip = [0,0,0,0]
        try:
            # separar lo introducido
            # partes separadas por comas
            if len(re.findall(",",introducido)) >= 1: # de introducir alguna coma
                partes_coma = separar_coma.split(introducido)
            else:
                partes_coma = [introducido]
            IP_rango = []
            for i in range(len(partes_coma)):
                # rangos de ip indicados con guion
                if len(re.findall("-",partes_coma[i])) >= 1:
                    rangoIP = separar_guion.split(partes_coma[i])
                    ip_partesLista = separar_punto.split(rangoIP[0])
                    ip_primero = rangoIP[0]
                    ip_ultimo = '%s.%s.%s.%s' %(ip_partesLista[0],ip_partesLista[1],ip_partesLista[2], rangoIP[1])
                    IP_rango.extend(self.formatRange(ip_primero, ip_ultimo))
                # rangos de ip indicados con barra
                elif len(re.findall("/",partes_coma[i])): # de introducir alguna barra
                    [ipBase, ipHost1, ipHostUltimo, ipBroadcast, mask]=self.cIP.calculate_ip(partes_coma[i])
                    IP_rango.extend(self.formatRange(ipHost1, ipHostUltimo))
                # indicar una sola direccion ip
                else:
                    ip_partes = separar_punto.split(partes_coma[i])
                    if len(ip_partes)==4:
                        # formed first numbers of the ip to add later the number after coma
                        # Example: introducido = '192.168.1.1,33' -> 192.168.1.1 and 192.168.1.33
                        ip[0] = ip_partes[0]
                        ip[1] = ip_partes[1]
                        ip[2] = ip_partes[2]
                        ip[3] = ip_partes[3]
                        IP_rango.append(partes_coma[i])
                    elif len(ip_partes)==1: # if after coma is a numer, example '192.168.1.1,33', then partes_coma[i]=33
                        ip2add = '%s.%s.%s.%s' %(ip[0],ip[1],ip[2], partes_coma[i])
                        IP_rango.append(ip2add)
            return tuple(IP_rango) # example: ['192.168.1.50', '192.168.1.51', '192.168.1.52'] -> ('192.168.1.50', '192.168.1.51', '192.168.1.52')
        except:
            print color('rojo', 'Invalid syntax')

    def hosts2nmapFormat (self, IPList):
        # converts a list to the NMap required format
        # for class C
        # example ['192.168.1.1', '192.168.1.200', '192.168.1.33'] to '192.168.1.1,200,33'
        separar_punto = re.compile('\.') # separador
        ipReturn = IPList[0]
        for ip in IPList[1:]:
            ip_partes = separar_punto.split(ip)
            ipReturn = '%s,%s' %(ipReturn,ip_partes[3])
        return ipReturn

    # sql queries do not accept some characters
    def eliminateCharacters (self, string2change):
        rmCh1 = string2change.replace("{", "")
        rmCh2 = rmCh1.replace("}", "")
        rmCh3 = rmCh2.replace('"', "")
        stringFinal = rmCh3.replace("'", "")
        return stringFinal

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