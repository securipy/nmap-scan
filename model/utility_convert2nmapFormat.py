#!/usr/bin/python

import re
from itertools import groupby
from operator import itemgetter

class Utility_convert2nmapFormat:
	# converts hosts IP at complete format to Nmap format
	# example: ('192.168.1.1', '192.168.1.61', '193.168.1.1', '193.168.1.61') -> '192-193.168.1.1,61'

	def convert2nmapFormat(self, hostsIPTupleCompleteIP):
		# main function of this class
		# example: ('192.168.1.1', '192.168.1.61', '193.168.1.1', '193.168.1.61') -> '192-193.168.1.1,61'
		# can work with hosts IP of all classes
		# variables:
		# - input. hostsIPTupleCompleteIP: tuple of strings. These strings are hosts IP
		# - output. IPnmapFormat: string. Hosts IP at nmap format
		HostsIP2shorten = list(hostsIPTupleCompleteIP) # save hosts IP that are not at nmap format
		HostsIP2shorten = [self.createListDotParts(x) for x in HostsIP2shorten] # lists of lists. Example: ('192.168.1.1', '192.168.1.200', '192.168.1.33') -> [['192', '168', '1', '1'], ['192', '168', '1', '200'], ['192', '168', '1', '33']]
		IPnmapFormat = map (list, zip(*HostsIP2shorten)) # list of lists of str. Example [['192', '192', '192'], ['168', '168', '168'], ['1', '1', '1'], ['1', '200', '33']] -> [['192', '192', '192'], ['168', '168', '168'], ['1', '1', '1'], ['1', '200', '33']]. Explanation: http://stackoverflow.com/questions/1388818/how-can-i-compare-two-lists-in-python-and-return-matches
		IPnmapFormat = self.eliminateRepetitonsInListOfLists(IPnmapFormat) # example: [['192', '192', '192'], ['168', '168', '168'], ['1', '1', '1'], ['1', '200', '33']] -> [['192'], ['168'], ['1'], ['1', '33', '66']]
		IPnmapFormat = self.convertListOfListsOfStr2ListOfListOfInt(IPnmapFormat) # example: [['192'], ['168'], ['1'], ['1', '33', '66']] -> [[192], [168], [1], [1, 33, 66]]
		IPnmapFormat = self.putTogetherAsNmapFortmat(IPnmapFormat) # example: [[192], [168], [1], [1, 33, 66]] -> '192.168.1.1,33,36'
		return IPnmapFormat

	def createListDotParts(self, str2convert):
	    # example: '192.168.1.0' -> ['192','168','1','0']
	    # variables:
	    # - input. str2convert: string
	    # - output. list2return: list of str
	    separate_dot = re.compile('\.') # separator
	    list2return = separate_dot.split(str2convert)
	    return list2return

	def eliminateRepetitonsInListOfLists(self, list2modify):
		# example: [['192', '192', '192'], ['168', '168', '168'], ['1', '1', '1'], ['1', '200', '33']] -> [['192'], ['168'], ['1'], ['1', '200', '33']]
		# variables:
		# - input. list2modify: list of lists of str
		# - output. list2return: list of lists of str
		list2return = [sorted(set(listpart), key=int) for listpart in list2modify] # sorted: order in ascendent mode
		return list2return

	def convertListOfListsOfStr2ListOfListOfInt(self, list2modify):
		# example: [['192'], ['168'], ['1'], ['1', '33', '66']] -> [[192], [168], [1], [1, 33, 66]]
		# variables:
		# - input. list2modify: lists of lists of strings
		# - output. list2return: list of lists of int numbers
		list2return = []
		for listInList in list2modify:
			list2return.append([int(listString) for listString in listInList])
		return list2return

	def createStrNumbersDash(self, listWithNumbers):
		# example: [1, 2, 3, 4, 5] -> '1-5'
		# variables
		# - input. listWithNumbers: list with consecutive numbers
		# - output. str2return: str with first and last number separated by dash
		str2return = str(listWithNumbers[0]) + '-' + str(listWithNumbers[-1])
		return str2return

	def createIPpartNmapFormat(self, ipPart):
		# example: [192, 193, 198] -> '192-193, 198'
		# variables
		# - input. ipPart: list of numbers wich are the first, second, third or four part of the originals IP
		# - output. ipPartNmapFormat: str with list of numbers as Nmap format
		ipPartNmapFormat = '' # string where save numbers between dots as Nmap format
		iteration1 = 1 # know if the first number of the ipPart has been used
		for k, g in groupby(enumerate(ipPart), lambda (i, x): i-x):
			consecutiveNumbers = map(itemgetter(1), g) # list formed by each consecutive numbers. Example: [192, 193] or [1] if there is not consecutive numbers
			ipPartNmapFormat = self.addInformation2IPpartNampFormat(ipPartNmapFormat, consecutiveNumbers, iteration1) # part of the numbers between dots at Nmap format
			iteration1 = 0 # first number of the ipPart has been used
		return ipPartNmapFormat

	def addInformation2IPpartNampFormat(self, ipPartNmapFormat, consecutiveNumbers, iteration1):
		# This method adds information to the ipPart
		# variables
		# - input:  
		# -- ipPartNmapFormat: string where save numbers between dots as Nmap format, this method completes this string at each iteration
		# -- consecutiveNumbers: list with numbers that are consecutives. Example [192,193] or [1] if there is not consecutive numbers
		# -- iteration1: int (1 or 0) know if the number is the first (iteration1 == 1) for the ipPart
		# - output:
		# -- ipPartNmapFormat: string with the ipPart with the information in 'consecutiveNumbers' added
		if len(consecutiveNumbers)>1:
			if iteration1 == 1:
				ipPartNmapFormat = ipPartNmapFormat + self.createStrNumbersDash(consecutiveNumbers)
			else:
				ipPartNmapFormat = ipPartNmapFormat + ',' + self.createStrNumbersDash(consecutiveNumbers)
		else:
			if iteration1 == 1:
				ipPartNmapFormat = ipPartNmapFormat + str(consecutiveNumbers[0])
			else:
				ipPartNmapFormat = ipPartNmapFormat + ',' + str(consecutiveNumbers[0])
		return ipPartNmapFormat

	def putTogetherAsNmapFortmat(self, ipParts):
		# example: [[192], [168], [1], [1, 33, 66]] -> '192.168.1.1,33,36'
		# variables:
		# - input. ipParts: list of list of int numbers
		# - output. ipPartNmapFormatStr: string. Hosts IP at nmap format
		# http://stackoverflow.com/questions/2361945/detecting-consecutive-integers-in-a-list
		ipPartNmapFormatList = ['NmapFormat','NmapFormat','NmapFormat','NmapFormat'] # save each part separated by dot
		for idx, ipPart in enumerate(ipParts):
			ipPartNmapFormatList[idx] = self.createIPpartNmapFormat(ipPart)
		ipPartNmapFormatStr = '%s.%s.%s.%s' %(ipPartNmapFormatList[0],ipPartNmapFormatList[1],ipPartNmapFormatList[2], ipPartNmapFormatList[3])
		return ipPartNmapFormatStr