#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan. Ask for information"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys
sys.path.append('model')
from database import Database
from teco import color, style
from utility2 import ChangeFormat, Check, Message

class Ask:

	def __init__(self):
		self.cf = ChangeFormat()
		self.ck = Check()
		self.db = Database()
		self.ms = Message()

	def ask4name(self, what2ask4):
		name = ''
		while name == '':
			name = raw_input(str(what2ask4)+' name: ')
		return name

	def ask4number(self):
		# ask until the answer is an integer
		number = ''
		while number == '':
			print 'Select number'
			number = self.askNumber()
		return number

	def askNumber(self):
		# return number (type int) or '' (advising invalid syntax)
		number = raw_input ('>> ') # string
		if self.ck.checkStrIsInt(number) == -1:
			number = ''
			print color('rojo', '\nInvalid option\n')
		else:
			number = self.cf.convertString2Int(number)
		return number

	def ask4ListOptionNumber(self, availableOptionsNumbers):
		optionNumber = ''
		while optionNumber == '':
			optionNumber = self.ask4number()
			if optionNumber not in availableOptionsNumbers:
				self.ms.adviseInvalidOption()
				optionNumber = ''
		return optionNumber

	def ask4hosts2workOptions(self, auditNumber, revisionNumber, myIP):
		# get ip to scan
		option2scan = self.ask4hostsOption()
		if option2scan == 1:
			# check if the discovery option was maded for this revision
			discoveryDone = self.db.check_tableHostsValues4ThisRevision(auditNumber, revisionNumber) # check values at hosts table for this revision
			if discoveryDone == 1:
				# scan all discovered hosts, down hosts too because they can change to up
				hosts2scan_longFormat = self.db.retrieve_hostsIP_byRevision(auditNumber, revisionNumber)
				hosts2scan_shortFormat, hosts2scan_longFormat = self.cf.getShortLongFormatFromLongFormat(hosts2scan_longFormat, myIP)
				print "Hosts: " + str(hosts2scan_longFormat)
				print "Number of hosts: " + str(len(hosts2scan_longFormat))
			else:
				print color('rojo', 'No hosts ip discovered for this revision')
				hosts2scan_shortFormat, hosts2scan_longFormat = self.askHostsIP(myIP)
		elif option2scan == 2:
			hosts2scan_shortFormat, hosts2scan_longFormat = self.askHostsIP(myIP)
		return [hosts2scan_shortFormat, hosts2scan_longFormat] # -hosts2scan_shortFormat example: '192.168.1.1,2' -hosts2scan_longFormat example ('192.168.1.1','192.168.1.2')

	def ask4hostsOption(self):
		print color('bcyan', 'Select IP')
		print color('cyan', '1. IP discovered \n2. Specify IP')
		option2scan = ''
		while option2scan != 1 and option2scan != 2:
			option2scan = self.ask4number()
		return option2scan

	def askHostsIP(self, myIP):
		hostsIP_shortFormat=''
		while hostsIP_shortFormat == '':
			hostsIP_shortFormat = raw_input('Type an IP or range (no spaces): ')
			if self.ck.checkCharacter(hostsIP_shortFormat) == 1 or self.ck.checkIPparts(hostsIP_shortFormat) == -1:
				self.ms.adviseInvalidSyntax()
				hostsIP_shortFormat=''
			else:
				hostsIP_longFormat = self.cf.hosts2completeFormat(hostsIP_shortFormat) # return list. Example ['192.168.1.50', '192.168.1.51', '192.168.1.52']
				hostsIP_shortFormat, hostsIP_longFormat = self.cf.getShortLongFormatFromLongFormat(hostsIP_longFormat, myIP)
		return hostsIP_shortFormat, hostsIP_longFormat

	def ask4parameters(self, scanCustomNotAllowedOptions):
		parameters=""
		while parameters == "":
			parameters = raw_input('Type parameters for the scan: ')
			if self.ck.checkInString(parameters, scanCustomNotAllowedOptions) == 1:
				parameters = ""
				print color('rojo', 'Thanks for using this tool\nThe specified parameter is not available\nRemember, this tool save information in a database and input/output information is controlled\nOptions not allowed: '+str(scanCustomNotAllowedOptions)+'\nTry another parameter')
		return parameters

	def ask4ports2search(self):
		ports2search = ""
		while ports2search == "":
			ports2search = raw_input('Type ports (no spaces. For no port type None): ')
			if ports2search != 'None':
				if self.ck.checkCharacter(ports2search) == 1:
					self.ms.adviseInvalidSyntax()
					ports2search = ""
		if ports2search == 'None': # At custom parameters option not always ports will be scanned
			return[None, None]
		else:
			por2search_string = ports2search # example '20-22,80'
			ports2search_listOfStrings = self.cf.convertSring2ListWitchAllValues(ports2search) # example ['20', '21', '22, '80']
			return [por2search_string, ports2search_listOfStrings]

	def askOptionAllInfoHost(self):
		print 'Export information in a .txt file (1) or show in window (2)?'
		mode = ""
		while mode != 1 and mode != 2:
			mode = self.ask4number()
		return mode

	def askOverwriteFile(self, fileName):
		print color('rojo', 'File ' +str(fileName)+ ' already exists')
		print color('cyan', 'Options:\n1.Overwrite \n2.New file')
		fileOptions = ''
		while fileOptions!=1 and fileOptions!=2:
			fileOptions = self.ask4number()
		if fileOptions == 2:
			fileOptions = -1
		return fileOptions
