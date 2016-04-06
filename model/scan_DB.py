#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan. This script uses 'database.py' methods"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys, nmap, time, os.path
sys.path.append('model')
from database import Database
from utility2 import ChangeFormat, Check, Message
from utility_ask import Ask

class ScanDB:

	def __init__(self):
		self.cf = ChangeFormat()
		self.ck = Check()
		self.db = Database()
		self.ms = Message()

	def getHostAllInformationDB(self, auditNumber, revisionNumber, hostMac, hostIP):
		# retrieve info form db table hosts
		hostLastID = self.db.retrieve_host_id_withIP(auditNumber, revisionNumber, hostMac, hostIP) # work with last information
		hostIDallInfo = self.db.retrieve_hostAllInfo_byID(hostLastID)
		infoTableHosts = self.formInfoTableHosts(hostIDallInfo)
		# retrieve info form db table puertos
		portsNumber4hostID = self.getPortsNumber(hostLastID) # list of one or moreintegers. Example [80, 21, 22, 23]
		portsOpenID = self.getPortsOpenID(hostLastID, portsNumber4hostID)
		infoTablePorts = self.getPortsInfo(portsOpenID)
		# all information for the host
		hostsInfo = infoTableHosts + '\n' + infoTablePorts
		return hostsInfo

	def getPortsInfo(self, portsID):
		if portsID == -1:
			portsInfo = '\nAll ports are closed\n'
		else:
			portsInfo = ''
			for portID in portsID:
				portInfo = self.db.retrieve_portAllInfo_byPortID(portID)
				portInfo = self.formPortInfoTablePuertos(portInfo)
				portsInfo = portsInfo + portInfo + '\n'
		return portsInfo

	def formPortInfoTablePuertos(self, portInfo):
		id, id_host, portNumber, state, version, date_time, scripts = portInfo
		# diferenciate information
		version = self.cf.addIndentation(version,'        -') # each line stars with -
		scripts = self.cf.addIndentation(scripts,'        -') # each line stars with -
		# form information
		tableInfo = '\n'
		tableInfo = tableInfo + 'Port number: ' + str(portNumber) + '\n'
		tableInfo = tableInfo + '    - Version: ' + str(version) + '\n'
		tableInfo = tableInfo + '    - Scripts: ' + str(scripts)
		return tableInfo

	def getPortsOpenID(self, hostLastID, portsNumber4hostID):
		if portsNumber4hostID == -1:
			portsID = -1
		else:
			portsID = self.getPortsLastID(hostLastID, portsNumber4hostID)  # tuple of integers. Example (10, 11, 12 ,13)
			portsID = self.db.retrieve_portsOpenID_byPortID(portsID)
		return portsID

	def getPortsLastID(self, hostID, ports4hostID):
		portsLastID=[]
		for port in ports4hostID:
			portLastID = self.db.retrieve_portLastIDbyHostIDandPort(hostID, port) # type int
			portsLastID.append(portLastID) # list of integers
		portsLastID = tuple(portsLastID)
		if len(portsLastID) == 1:
			portsLastID = portsLastID + portsLastID # avoid tuple to ends with coma
		return tuple(portsLastID) # tuple of integers

	def getPortsNumber(self, hostID):
		# return list on one or more integers
		ports = self.db.retrieve_ports(hostID)  # list of tuples with an integer. Example [(80,), (21,), (22,), (23,)]
		ports = self.cf.eliminateTuplesAtList(ports,1)  # list of integers. Example [80, 21, 22, 23] or [80]
		return ports

	def formInfoTableHosts(self, hostIDallInfo):
		os, status, id, id_rev, ip, date_time, mac = hostIDallInfo
		os = self.cf.addIndentation(os, '    -')
		tableInfo = '########################\n'
		tableInfo = tableInfo + 'Host IP: ' + str(ip) + '\n'
		tableInfo = tableInfo + '########################\n'
		tableInfo = tableInfo + '\nHost Mac: ' + str(mac) + '\n'
		tableInfo = tableInfo + '\nOperating system: ' + str(os) + '\n'
		tableInfo = tableInfo + '\nStatus: ' + str(status)
		return tableInfo