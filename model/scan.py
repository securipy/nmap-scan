#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys, nmap, time, os.path
sys.path.append('model')
from database import Database
from nmapscan import NmapScan
from scan_DB import ScanDB
from teco import color, style
from utility2 import ChangeFormat, Check, Message
from utility_ask import Ask
from utility_calculatorIP import CalcIP
from utility_changeHostName import ChangeHostName
from utility_export import UtilityExport
from utility_network import NetworkUtility
from utility_selectAuditAndRevision import SelectAuditRev
import pprint

class Scan:

	def __init__(self):
		self.auditNumber = None
		self.auditName = None
		self.revisionNumber = None
		self.revisionName = None
		self.myIP = None
		self.ar = SelectAuditRev()
		self.ask = Ask()
		self.cf = ChangeFormat()
		self.cIP = CalcIP()
		self.ck = Check()
		self.cn = ChangeHostName()
		self.db = Database()
		self.dbs = ScanDB()
		self.ex = UtilityExport()
		self.ms = Message()
		self.nm = nmap.PortScanner()
		self.nt = NetworkUtility()
		self.save_path = 'modules/nmap-scan/model/exportedFiles' # where save .txt files
		self.scanOptions = {'discovery':0, 'operatingSystem':0, 'versionORscript':0, 'custom':0, 'portsState':0} # what the user want to scan. Values: -1 (not used) or 1 (used)
		# not allowed commands at CustomParameters option (black list). Those that modify input or output information
		self.scanCustomNotAllowedOptions = ['-iL',
											'-iR',
											'--exludefile',
											'-oN',
											'-oX',
											'-oS',
											'-oG',
											'-oA',
											'--append-output',
											'--resume',
											'--stylesheet',
											'--webxml',
											'--no_stylesheet',
											'--append-output']

	def select_audit(self):
		self.auditNumber, self.auditName = self.ar.selectAudit()
		self.select_revision()

	def select_revision(self):
		self.auditNumber, self.auditName, self.revisionNumber, self.revisionName = self.ar.selectRevision(self.auditNumber, self.auditName)

	def discovery(self):
		if self.__initScan() == 1:
			# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
			hosts2scan_shortFormat, hosts2scan_longFormat = self.ask.askHostsIP(self.myIP)
			if hosts2scan_longFormat != -1:
				# scan
				self.__scanDiscovery(hosts2scan_shortFormat)
				# indicate option
				self.scanOptions['discovery']=1
				self.__actualiceOptions()
				# show ip of hosts up
				self.__showHostsIPscannedUp()
				# actualice database
				self.__actualiceDB(hosts2scan_longFormat)
				# clear option
				self.scanOptions['discovery']=0
				self.__actualiceOptions()

	def discoverOS(self):
		if self.__initScan() == 1:
			# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
			[hosts2scan_shortFormat, hosts2scan_longFormat] = self.ask.ask4hosts2workOptions(self.auditNumber, self.revisionNumber, self.myIP)
			# save ip to scan
			if hosts2scan_shortFormat != -1 and hosts2scan_longFormat != -1:
				# scan
				self.__scanDiscoverOS(hosts2scan_shortFormat)
				# indicate option
				self.scanOptions['operatingSystem']=1
				self.__actualiceOptions()
				# show ip of hosts scanned
				self.__showHostsIPscannedUp()
				# actualice database
				self.__actualiceDB(hosts2scan_longFormat)
				# clear option
				self.scanOptions['operatingSystem']=0
				self.__actualiceOptions()

	def version(self):
		if self.__initScan() == 1:
			# ask for hosts ip to scan
			hosts2scan = self.ask.ask4hosts2workOptions(self.auditNumber, self.revisionNumber, self.myIP)[0]
			if hosts2scan != -1:
				# scan
				self.__scanVersion(hosts2scan)
				# indicate option
				self.scanOptions['versionORscript']=1
				self.__actualiceOptions()
				# show ip of hosts up
				self.__showHostsIPscannedUp()
				# actualice database
				self.__actualiceDB()
				# clear option
				self.scanOptions['versionORscript']=0
				self.__actualiceOptions()

	def script(self):
		if self.__initScan() == 1:
			# ask for hosts ip to scan
			hosts2scan = self.ask.ask4hosts2workOptions(self.auditNumber, self.revisionNumber, self.myIP)[0]
			if hosts2scan != -1:
				# scan
				self.__scanScript(hosts2scan)
				# indicate option
				self.scanOptions['versionORscript']=1
				self.__actualiceOptions()
				# show ip of hosts up
				self.__showHostsIPscannedUp()
				# actualice database
				self.__actualiceDB()
				# clear option
				self.scanOptions['versionORscript']=0
				self.__actualiceOptions()

	def CustomParameters(self):
	# introduce custom parameters
		if self.__initScan() == 1:
			# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
			[hosts2scan_shortFormat, hosts2scan_longFormat] = self.ask.ask4hosts2workOptions(self.auditNumber, self.revisionNumber, self.myIP)
			if hosts2scan_shortFormat != -1 and hosts2scan_longFormat != -1:
				# ask for parameters of the scan
				parameters = self.ask.ask4parameters(self.scanCustomNotAllowedOptions)
				# scan
				self.__scanCustomParameters(hosts2scan_shortFormat, parameters)
				# indicate options
				self.scanOptions['custom']=1
				# # if ports were indicated, then they are added at db as open or closed. If no ports were indicated, not retrieve scanned ports are down and the db has to be actualized
				if self.cf.detectPorts(parameters)[0] == None: # no ports were indicated, scan retrieves open ports
					self.scanOptions['versionORscript'] = 1 # necessary to actualize db with no retrieve scanned ports
				self.__actualiceOptions()
				# show ip of hosts up
				self.__showHostsIPscannedUp()
				# actualice database. In CustomParameters all the information is saved
				self.__actualiceDB(hosts2scan_longFormat)
				# clear option
				self.scanOptions['custom']=0
				self.scanOptions['versionORscript'] = 0
				self.__actualiceOptions()

	def puertos(self):
	# introduce hosts ip and ports to scan and check if ports are open or closed, not more information is saved
		if self.__initScan() == 1:
			# ask for hosts ip to scan
			hosts2scan_shortFormat = self.ask.ask4hosts2workOptions(self.auditNumber, self.revisionNumber, self.myIP)[0]
			if hosts2scan_shortFormat != -1:
				# ask ports to scan
				ports2scan_shortFormat = self.ask.ask4ports2search()[0]
				if ports2scan_shortFormat != None:
					# scan
					self.__scanPorts(hosts2scan_shortFormat, ports2scan_shortFormat)
					# indicate options
					self.scanOptions['portsState']=1
					self.__actualiceOptions()
					# actualice database
					self.__actualiceDB()
					# clear options
					self.scanOptions['portsState']=0
					self.__actualiceOptions()

	def portsFile(self):
	# create a .txt file, one per port indicated, with hosts IP up with those ports open
		# check if a revision and audit were selected
		self.__check_audit_rev(1)
		if self.auditNumber!= None and self.revisionNumber != None:
			revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.auditNumber, self.revisionNumber)
			if revision_with_values != -1:
				# ask ports to export
				ports2File = self.ask.ask4ports2search()[1] # list of int numbers as strings, with all ports
				if ports2File != None:
					for port in ports2File:
						self.__createFile4port(port)
			else:
				print color('rojo', 'No hosts discovered for this revision')

	def allInfoHost(self):
		# create a .txt file or print at console the information associated to a host
		# get my hosts IP
		self.myIP = self.nt.getMyIP()
		# check if a revision and audit were selected
		self.__check_audit_rev(1)
		if self.auditNumber != None and self.revisionNumber != None:
			revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.auditNumber, self.revisionNumber)
			if revision_with_values != -1:
				# ask how to get the information
				modeHostInformation = self.ask.askOptionAllInfoHost() # int
				hostsIP_longFormat = self.ask.ask4hosts2workOptions(self.auditNumber, self.revisionNumber, self.myIP)[1]
				for hostIP in hostsIP_longFormat:
					self.__createFile4host(hostIP, modeHostInformation)
			else:
				print color('rojo', 'No hosts discovered for this revision')

	def changeHostName(self):
		# give an indicative name for each host
		self.__check_audit_rev(1)
		if self.auditNumber != None and self.revisionNumber != None:
			revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.auditNumber, self.revisionNumber)
			if revision_with_values != -1:
				self.cn.changeName(self.auditNumber, self.revisionNumber)
			else:
				print color('rojo', 'No hosts discovered for this revision')

	def calcIPbase(self):
		self.cIP.askAndCalculate()

	def __initScan(self):
		# get my hosts IP
		self.myIP = self.nt.getMyIP()
		# check if you have network connection
		networkConnection = self.nt.checkNetworkConnection(self.myIP)
		if networkConnection == 1:
			# check if a revision and audit were selected
			self.__check_audit_rev()
			return 1
		else:
			return -1

	def __actualiceOptions(self):
		# know type of scan
		self.scanOptions4Hosts = [self.scanOptions['discovery'], self.scanOptions['operatingSystem'], self.scanOptions['custom']] # options for studying ports
		self.scanOptions4Ports = [self.scanOptions['versionORscript'], self.scanOptions['portsState'], self.scanOptions['custom']] # options for studying ports
		# as we see, with custom option all the information is saved

	def __check_audit_rev(self, noNew=None):
		# noNew: if no new audit or revision can be created
		# check if a revision and audit were selected and their names saved at self.auditName and self.revisionName
		if noNew == None:
			if self.auditNumber == None or self.auditName == None:
				self.select_audit()
			if self.revisionNumber == None or self.revisionName == None:
				self.select_revision()
		else:
			if self.auditNumber == None or self.auditName == None:
				self.auditNumber, self.auditName = self.ar.selectExistingAudit()
			if self.auditNumber != None and (self.revisionNumber == None or self.revisionName == None):
				self.revisionNumber, self.revisionName = self.ar.selectExistingRevision(self.auditNumber)

	# add last revison's hosts if this is the first discovery for actual revision
	def __addDBlastRevisionHosts(self):
		revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.auditNumber, self.revisionNumber)
		if revision_with_values == -1:
			self.db.add_old_hosts (self.auditNumber, self.revisionNumber)

	# scan for Discovery option
	def __scanDiscovery(self, hosts2scan):
		# example in nmap: nmap -n -sP --exclude 192.168.1.37 192.168.1.1
		print 'Discovery scan started'
		self.nm.scan(hosts=hosts2scan, arguments='-n -sP --exclude '+str(self.myIP))

	# scan for Operating System
	def __scanDiscoverOS(self, hosts2scan):
		print 'Discover operating system started'
		self.nm.scan(hosts=hosts2scan, arguments='-O --exclude '+str(self.myIP))

	# scan for Version option
	def __scanVersion(self, hosts2scan):
		# example in nmap: nmap -sV --exclude 192.168.1.37 192.168.1.1
		print 'Version ports scan started'
		self.nm.scan(hosts=hosts2scan, arguments='-sV --exclude '+str(self.myIP))

	# scan for Script option
	def __scanScript(self, hosts2scan):
		print 'Script ports scan started'
		self.nm.scan(hosts=hosts2scan, arguments='-sV -sC --exclude '+str(self.myIP))

	# scan for CustomParameters option
	def __scanCustomParameters(self, hosts2scan, parameters):
		# parameters: string
		# ports2scan: string
		print 'Custom scan started'
		self.nm.scan(hosts=hosts2scan, arguments = parameters + ' --exclude '+str(self.myIP))

	# scan for Ports option
	def __scanPorts(self, hosts2scan, ports2scan):
		# hosts2scan: string
		# ports2scan: string
		# example in nmap: nmap -p 20,80 192.168.1.1
		print 'Ports scan started'
		self.nm.scan(hosts=hosts2scan, arguments="-p "+ports2scan)

	def __actualiceDB(self, hosts2scan_longFormat=None): # example hosts2scan_longFormat=('192.168.1.50', '192.168.1.51', '192.168.1.52')
		macs_up = [] # using later to know which hosts mac put down
		# check what scan type was maded
		hostsWereScanned = self.ck.checkAnyIs1(self.scanOptions4Hosts)
		portsWereScanned = self.ck.checkAnyIs1(self.scanOptions4Ports)
		# add last revison hosts (once per revision)
		self.__addDBlastRevisionHosts()
		# indicate how info will will be showed
		if portsWereScanned == 1:
			print 'Hosts IP: [open ports]'
		for hostIP in self.nm.all_hosts():
			# get host info
			hostMac, hostOS, hostPortsScanned_longFormat, hostName = self.__getHostScannedInformation(hostIP) # necessary retrieve scanned ports if they were not indicated
			# save scanned mac
			macs_up = self.__addScannedMac(hostsWereScanned, hostIP, macs_up, hostMac)
			# add host to hosts table (new hosts can be discovered)
			self.__addDBupHost(hostIP, hostMac, hostOS, hostName)  # if the host is at the db, it is added again to know the last time it was scanned
			# work with ports
			self.__actualiceDBportsOfAhost(portsWereScanned, hostMac, hostIP, hostPortsScanned_longFormat)
		# add 'down' hosts at host table
		self.__actualiceDBdownHosts(hostsWereScanned, macs_up, hosts2scan_longFormat)
		# indicate no ports were scanned when scanning ports
		if portsWereScanned ==1 and self.nm.all_hosts() == []: # if all ports are closed then nm.all_hosts()=[] (empty)
			print 'No ports'

	def __addScannedMac(self, hostsWereScanned, hostIP, macs_up, mac):
		if mac == None:
			print str(hostIP) + ": no mac info"
		else:
			if hostsWereScanned == 1:
				macs_up.append(mac)
		return macs_up

	def __actualiceDBdownHosts(self, hostsWereScanned, macs_up, hosts2scan_longFormat):
		# add 'down' hosts at host table
		if hostsWereScanned==1:
			# not add 'down' hosts at hosts table when ports are studied because not scanned ports (-> not host showed as up) does not mean the host is down
			self.__addDBDownHosts(macs_up, hosts2scan_longFormat)

	def __actualiceDBportsOfAhost(self, portsWereScanned, mac, hostIP, hostPortsScanned_longFormat):
		# get id of the host with we are working now
		hostID = self.db.retrieve_hostID_withIP(self.auditNumber, self.revisionNumber, mac, hostIP)
		# add last ID host ports. One time for each host ID, neccesary to not forget ports scanned in the past for a host
		self.__addDBLastIDhostPorts(hostIP, hostID, mac)
		if portsWereScanned == 1:
			# get ports up
			hostPortsOpen = self.__getScannedPortsByState(hostIP, hostPortsScanned_longFormat)[0]
			# show scanned information
			self.__showPortsScanned(hostIP, hostPortsOpen)
			# actualice db for ports
			self.__actualiceDBtablePuertos(hostID, hostIP, hostPortsScanned_longFormat, hostPortsOpen)

	# add new row with host up at hosts table
	def __addDBupHost(self, ip, mac, os=None, name=None):
		hostActualID = self.db.add_host('up', self.revisionNumber, ip, mac, os, name) # add host and get associated ID
		# if host had a name, no modify it
		hostPreviousID = self.db.retrieve_hostPreviousID(self.auditNumber, mac, hostActualID) # get previous host ID at db
		if hostPreviousID != -1: # host at db with a previous ID
			hostLastName = self.db.retrieve_hostName_byHostID(hostPreviousID) # get last host name at database
			if hostLastName != -1: # host had a name
				self.db.update_hostName_byID(hostActualID, hostLastName) # host had a name at database, don't change this field in order to not modify user's values

	# add 'down' hosts
	def __addDBDownHosts(self, macs_up, hosts_scanned):
		# macs_up: list of strings
		# hosts_scanned: tuple of strings
		id_hosts2putDown = self.db.retrieve_id_hosts2putDown(self.auditNumber, self.revisionNumber, macs_up, self.nm.all_hosts(), hosts_scanned)
		if id_hosts2putDown != -1:
			for id_host in id_hosts2putDown:
				self.__addDBDownHost(id_host)

	# add new row with hosts down at hosts table
	def __addDBDownHost(self, id_host):
		down_hostInfo = self.db.retrieve_hostAllInfo_byID(id_host)
		os, status, id, rev, ip, date, mac, name = down_hostInfo
		self.db.add_host('down', self.revisionNumber, ip, mac, os, name)

	def __actualiceDBtablePuertos(self, hostIDwithPorts, hostIPwithPorts, portsScanned, portsOpen):
		# add new information to puertos table (ports scanned as open and closed)
		self.__addDBscannedPorts(hostIDwithPorts, hostIPwithPorts, portsScanned)
		# add 'closed' ports. Ports that were open but now they are closed (for options where if ports are not retrieved as scanned ports it means these ports are closed)
		self.__addDBactualicePorts2closed(hostIDwithPorts, portsOpen)

	def __addDBLastIDhostPorts(self, hostWithPorts, actualHostID, mac):
	# add ports associated to this host (mac) but at the db are associated to an old id_host
	# it is done only one time per id_host (at the first time working with the id_host)
		# check if the actual id host has port information at the DB. In order to add old ports only one time per host ID
		check_idHost_with_DBportsValues = self.db.check_tablePuertosValues4ThisHostID(actualHostID)
		if check_idHost_with_DBportsValues != 1:
			# search the last ports information associated to this host (mac) at the table, search the maximum previous id of this host(mac) with port values
			previousHostID = self.db.retrieve_hostPreviousID(self.auditNumber, mac, actualHostID)
			# ckeck if last id has values at table puertos
			check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
			# search last id for this host (mac) with ports values (it is not necessarily the las ID because for the last ID maybe no ports were scanned)
			while check_idPreviousHost_with_portsValues == -1 and previousHostID > 0:
				previousHostID = self.db.retrieve_hostPreviousID(self.auditNumber, mac, previousHostID)
				check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
			# add previous id_host ports to the actual id_host
			if check_idPreviousHost_with_portsValues == 1:
				self.db.add_old_ports4host(previousHostID, actualHostID)

	def __addDBscannedPorts(self, id_hostWithPorts, ip_hostWithPorts, portsScanned):
		# ports can be scanned as closed in options where ports' number were specified
		# work with each port of the host
		if portsScanned != None:
			for portScanned in portsScanned:
				# get port values
				[version, scripts, state] = self.__getScannedPortInformation(ip_hostWithPorts, portScanned) # state: open or closed
				# add port, always add in order to know last scan time
				self.db.add_port(state, id_hostWithPorts, portScanned, version, scripts)

	def __getHostScannedInformation(self, hostIP):
		mac = self.__getScannedMac(hostIP)
		os = self.__getScannedOperatingSystem(hostIP, mac)
		portsScanned = self.__getScannedPorts(hostIP)  # list of integers
		hostName = self.__getScannedHostName(hostIP)
		return mac, os, portsScanned, hostName

	def __getScannedMac (self, ip):
		# if not port information is scanned, self.nm[hostWithPorts]['addresses']['mac'] generate an exception
		try:
			return self.nm[ip]['addresses']['mac'] # addresses: addresses of the discovered host
		except:
			return None

	def __getScannedOperatingSystem(self, ip, mac):
		# example, for a mobile phone this information will be saved: 'osclass': {'vendor': 'Apple', 'osfamily': 'iOS', 'type': 'phone', 'osgen': '6.X', 'accuracy': '100'}
		# example2, for a pc not retrieves osclass, only vendor: {'status': {'state': 'up', 'reason': 'arp-response'}, 'hostnames': [], 'vendor': {'xx:xx:xx:xx:xx:xx': 'Microsoft'}, 'addresses': {'mac': '20:62:74:DE:4D:88', 'ipv4': '172.19.221.10'}}
		# example3, other forms depending of the nmap version
		if self.scanOptions['discovery'] == 1:
			return None
		else:
			try:
				return self.cf.convertDictionary2string(self.nm[ip]['osclass'])
			except: # if not information are retrieved in 'osclass' maybe are at other form like at example2
				return self.__getScannedOperatingSystemInfoIndividually(ip, mac)

	def __getScannedOperatingSystemInfoIndividually(self, ip, mac):
		# retreive information search directly for 'vendor', 'osfamily' etc
		OS = self.__getScannedOperatingSystemInfoIndividuallyOption1(ip,mac)
		if 'None' in OS:
			OS2 = self.__getScannedOperatingSystemInfoIndividuallyOption2(ip)
			if OS2 != -1:
				OS = OS2
		return OS

	def __getScannedOperatingSystemInfoIndividuallyOption1(self,ip,mac):
		vendor = self.__getScannedOSvendor(ip, mac)
		osfamily = self.__getScannedOSfamily(ip, mac)
		ostype = self.__getScannedOStype(ip, mac)
		osgen = self.__getScannedOSgen(ip, mac)
		accuracy = self.__getScannedOSaccuracy(ip, mac)
		OS = 'vendor: %s \nosfamily: %s \ntype: %s \nosgen: %s  \naccuracy: %s' % (vendor, osfamily, ostype, osgen, accuracy)
		return OS

	def __getScannedOperatingSystemInfoIndividuallyOption2(self,ip):
		# check in Ubuntu with Nmap version 7.01
		vendor, osfamily, ostype, osgen, accuracy = self.__getScannedOSinfoOption2(ip)
		if vendor != None and osfamily != None and ostype != None and osgen != None and accuracy != None:
			OS = "vendor: %s \nosfamily: %s \ntype: %s \nosgen: %s  \naccuracy: %s" % (vendor, osfamily, ostype, osgen, accuracy)
			return self.cf.eliminateCharacters(OS)# save '' at database crashes the program
		else:
			return -1

	def __getScannedOSvendor(self,ip,mac):
		return self.__getScannedOS(ip,mac,'vendor')

	def __getScannedOSfamily(self,ip,mac):
		return self.__getScannedOS(ip,mac,'osfamily')

	def __getScannedOStype(self,ip,mac):
		return self.__getScannedOS(ip,mac,'type')

	def __getScannedOSgen(self, ip,mac):
		return self.__getScannedOS(ip,mac,'osgen')

	def __getScannedOSaccuracy(self, ip,mac):
		return self.__getScannedOS(ip,mac,'accuracy')

	def __getScannedOS(self,ip,mac,info):
		try:
			return self.nm[ip][info][mac]
		except:
			return None

	def __getScannedOSinfoOption2(self, ip):
		osInfo = self.__getScannedOS2(ip) # type list
		if osInfo != None:
			vendor = ""
			osfamily = ""
			ostype = ""
			osgen = ""
			accuracy = ""
			noneCount = 0
			for i in range(len(osInfo)):
				infoI = self.__getScannedOS2part(osInfo,i)
				if infoI != None:
					vendor = vendor + str(infoI['vendor']) + ', '
					osfamily = osfamily + str(infoI['osfamily']) + ', '
					ostype = ostype + str(infoI['type']) + ', '
					osgen = osgen + str(infoI['osgen']) + ', '
					accuracy = accuracy + str(infoI['accuracy']) + ', '
			if vendor != "": # no information was saved
				# elminate last ', '
				vendor = self.cf.eliminateLastCharacters(vendor,2)
				osfamily = self.cf.eliminateLastCharacters(osfamily, 2)
				ostype = self.cf.eliminateLastCharacters(ostype, 2)
				osgen = self.cf.eliminateLastCharacters(osgen, 2)
				accuracy = self.cf.eliminateLastCharacters(accuracy, 2)
			else:
				osInfo = None
		if osInfo == None:
			vendor = None
			osfamily = None
			ostype = None
			osgen = None
			accuracy = None
		return vendor, osfamily, ostype, osgen, accuracy

	def __getScannedOS2(self,ip):
		try:
			return self.nm[ip]['osmatch'] # type list
		except:
			return None

	def __getScannedOS2part(self,osInfo, i):
		try:
			return osInfo[i]['osclass'][0]	#type(os[i]['osclass']) = list
		except:
			return None

	def __getScannedHostName(self,ip):
		try:
			hostname = self.nm[ip]['hostnames'][0]['name'] # example. 'hostnames': [{'type': 'PTR', 'name': 'moli-mol.cuenca.es'}]
			if hostname == []:
				return None
			else:
				return hostname
		except:
			return None

	def __getScannedPorts(self, ip):
		# retrieve ports numbers, example: [22, 8080]
		# if not port information is scanned, ports = self.nm[hostWithPorts]['tcp'].keys() generates an exception
		try:
			return self.nm[ip]['tcp'].keys() # list of integers
		except:
			return None

	def __getScannedPortInformation(self, hostWithPorts, port):
		# sometimes the results have not all those values
		# version scan information
		product = self.__getScannedPortProduct(hostWithPorts,port)
		version = self.__getScannedPortVersion(hostWithPorts,port)
		name = self.__getScannedPortName(hostWithPorts,port)
		extrainfo = self.__getScannedPortExtrainfo(hostWithPorts,port)
		portVersionInformation = 'product: %s \nversion: %s \nname: %s \nextrainfo: %s' %(product, version, name, extrainfo)
		# script scan information
		portScriptInformation = self.__getScannedPortScript(hostWithPorts,port)
		# port scan information (state)
		# only at this option we check if state is open or closed when put the port open or closed at the table because the other scan options only retrieve open ports
		portPortInformation = self.__getScannedPortState(hostWithPorts, port)
		return [portVersionInformation, portScriptInformation, portPortInformation]

	def __getScannedPortProduct(self, hostWithPorts, port):
		return self.__getScannedPortInfo(hostWithPorts,port,'product')

	def __getScannedPortVersion(self, hostWithPorts, port):
		return self.__getScannedPortInfo(hostWithPorts,port,'version')

	def __getScannedPortName(self, hostWithPorts, port):
		return self.__getScannedPortInfo(hostWithPorts,port,'name')

	def __getScannedPortExtrainfo(self, hostWithPorts, port):
		return self.__getScannedPortInfo(hostWithPorts,port,'extrainfo')

	def __getScannedPortScript(self, hostWithPorts, port):
		script = self.__getScannedPortInfo(hostWithPorts,port,'script') # dictionary
		if script != None:
			script = self.cf.convertDictionary2string(script)
		return script

	def __getScannedPortState(self, hostWithPorts, port):
		return self.__getScannedPortInfo(hostWithPorts, port, 'state')

	def __getScannedPortInfo(self, ip, port, info):
		# get the information indiciated of the port of a host
		try:
			info = self.nm[ip]['tcp'][port][info] # name, state, etc: string. script: dictionary
			if info == '':
				info = None
			return info
		except:
			return None

	def __getScannedPortsByState(self, hostIP, hostPortsScanned):
		portsOpen = []
		portsClosed = []
		if hostPortsScanned != None:
			hostPortsScanned = sorted(set(hostPortsScanned), key=int)  # order in ascendent mode
			for port in hostPortsScanned:
				portState = self.__getScannedPortInformation(hostIP, port)[2]
				if portState == 'open':  # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
					portsOpen.append(port)
				elif portState == 'closed':
					portsClosed.append(port)
		return [portsOpen, portsClosed]

	def __addDBactualicePorts2closed(self, id_hostWithPorts, portsOpen):
		# add 'closed' ports, ports that were open but now they are closed
		# for options where if ports are not retrieved as scanned ports it means these ports are closed, example Version or Scripts options or in Custom parameters when ports are scanned but no ports number were indicated
		# Check if at db last ports state is open in order to change to closed
		# for Port State option and optiones where ports number were indicated, closed ports are already added to database.
		if self.scanOptions['versionORscript'] == 1:
			# ports at the db for a id_host that where 'open'
			portsNumber = self.db.retrieve_ports(id_hostWithPorts)
			if portsNumber != -1: # host has ports in database
				portsNumber = self.cf.eliminateTuplesAtList(portsNumber, 1)
				lastPortsID = self.dbs.getPortsLastID(id_hostWithPorts, portsNumber)
				id_ports2putClosed = self.db.retrieve_id_ports2putClosed(lastPortsID, portsOpen)
				if id_ports2putClosed != -1: # at the db are ports associated to a host
					# work with each port
					for id_port in id_ports2putClosed:
						closedPortInfo = self.db.retrieve_portAllInfo_byPortID(id_port)
						if closedPortInfo != -1:
							id_port, id_hosts_port, puerto_port, estado_port, version_port, fecha_port, scripts_port = closedPortInfo
							self.db.add_port('closed', id_hostWithPorts, puerto_port, version_port, scripts_port)
							#self.db.update_port_estadoANDfecha('closed', id_hostWithPorts, old_port[0])

	def __showHostsIPscannedUp(self, showAllInfo=0):
		print 'Hosts scanned up (' + str(len(self.nm.all_hosts())) + '): ' + str(self.cf.convertListTuple2string(self.nm.all_hosts()))
		print 'My IP: ' + str(self.myIP)
		if self.scanOptions['discovery'] != 1 and showAllInfo != 0:
			print 'Hosts scanned up: '
			for host in self.nm.all_hosts():
				print '\n' + host
				try:
					for key, value in self.nm[host]['osclass'].iteritems():
						print '- %s: %s' %(key, value)
				except:
					print '- No info scanned'

	def __showPortsScanned(self, hostWithPorts, hostPorts2show, showAllInfo=0):
		if hostPorts2show == []:
			print str(hostWithPorts) + ": no ports info"
		else:
			if self.scanOptions['portsState'] == 0:
				# show scanned ports
				if showAllInfo == 0:
					print str(hostWithPorts) + ': ' + str(hostPorts2show)
				else:
					print '\n' + str(hostWithPorts) + ': ' + str(hostPorts2show)
					for port in hostPorts2show:
						portVersionInformation = self.__getScannedPortInformation(hostWithPorts, port)[0] # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
						print '- ' + str(port)
						print portVersionInformation
						# try:
						# 	for key, value in self.nm[host]['osclass'].iteritems():
						# 		print '- %s: %s' %(key, value)
						# except:
						# 	print '- No info scanned'
			else: # scanned if ports are open or closed
				# Port scan only show open ports
				print str(hostWithPorts) + ' ' + str(hostPorts2show)

	def __createFile4port(self, port):
		hostsIPwithAport = self.__checkDBandGetHostsIPwithAport(port)
		if hostsIPwithAport != -1:  # port at database
			information2save = self.__getPortInfo2save(hostsIPwithAport, port)
			self.ex.createFile(self.auditName, self.revisionName, self.save_path, port, information2save)
		else:
			print "Warning. Port %s not at database. No file has been created for this port." % port

	def __getPortInfo2save(self, hostsIPwithAport, port):
		if self.ck.checkListEmpty(hostsIPwithAport) == 1:
			information2save = ''
			print 'Warning. Port %s at database but port is closed or hosts are down \nFile will be created empty' % port
		else:
			information2save = self.__createPortInfo2save(hostsIPwithAport)
		return information2save

	def __createPortInfo2save(self, hostsIPwithAport):
		# input list of strings
		# output 'string'
		info2save = ''
		for ip in hostsIPwithAport:
			info2save = info2save + ip + '\n'
		return info2save

	def __checkDBandGetHostsIPwithAport(self, port):
		# port: string
		# return a list of strings
		# check if db has ports for this revision and return those hosts IP
		if self.db.check_portAtDB(self.auditNumber, self.revisionNumber, port) != -1:
			hostsIP = []
			# get hosts IP that are up with this port open
			hostsIPwithAport = self.__getDBhostsIPwithAport(port) # list of strings, example: [u'192.168.1.1', u'192.168.1.33']
			if hostsIPwithAport != -1:
				for hostIP in hostsIPwithAport:
					if self.ck.checkStrIsInt(hostIP,0) == -1: # ip is formed by four numbers sepprated with dots, is not an int number
						# convert to list of strings
						hostsIP.append(hostIP)
				return hostsIP
			else:
				return -1
		else:
			self.ms.adviseNotInDB4revision('Port',port)
			return -1

	def __getDBhostsIPwithAport(self, port):
		hostsIP = []
		idOfHostsUpWithPort = self.db.retrieve_idOfHostsUpWithAPort(port) # list of int numbers or only an int number
		if self.ck.checkStrIsInt(idOfHostsUpWithPort,0) == 1:
			listAuxiliar = []
			listAuxiliar.append(idOfHostsUpWithPort)
			idOfHostsUpWithPort = listAuxiliar
		for idHost in idOfHostsUpWithPort:
			lastIDport = self.db.retrieve_portLastID_byHostIDandPort(idHost, port)
			hostIP = self.db.retrieve_hostIP_byPortID(self.auditNumber, self.revisionNumber, lastIDport)
			hostsIP.append(hostIP) # list
		hostsIP = list(set(hostsIP)) # remove hosts IP repeated
		return hostsIP # example: [u'192.168.1.2', u'192.168.1.3']

	def __createFile4host(self, hostIP, modeHostInformation):
		hostsMac4IP = self.db.retrieve_hostsMac_byIP(self.auditNumber, self.revisionNumber, hostIP) # list of strings with hosts mac that have same IP. If only one mac it is a list of one string
		if hostsMac4IP != -1:
			ipWithSeveralMacs = self.__checkIPwithSeveralMacs(hostIP, hostsMac4IP)
			for hostMac in hostsMac4IP:
				hostAllInformation = self.dbs.getHostAllInformationDB(self.auditNumber, self.revisionNumber, hostMac, hostIP) # get only info of the mac with the indicated IP
				if modeHostInformation == 1: # export .txt file
					fileName = self.__fileNameAllInfoHost(hostIP, hostMac, ipWithSeveralMacs)
					self.ex.createFile(self.auditName, self.revisionName, self.save_path, fileName, hostAllInformation)
				elif modeHostInformation == 2: # print info
					print '\n' + hostAllInformation
		else:
			self.ms.adviseNotInDB4revision('Host IP', hostIP)

	def __checkIPwithSeveralMacs(self, hostIP, hostsMac4IP):
		if len(hostsMac4IP) > 1:
			self.__showHostsMac4IP(hostIP, hostsMac4IP)
			return 1
		else:
			return -1

	def __fileNameAllInfoHost(self, hostIP, hostMac, ipWithSeveralMacs):
		if ipWithSeveralMacs == 1:
			fileName = hostIP + '_' + hostMac
		else:
			fileName = hostIP
		return fileName

	def __showHostsMac4IP(self, hostIP, hostsMac4IP):
		print 'Warning. More than one host with same IP'
		print '%s:' %hostIP
		for hostMac in hostsMac4IP:
			print '- %s' %hostMac
		print "Working with each host's mac"
