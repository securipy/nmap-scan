#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys, nmap, time, os.path, socket, fcntl, struct
sys.path.append('model')
from database import Database
from nmapscan import NmapScan
from teco import color, style
from utility2 import ChangeFormat, Check, Ask, Message
from utility_calculatorIP import CalcIP
from utility_network import networkUtility
from utility_selectAuditAndRevision import selectAuditRev
import pprint

class Scan:

	def __init__(self):
		self.auditNumber = None
		self.auditName = None
		self.revisionNumber = None
		self.revisionName = None
		self.myIP = None
		self.ar = selectAuditRev()
		self.ask = Ask()
		self.cf = ChangeFormat()
		self.cIP = CalcIP()
		self.ck = Check()
		self.db = Database()
		self.ms = Message()
		self.nm = nmap.PortScanner()
		self.nt = networkUtility()
		self.save_path = 'modules/nmap-scan/model/ports' # save .txt files
		self.scanOptions = {'discovery':0, 'operatingSystem':0, 'versionORscript':0, 'custom':0, 'portsState':0} # what the user want to scan. Values: -1 (not used) or 1 (used)
		self.scanCustomNotAllowedOptions = ['-iR'] # not allowed command at CustomParameters option

	def select_audit(self):
		self.auditNumber, self.auditName = self.ar.selectAudit()
		self.select_revision()

	def select_revision(self):
		self.auditNumber, self.auditName, self.revisionNumber, self.revisionName = self.ar.selectRevision(self.auditNumber, self.auditName)

	def discovery(self):
		self.__initScan()
		# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
		hosts2scan_shortFormat, hosts2scan_longFormat = self.__askHostsIP()
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
		self.__initScan()
		# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
		[hosts2scan_shortFormat, hosts2scan_longFormat] = self.__ask4hosts2scanOptions()
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
		self.__initScan()
		# ask for hosts ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
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
		self.__initScan()
		# ask for hosts ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
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
		self.__initScan()
		# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
		[hosts2scan_shortFormat, hosts2scan_longFormat] = self.__ask4hosts2scanOptions()
		if hosts2scan_shortFormat != -1 and hosts2scan_longFormat != -1:
			# ask for parameters of the scan
			parameters = self.__ask4parameters()
			# necessary save ports to scan
			print '\nPlease, type again ports you want to scan'
			ports2scan_longFormat = self.__ask4ports2search()[1]
			# scan
			self.__scanCustomParameters(hosts2scan_shortFormat, parameters)
			# indicate options
			self.scanOptions['custom']=1
			self.__actualiceOptions()
			# show ip of hosts up
			self.__showHostsIPscannedUp()
			# actualice database. In CustomParameters all the information is saved
			self.__actualiceDB(hosts2scan_longFormat, ports2scan_longFormat)
			# clear option
			self.scanOptions['custom']=0
			self.__actualiceOptions()

	def puertos(self):
	# introduce hosts ip and ports to scan and check if ports are open or closed, not more information is saved
		self.__initScan()
		# ask for hosts ip to scan
		hosts2scan_shortFormat = self.__ask4hosts2scanOptions()[0]
		if hosts2scan_shortFormat != -1:
			# ask ports to scan
			[ports2scan_shortFormat, ports2scan_longFormat] = self.__ask4ports2search()
			if ports2scan_shortFormat != None:
				# scan
				self.__scanPorts(hosts2scan_shortFormat, ports2scan_shortFormat)
				# indicate options
				self.scanOptions['portsState']=1
				self.__actualiceOptions()
				# actualice database
				self.__actualiceDB(None, ports2scan_longFormat)
				# clear options
				self.scanOptions['portsState']=0
				self.__actualiceOptions()

	def portsFile(self):
	# create a .txt file, one per port indicated, with hosts IP up with those ports open
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# ask ports to export
		ports2File = self.__ask4ports2search()[1] # list of int numbers as strings, with all ports
		if ports2File != None:
			for port in ports2File:
				hostsIPwithAPort = self.__checkDBandGetDB4hostsIPwithAPort(port)
				if hostsIPwithAPort != -1: # port at database
					self.__createFile(port, hostsIPwithAPort)

	def allInfoHost(self):
		print 'Coming soon'
	# # create a .txt file or print at console the information associated to a host
	# 	# check if a revision and audit were selected
	# 	self.__check_audit_rev()
	# 	# ask how to get the information
	# 	modeHostInformation = self.__askOptionHostIPallInfo()
	# 	hostsIP_shortFormat, hostsIP_longFormat = self.__askHostsIP()
	# 	for hostIP in hostsIP_longFormat:
	# 		hostsMac4IP = self.getMacs4IP(hostIP) # list of strings with hosts mac that have same IP. If only one mac it is a list of one string
	# 		if len (hostsMac4IP) > 1:
	# 			print '\nPlease, type again ports you want to scan'
	# 		for hostMac in hostsMac4IP:
	# 			hostAllInformation = self.__getHostAllInformationDB(hostMac, hostIP) # get only info of the mac with the indicated IP
	# 			if modeHostInformation == 1: # export .txt file
	# 				print 'Txt created'
	# 			elif modeHostInformation == 2: # print info
	# 				print hostAllInformation
    #
	# def __getHostAllInformationDB(self, hostMac, hostIP):
	# 	line1 = 'Host Mac: ' + str(hostMac)
	# 	line2 = 'Host IP: ' + str(hostIP)
	# 	hostOS = ''
	# 	openPorts = ''
	# 	openPortsInfo = self.__getDBPortInfo()
	# 	hostsInfo = line1 + '\n' + line2 + '\n'
	# 	return hostsInfo

	def calcIPbase(self):
		self.cIP.askAndCalculate()

	def __initScan(self):
		# get my hosts IP
		self.myIP = self.nt.getMyIP()
		# check if you have network connection
		self.nt.checkNetworkConnection(self.myIP)
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addDBlastRevisionHosts()

	def __actualiceOptions(self):
		# know type of scan
		self.scanOptions4Hosts = [self.scanOptions['discovery'], self.scanOptions['operatingSystem'], self.scanOptions['custom']] # options for studying ports
		self.scanOptions4Ports = [self.scanOptions['versionORscript'], self.scanOptions['portsState'], self.scanOptions['custom']] # options for studying ports
		# as we see, with custom option all the information is saved

	def __check_audit_rev(self):
		if self.auditNumber == None and self.auditName == None:
			self.select_audit()
		if self.revisionNumber == None and self.revisionName == None:
			self.select_revision()

	def __ask4hosts2scanOptions(self):
		# get ip to scan
		print color('bcyan', 'Select IP to scan')
		print color('cyan', '1. IP discovered \n2. Specify IP')
		option2scan= ''
		while option2scan != 1 and option2scan != 2:
			option2scan = self.ask.ask4number()
		if option2scan == 1:
			# check if the discovery option was maded for this revision
			discoveryDone = self.db.check_tableHostsValues4ThisRevision(self.auditNumber, self.revisionNumber) # check values at hosts table for this revision
			if discoveryDone == 1:
				# scan all discovered hosts, down hosts too because they can change to up
				hosts2scan_longFormat = self.db.retrieve_hosts_ip_by_revision(self.auditNumber, self.revisionNumber)
				hosts2scan_shortFormat, hosts2scan_longFormat = self.__getShortLongFormatFromLongFormat(hosts2scan_longFormat)
				print "Hosts to scan: " + str(hosts2scan_longFormat)
				print "Number of hosts to scan: " + str(len(hosts2scan_longFormat))
			else:
				print color('rojo', 'No hosts ip discovered for this revision')
				hosts2scan_shortFormat, hosts2scan_longFormat = self.__askHostsIP()
		elif option2scan == 2:
			hosts2scan_shortFormat, hosts2scan_longFormat = self.__askHostsIP()
		return [hosts2scan_shortFormat, hosts2scan_longFormat] # -hosts2scan_shortFormat example: '192.168.1.1,2' -hosts2scan_longFormat example ('192.168.1.1','192.168.1.2')

	def __askHostsIP(self):
		hostsIP_shortFormat=''
		while hostsIP_shortFormat == '':
			hostsIP_shortFormat = raw_input('Type an IP or range (no spaces): ')
			if self.ck.checkCharacter(hostsIP_shortFormat) == 1 or self.ck.checkIPparts(hostsIP_shortFormat) == -1:
				self.ms.adviseInvalidSyntax()
				hostsIP_shortFormat=''
			else:
				hostsIP_longFormat = self.cf.hosts2completeFormat(hostsIP_shortFormat) # return list. Example ['192.168.1.50', '192.168.1.51', '192.168.1.52']
				hostsIP_shortFormat, hostsIP_longFormat = self.__getShortLongFormatFromLongFormat(hostsIP_longFormat)
		return hostsIP_shortFormat, hostsIP_longFormat

	def __getShortLongFormatFromLongFormat(self, hostsIP_longFormat):
		# variables:
		# - input
		# -- hostsIP_longFormat: hosts ip at complete format
		# - output:
		# -- hostsIP_shortFormat: hosts ip at nmap format
		# -- hostsIP_longFormat: hosts ip at complete format
		hostsIP_longFormat = tuple(self.cf.eliminateMyIPInAList(hostsIP_longFormat, self.myIP)) # tuple for SQL queries
		hostsIP_shortFormat = self.cf.hosts2nmapFormat(hostsIP_longFormat)
		return hostsIP_shortFormat,hostsIP_longFormat

	def __ask4parameters(self):
		parameters=""
		while parameters == "":
			parameters = raw_input('Type parameters for the scan: ')
			if self.ck.checkInString(parameters, self.scanCustomNotAllowedOptions) == 1:
				parameters = ""
				print color('rojo', 'Thanks for using this tool\nThe specified option is not available\nRemember, this tool works with a database\nOptions not allowed: '+str(self.scanCustomNotAllowedOptions)+'\nTry another command')
		return parameters

	# add last revison's hosts if this is the first discovery for actual revision
	def __addDBlastRevisionHosts(self):
		revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.auditNumber, self.revisionNumber)
		if revision_with_values == -1:
			self.db.add_old_hosts (self.auditNumber, self.revisionNumber)

	# scan for Discovery option
	def __scanDiscovery(self, hosts2scan):
		print 'Discovery scan started'
		self.nm.scan(hosts=hosts2scan, arguments='-n -sP --exclude '+str(self.myIP))

	# scan for Operating System
	def __scanDiscoverOS(self, hosts2scan):
		print 'Discover operating system started'
		self.nm.scan(hosts=hosts2scan, arguments='-O --exclude '+str(self.myIP))

	# scan for Version option
	def __scanVersion(self, hosts2scan):
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
		print 'Ports scan started'
		self.nm.scan(hosts=hosts2scan, arguments="-p"+ports2scan)

	def __actualiceDB(self, hosts2scan_longFormat=None, ports2scan_longFormat=None): # example hosts2scan_longFormat=('192.168.1.50', '192.168.1.51', '192.168.1.52')
		macs_up = [] # using later to know which hosts mac put down
		# indicate how info will will be showed
		if self.ck.checkAnyIs1(self.scanOptions4Ports) == 1:
			print 'Hosts IP: [open ports]'
		for hostIP in self.nm.all_hosts():
			# get host info
			mac, os, portsUp = self.__getHostScannedInformation(hostIP)
			# work with host mac
			if mac == None:
				print str(hostIP) + ": no mac info"
			else:
				if self.ck.checkAnyIs1(self.scanOptions4Hosts) == 1:
					macs_up.append(mac)
			# add host to hosts table (new hosts can be discovered)
			self.__addDBUpHost(hostIP, mac, os)  # if the host is at the db, it is added again to know the last time it was scanned
			# work with ports
			if self.ck.checkAnyIs1(self.scanOptions4Ports) == 1:
				# show scanned information
				self.__printPortsScanned(hostIP, portsUp)
				# actualice db for ports
				self.__actualiceDBTablePuertos(mac, hostIP, portsUp, ports2scan_longFormat)
		# add 'down' hosts at host table
		if self.ck.checkAnyIs1(self.scanOptions4Hosts)==1:
			# not add 'down' hosts at hosts table when ports are studied because not scanned ports (-> not host showed as up) do not mean the host is down
			self.__addDBDownHosts(macs_up, hosts2scan_longFormat)
		# indicate no ports were scanned when scanning ports
		if self.nm.all_hosts() == [] and self.ck.checkAnyIs1(self.scanOptions4Ports)==1: # if all ports are closed then nm.all_hosts()=[] (empty)
			print 'No ports'

	# add new row with host up at hosts table
	def __addDBUpHost(self, ip, mac, os=None):
		self.db.add_host('up', self.revisionNumber, ip, mac, os)

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
		down_host = self.db.retrieve_hostAllInfoByID(id_host)
		os, status, id, rev, ip, date, mac = down_host[0]
		self.db.add_host('down', self.revisionNumber, ip, mac)

	def __actualiceDBTablePuertos(self, mac, hostWithPorts, portsUp, ports2scan):
		# get id of the host (using mac) with we are working now
		id_hostWithPorts = self.db.retrieve_host_id (self.auditNumber, self.revisionNumber, mac)
		# add last ID host ports. One time for each host ID
		self.__addDBLastIDhostPorts(hostWithPorts, id_hostWithPorts, mac)
		if portsUp != None:
			# add new information to puertos table
			self.__addDBnewPorts(id_hostWithPorts, portsUp, hostWithPorts)
			# add 'closed' ports
			self.__addDBclosedPorts(id_hostWithPorts, portsUp, ports2scan)

	# add ports associated to this host (mac) but at the db are associated to an old id_host
	# it is done only one time per id_host (at first time working with the id_host)
	def __addDBLastIDhostPorts(self, hostWithPorts, actualHostID, mac):
		# check if the actual id host has values. In order to add old ports only one time per host ID
		check_idHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(actualHostID)
		if check_idHost_with_portsValues != 1:
			# search the last ports information associated to this host (mac) at the table, search the maximum previous id of this host(mac) with port values
			previousHostID = self.db.retrieve_previous_host_id(self.auditNumber, mac, actualHostID)
			# ckeck if last id has values at table puertos
			check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
			# search last id for this host (mac) with ports values
			while check_idPreviousHost_with_portsValues == -1 and previousHostID > 0:
				previousHostID = self.db.retrieve_previous_host_id(self.auditNumber, mac, previousHostID)
				check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
			# add previous id_host ports to the actual id_host
			if check_idPreviousHost_with_portsValues == 1:
				self.db.add_old_ports4host (previousHostID, actualHostID)

	def __addDBnewPorts(self, id_hostWithPorts, ports, hostWithPorts):
		# work with each port of the host
		for port in ports:
			# get port values
			portInformation = self.__getScannedPortInformation(hostWithPorts, port) # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
			# add port
			# always add in order to know last scan time
			if self.scanOptions['portsState'] == 0:
				state = 'open'
			else:
				state = portInformation[2]
			self.db.add_port(state, id_hostWithPorts, port, portInformation[0], portInformation[1])

	def __getHostScannedInformation(self, hostIP):
		mac = self.__getScannedMac(hostIP)
		os = self.__getScannedOperatingSystem(hostIP, mac)
		portsUp = self.__getScannedPorts(hostIP)
		return mac, os, portsUp

	def __getScannedMac (self, ip):
		# if not port information is scanned, self.nm[hostWithPorts]['addresses']['mac'] generate an exception
		try:
			return self.nm[ip]['addresses']['mac'] # addresses: addresses of the discovered host
		except:
			return None

	def __getScannedOperatingSystem(self, ip, mac):
		# example, for a mobile phone this information will be saved: 'osclass': {'vendor': 'Apple', 'osfamily': 'iOS', 'type': 'phone', 'osgen': '6.X', 'accuracy': '100'}
		# example2, for a pc not retrieves osclass, only vendor: {'status': {'state': 'up', 'reason': 'arp-response'}, 'hostnames': [], 'vendor': {'xx:xx:xx:xx:xx:xx': 'Microsoft'}, 'addresses': {'mac': '20:62:74:DE:4D:88', 'ipv4': '172.19.221.10'}}
		if self.scanOptions['discovery'] == 1:
			return None
		else:
			try:
				return self.cf.convertDictionary2String(self.nm[ip]['osclass'])
			except: # if not information are retrieved in 'osclass' maybe are at other form like at example2
				return self.__getScannedOperatingSystemInfoIndividually(ip, mac)

	def __getScannedOperatingSystemInfoIndividually(self, ip, mac):
		# retreive information search directly for 'vendor', 'osfamily' etc
		vendor = self.__getScannedOSvendor(ip,mac)
		osfamily = self.__getScannedOSfamily(ip,mac)
		type = self.__getScannedOStype(ip,mac)
		osgen = self.__getScannedOSgen(ip,mac)
		accuracy = self.__getScannedOSaccuracy(ip,mac)
		OS = 'vendor: %s \nosfamily: %s \ntype: %s \nosgen: %s  \naccuracy: %s' %(vendor, osfamily, type, osgen, accuracy)
		return OS

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

	def __getScannedPorts(self, ip):
		# retrieve ports numbers, example: [22, 8080]
		# if not port information is scanned, ports = self.nm[hostWithPorts]['tcp'].keys() generates an exception
		try:
			return self.nm[ip]['tcp'].keys()
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
			script = self.cf.convertDictionary2String(script)
		return script

	def __getScannedPortState(self, hostWithPorts, port):
		return self.__getScannedPortInfo(hostWithPorts,port,'state')

	def __getScannedPortInfo(self, ip, port, info):
		# get the information indiciated of the port of a host
		try:
			return self.nm[ip]['tcp'][port][info] # name, state, etc: string. script: dictionary
		except:
			return None

	def __addDBclosedPorts(self, id_hostWithPorts, portsUp, portsScanned):
		# portScanned: list of int numbers as strings
		if self.scanOptions['portsState'] == 0:
			# ports at the db for a id_host that where 'open'
			id_ports2putClosed = self.db.retrieve_id_ports2putClosed(id_hostWithPorts, portsUp)
		else:
			# ports to put as closed ports had to been scanned
			id_ports2putClosed = self.db.retrieve_id_ports2putClosedPortOption(id_hostWithPorts, portsUp, portsScanned)
		if id_ports2putClosed != -1: # at the db are ports associated to a host
			# work with each port
			for id_port in id_ports2putClosed:
				closed_port = self.db.retrieve_port_by_id (id_port)
				if closed_port != -1:
					id_port, id_hosts_port, puerto_port, estado_port, version_port, fecha_port, scripts_port = closed_port[0]
					self.db.add_port('closed', id_hostWithPorts, puerto_port, version_port, scripts_port)
					#self.db.update_port_estadoANDfecha('closed', id_hostWithPorts, old_port[0])

	def __ask4ports2search(self):
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

	def __askOptionHostIPallInfo(self):
		mode = ""
		while mode == "":
			mode = raw_input('Export information in a .txt file (1) or show in window (2)?')
			if mode == str(1):
				mode = 1
			elif mode == str(2):
				mode = 2
			else:
				mode = ""
		return mode

	def __showHostsIPscannedUp(self, showAllInfo=0):
		print 'Hosts scanned up: ' + str(self.nm.all_hosts())
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

	def __printPortsScanned(self, hostWithPorts, ports, showAllInfo=0):
		if ports == None:
			print str(hostWithPorts) + ": no ports info"
		else:
			ports = sorted(set(ports), key=int) # order in ascendent mode
			if self.scanOptions['portsState'] == 0:
				# show scanned ports
				if showAllInfo == 0:
					print str(hostWithPorts) + ': ' + str(ports)
				else:
					print '\n' + str(hostWithPorts) + ': ' + str(ports)
					for port in ports:
						portVersionInformation = self.__getScannedPortInformation(hostWithPorts, port)[0] # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
						print '- ' + str(port)
						print portVersionInformation
						# try:
						# 	for key, value in self.nm[host]['osclass'].iteritems():
						# 		print '- %s: %s' %(key, value)
						# except:
						# 	print '- No info scanned'
			else:
				# Port scan only show open ports
				portsOpen = []
				for port in ports:
					if self.__getScannedPortInformation(hostWithPorts, port)[2] == 'open': # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
						portsOpen.append(port)
				print str(hostWithPorts) + ' ' + str(portsOpen)

	def __checkDBandGetDB4hostsIPwithAPort(self, port):
		# port: string
		# check if db has ports for this revision and return those hosts IP
		if self.db.check_portAtDB(self.auditNumber, self.revisionNumber, port) != -1:
			hostsIP = []
			# get hosts IP that are up with this port open
			hostsIPwithAPort = self.__getDBhostsIPwithAPort(port) # list of strings, example: [u'192.168.1.1', u'192.168.1.33']
			if hostsIPwithAPort != -1:
				for hostIP in hostsIPwithAPort:
					if self.ck.checkStrIsInt(hostIP,0) == -1: # ip is formed by four numbers sepprated with dots, is not an int number
						# convert to list of strings
						hostsIP.append(hostIP)
				return hostsIP
			else:
				return -1
		else:
			print 'Port %s not at database for this revision' %port
			return -1

	def __getDBhostsIPwithAPort(self, port):
		hostsIP = []
		idOfHostsUpWithPort = self.db.retrieve_idOfHostsUpWithAPort(port) # list of int numbers or only an int number
		if self.ck.checkStrIsInt(idOfHostsUpWithPort,0) == 1:
			listAuxiliar = []
			listAuxiliar.append(idOfHostsUpWithPort)
			idOfHostsUpWithPort = listAuxiliar
		for idHost in idOfHostsUpWithPort:
			lastIDport = self.db.retrieve_idOfLastPort4anIdHost(idHost, port)
			hostIP = self.db.retrieve_hostIP4portID(self.auditNumber, self.revisionNumber, lastIDport)
			hostsIP.append(hostIP) # list
		hostsIP = list(set(hostsIP)) # remove hosts IP repeated
		return hostsIP # example: [u'192.168.1.2', u'192.168.1.3']

	def __createFile(self, port, hostsIPwithAPort):
		auditName = self.db.retrieve_auditName(self.auditNumber)
		revisionName = self.db.retrieve_revisionName(self.auditNumber, self.revisionNumber)
		fileName = auditName + '_' + revisionName + '_' + port + '.txt'
		fileCompleteName = os.path.join(self.save_path, fileName)
		if self.__checkFileExists(fileCompleteName) == 1:
			if self.__askOverwriteFile(port) == -1:
				fileName = auditName + '_' + revisionName + '_' + port + '_' + self.__getDatetime() + '.txt'
				fileCompleteName = os.path.join(self.save_path, fileName)
		file = open(fileCompleteName,'w')
		for ip in hostsIPwithAPort:
			file.write(ip + '\n')
		file.close()
		if self.ck.checkListEmpty(hostsIPwithAPort) != -1:
			print 'Port %s at database but port is closed or hosts are down \nFile created empty' %port
		print 'File created: ' + fileName

	def __checkFileExists(self, fileName):
		try:
			open(fileName,'r')
			return 1
		except:
			return -1

	def __askOverwriteFile(self, port):
		fileOptions = ""
		while fileOptions == "":
			print color('rojo', 'File for port ' +str(port)+ ' already exists')
			print color('cyan', 'Options:\n1.Overwrite \n2.New file')
			fileOptions = self.ask.ask4number()
			if fileOptions == 2:
				fileOptions = -1
		return fileOptions

	def __getDatetime(self):
		time2 = time.strftime("%H-%M-%S")
		date = time.strftime("%Y-%m-%d")
		datetime = '%s_%s' %(date, time2)
		return datetime