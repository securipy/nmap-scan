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
from utility2 import CalcIP, ChangeFormat, Check
import pprint

class Scan:

	def __init__(self):
		self.num_audit = None
		self.nom_audit = None
		self.num_rev = None
		self.nom_rev = None
		self.nm = nmap.PortScanner()
		self.db = Database()
		self.cIP = CalcIP()
		self.cf = ChangeFormat()
		self.ck = Check()
		self.save_path = 'modules/nmap-scan/model/ports' # save .txt files
		self.myIP = self.__getMyIP()# avoid save information of our own host
		self.scanOptions = {'discovery':0, 'operatingSystem':0, 'versionORscript':0, 'custom':0, 'portsState':0} # what the user want to scan. Values: -1 (not used) or 1 (used)
		self.scanCustomNotAllowedOptions = ['-iR'] # not allowed command at CustomParameters option

	def __getMyIP(self):
		myIP = socket.gethostbyname(socket.gethostname())
		if self.ck.checkNetworkConnection(self.myIP) == -1:
			self.myIP = self.__getInterfaceIP('eth0') # required at wired connections, because the last option get another interface IP

	def __getInterfaceIP(self, interface):
	# get IP address of the indicated interface
	# https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
	    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	    return socket.inet_ntoa(fcntl.ioctl(
	        s.fileno(),
	        0x8915,  # SIOCGIFADDR
	        struct.pack('256s', interface[:15])
	    )[20:24])

	def __actualieOptions(self):
		# know type of scan
		self.scanOptions4Hosts = [self.scanOptions['discovery'], self.scanOptions['operatingSystem'], self.scanOptions['custom']] # options for studying ports
		self.scanOptions4Ports = [self.scanOptions['versionORscript'], self.scanOptions['portsState'], self.scanOptions['custom']] # options for studying ports
		# as we see, with custom option all the information is saved

	def select_audit(self):
		auditNotAtDB = 0
		audit_action = ""
		print color('cyan', '1. New audit\n2. Existing audit')
		while audit_action == "":
			audit_action = raw_input('Select option: ')
		if audit_action == '1':
			# Add new audit
			new_audit = raw_input('Name audit: ')
			while new_audit == "":
				new_audit = raw_input('Name audit: ')
			if len(self.db.retrieve_audit_name(new_audit)) == 0:
				self.num_audit = self.db.add_audit(new_audit)
				self.nom_audit = new_audit
				self.select_revision()
			else:
				print color('rojo', '\nRepeated name\n')
				self.select_audit()
		elif audit_action == '2':
			# Select existing audit
			all_audits = self.db.retrieve_audits()
			if len(all_audits) == 0:
				print color("rojo", "\nNo existing audits\n")
				self.select_audit()
			else:
				for num,audit in all_audits:
					print color('verde' , str(num)+". "+audit )
				number_audit = raw_input('Number audit: ')
				while number_audit == "":
					number_audit = raw_input('Number audit: ')
				self.num_audit = number_audit
				all_audits = dict((x,y) for x, y in all_audits)
				try:
					self.nom_audit = all_audits[int(number_audit)]
				except:
					print color('rojo', '\nAudit does not exist\n')
					auditNotAtDB = 1
				if auditNotAtDB != 1:
					self.select_revision()
				else:
					self.select_audit()
		else:
			print color('rojo', '\nInvalid option\n')
			self.select_audit()

	def select_revision(self):
		if self.num_audit == None and self.nom_audit == None:
			print "Select audit before revison"
			self.select_audit()
		else: # necessary to solve issue 1 (view Issues at github.com)
			rev_action = ""
			print color('cyan', '1. New revision\n2. Existing revision')
			while rev_action == "":
				rev_action = raw_input('Select option: ')
			if rev_action == '1':
				# Add new revision
				new_rev = raw_input('Name revision: ')
				while new_rev == "":
					new_rev = raw_input('Name revision: ')
				if len(self.db.retrieve_revison_name(new_rev, self.num_audit)) == 0:
					self.num_rev = self.db.add_revision(int(self.num_audit), new_rev)
					self.nom_rev = new_rev
				else:
					print color('rojo', '\nRepeated name\n')
					self.select_revision()
			elif rev_action == '2':
				# Select existing revision
				all_revs = self.db.retrieve_revison_id(self.num_audit)
				if len(all_revs) == 0:
					print color("rojo", "\nNo existing revisions\n")
					print "Create a revision for this audit"
					self.select_revision()
				else:
					for fecha, num, id_audit, rev in all_revs:
						print color('verde' , str(num)+". "+rev+" ("+str(fecha)+")")
					number_rev = raw_input('Number revision: ')
					while number_rev == "":
						number_rev = raw_input('Number revision: ')
					self.num_rev = number_rev
					all_revs = dict((y,z) for x,y, w, z in all_revs)
					try:
						self.nom_rev = all_revs[int(number_rev)]
					except:
						print color('rojo', '\nRevision not at this audit\n')
			else:
				print color('rojo', '\nInvalid option\n')
				self.select_revision()

	def discovery(self):
		# check if a revision and audit were selected and add last revison hosts (once per revision), and notifies if you haven't got network connection
		self.__initScan()
		# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
		hosts2scan_shortFormat, hosts2scan_longFormat = self.__ask4hosts2scan()
		if hosts2scan_longFormat != -1:
			# scan
			self.__scanDiscovery(hosts2scan_shortFormat)
			# indicate option
			self.scanOptions['discovery']=1
			self.__actualieOptions()
			# show ip of hosts up
			self.__printHostsScanned()
			# actualice database
			self.__actualiceDB(hosts2scan_longFormat)
			# clear option
			self.scanOptions['discovery']=0
			self.__actualieOptions()

	def discoverOS(self):
		# check if a revision and audit were selected and add last revison hosts (once per revision), and notifies if you haven't got network connection
		self.__initScan()
		# ask for hosts ip to scan. Save hosts ip as nmap format (shortFormat) and as complete format (longFormat)
		[hosts2scan_shortFormat, hosts2scan_longFormat] = self.__ask4hosts2scanOptions()
		# save ip to scan
		if hosts2scan_shortFormat != -1 and hosts2scan_longFormat != -1:
			# scan
			self.__scanDiscoverOS(hosts2scan_shortFormat)
			# indicate option
			self.scanOptions['operatingSystem']=1
			self.__actualieOptions()
			# show ip of hosts scanned
			self.__printHostsScanned()
			# actualice database
			self.__actualiceDB(hosts2scan_longFormat)
			# clear option
			self.scanOptions['operatingSystem']=0
			self.__actualieOptions()

	def version(self):
		# check if a revision and audit were selected and add last revison hosts (once per revision), and notifies if you haven't got network connection
		self.__initScan()
		# ask for hosts ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
		if hosts2scan != -1:
			# scan
			self.__scanVersion(hosts2scan)
			# indicate option
			self.scanOptions['versionORscript']=1
			self.__actualieOptions()
			# show ip of hosts up
			self.__printHostsScanned()
			# actualice database
			self.__actualiceDB()
			# clear option
			self.scanOptions['versionORscript']=0
			self.__actualieOptions()

	def script(self):
		# check if a revision and audit were selected and add last revison hosts (once per revision), and notifies if you haven't got network connection
		self.__initScan()
		# ask for hosts ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
		if hosts2scan != -1:
			# scan
			self.__scanScript(hosts2scan)
			# indicate option
			self.scanOptions['versionORscript']=1
			self.__actualieOptions()
			# show ip of hosts up
			self.__printHostsScanned()
			# actualice database
			self.__actualiceDB()
			# clear option
			self.scanOptions['versionORscript']=0
			self.__actualieOptions()

	def CustomParameters(self):
		# introduce custom parameters
		# check if a revision and audit were selected and add last revison hosts (once per revision), and notifies if you haven't got network connection
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
			self.__actualieOptions()
			# show ip of hosts up
			self.__printHostsScanned()
			# actualice database. In CustomParameters all the information is saved
			self.__actualiceDB(hosts2scan_longFormat, ports2scan_longFormat)
			# clear option
			self.scanOptions['custom']=0
			self.__actualieOptions()

	def puertos(self):
	# introduce hosts ip and ports to scan and check if ports are open or closed, not more information is saved
		# check if a revision and audit were selected and add last revison hosts (once per revision), and notifies if you haven't got network connection
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
				self.__actualieOptions()
				# actualice database
				self.__actualiceDB(None, ports2scan_longFormat)
				# clear options
				self.scanOptions['portsState']=0
				self.__actualieOptions()

	def portsFile(self):
	# create a .txt file, one per port indicated, with hosts IP up with those ports open
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# ask ports to export
		ports2File = self.__ask4ports2search()[1] # list of int numbers as strings, with all ports
		if ports2File != None:
			for port in ports2File:
				portHostsIP = self.__searchPortHostsIP(port)
				if portHostsIP != -1: # port at database
					self.__createFile(port, portHostsIP)

	def allInfoHost(self):
	# create a .txt file or print at console the information associated to a host
	# 	# check if a revision and audit were selected
	# 	self.__check_audit_rev()
	# 	# ask how to get the information
	# 	modeHostInformation = self.__ask4AllInfoHostMode()
		print 'Coming soon'

	def __initScan(self):
		# check if you have network connection
		self.__checkNetworkConnection()
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addLastRevisionHosts()

	def __checkNetworkConnection(self):
		if self.ck.checkNetworkConnection(self.myIP) == -1:
			print color('rojo', 'Are you sure you have network connection?')

	def __check_audit_rev(self):
		if self.num_audit == None and self.nom_audit == None:
			print color('bcyan', "Select audit")
			self.select_audit()
		if self.num_rev == None and self.nom_rev == None:
			print color('bcyan', "Select revision")
			self.select_revision()

	def __ask4hosts2scanOptions(self): #__ -> class private method
		# get ip to scan
		option2scan = 0
		print 'Select IP to scan: '+color('cyan','\n1. IP discovered \n2. Specify IP')
		while option2scan != 1 and option2scan != 2:
			option2scan = raw_input ('>> ')
			if self.ck.checkInt(option2scan) == -1:
				option2scan = 0
			else:
				option2scan = int(option2scan)
		if option2scan == 1:
			# check if the discovery option was maded for this revision
			discoveryDone = self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev) # check values at hosts table for this revision
			if discoveryDone == 1:
				# scan all discovered hosts, down hosts too because they can change to up
				hosts2scan_longFormat = self.db.retrieve_hosts_ip_by_revision(self.num_audit, self.num_rev)
				hosts2scan_shortFormat, hosts2scan_longFormat = self.__getShortLongFormat(hosts2scan_longFormat)
				print "Hosts to scan: " + str(hosts2scan_longFormat)
				print "Number of hosts to scan: " + str(len(hosts2scan_longFormat))
			else:
				print color('rojo','No hosts ip discovered for this revision')
				hosts2scan_shortFormat = -1
				hosts2scan_longFormat = -1
				hosts2scan_shortFormat, hosts2scan_longFormat = self.__ask4hosts2scan()
		elif option2scan == 2:
			hosts2scan_shortFormat, hosts2scan_longFormat = self.__ask4hosts2scan()
		if hosts2scan_shortFormat == -1:
			print "Error selecting ip"
		return [hosts2scan_shortFormat, hosts2scan_longFormat] # -hosts2scan_shortFormat example: '192.168.1.1,2' -hosts2scan_longFormat example ('192.168.1.1','192.168.1.2')

	def __ask4hosts2scan(self):
		hosts2scan_shortFormat=""
		while hosts2scan_shortFormat == "":
			hosts2scan_shortFormat = raw_input('Type an IP or range (no spaces): ')
			if self.ck.checkCharacter(hosts2scan_shortFormat) == 1 or self.ck.checkIPparts(hosts2scan_shortFormat) == -1:
				self.__printInvalidSyntax()
				hosts2scan_shortFormat=""
			else:
				hosts2scan_longFormat = self.cf.hosts2completeFormat(hosts2scan_shortFormat) # return list. Example ['192.168.1.50', '192.168.1.51', '192.168.1.52']
				hosts2scan_shortFormat, hosts2scan_longFormat = self.__getShortLongFormat(hosts2scan_longFormat)
		return hosts2scan_shortFormat, hosts2scan_longFormat

	def __getShortLongFormat(self, hosts2scan_longFormat):
		# variables:
		# - input
		# -- hosts2scan_longFormat: hosts ip at complete format
		# - output:
		# -- hosts2scan_shortFormat: hosts ip at nmap format
		# -- hosts2scan_longFormat: hosts ip at complete format
		hosts2scan_longFormat = tuple(self.cf.eliminateMyIPInAList(hosts2scan_longFormat, self.myIP)) # tuple for SQL queries
		hosts2scan_shortFormat = self.cf.hosts2nmapFormat(hosts2scan_longFormat)
		return hosts2scan_shortFormat,hosts2scan_longFormat

	def __ask4parameters(self):
		parameters=""
		while parameters == "":
			parameters = raw_input('Type parameters for the scan: ')
			if self.ck.checkInString(parameters, self.scanCustomNotAllowedOptions) == 1:
				parameters = ""
				print color('rojo','Thanks for using this tool\nThe specified option is not available\nRemember, this tool works with a database\nOptions not allowed: '+str(self.scanCustomNotAllowedOptions)+'\nTry another command')
		return parameters

	# add last revison's hosts if this is the first discovery for actual revision
	def __addLastRevisionHosts(self):
		revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev)
		if revision_with_values == -1:
			self.db.add_old_hosts (self.num_audit, self.num_rev)

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
			mac, os, portsUp = self.__getHostInformation(hostIP)
			# work with host mac
			if mac == None:
				print str(hostIP) + ": no mac info"
			else:
				if self.ck.checkAnyIs1(self.scanOptions4Hosts) == 1:
					macs_up.append(mac)
			# add host to hosts table (new hosts can be discovered)
			self.__addUpHost(hostIP, mac, os)  # if the host is at the db, it is added again to know the last time it was scanned
			# work with ports
			if self.ck.checkAnyIs1(self.scanOptions4Ports) == 1:
				# show scanned information
				self.__printPortsScanned(hostIP, portsUp)
				# actualice db for ports
				self.__actualiceTablePuertos(mac, hostIP, portsUp, ports2scan_longFormat)
		# add 'down' hosts at host table
		if self.ck.checkAnyIs1(self.scanOptions4Hosts)==1:
			# not add 'down' hosts at hosts table when ports are studied because not scanned ports (-> not host showed as up) do not mean the host is down
			self.__addDownHosts(macs_up, hosts2scan_longFormat)
		# indicate no ports were scanned when scanning ports
		if self.nm.all_hosts() == [] and self.ck.checkAnyIs1(self.scanOptions4Ports)==1: # if all ports are closed then nm.all_hosts()=[] (empty)
			print 'No ports'

	# add new row with host up at hosts table
	def __addUpHost(self, ip, mac, os=None):
		self.db.add_host('up', self.num_rev, ip, mac, os)

	# add 'down' hosts
	def __addDownHosts(self, macs_up, hosts_scanned):
		# macs_up: list of strings
		# hosts_scanned: tuple of strings
		id_hosts2putDown = self.db.retrieve_id_hosts2putDown(self.num_audit, self.num_rev, macs_up, self.nm.all_hosts(), hosts_scanned)
		if id_hosts2putDown != -1:
			for id_host in id_hosts2putDown:
				self.__addDownHost(id_host)

	# add new row with hosts down at hosts table
	def __addDownHost(self, id_host):
		down_host = self.db.retrieve_host_by_id(id_host)
		os, status, id, rev, ip, date, mac = down_host[0]
		self.db.add_host('down', self.num_rev, ip, mac)

	def __actualiceTablePuertos(self, mac, hostWithPorts, portsUp, ports2scan):
		# get id of the host (using mac) with we are working now
		id_hostWithPorts = self.db.retrieve_host_id (self.num_audit, self.num_rev, mac)
		# add last ID host ports. One time for each host ID
		self.__addLastIDhostPorts(hostWithPorts, id_hostWithPorts, mac)
		if portsUp != None:
			# add new information to puertos table
			self.__addNewPorts(id_hostWithPorts, portsUp, hostWithPorts)
			# add 'closed' ports
			self.__addClosedPorts(id_hostWithPorts, portsUp, ports2scan)

	# add ports associated to this host (mac) but at the db are associated to an old id_host
	# it is done only one time per id_host (at first time working with the id_host)
	def __addLastIDhostPorts(self, hostWithPorts, actualHostID, mac):
		# check if the actual id host has values. In order to add old ports only one time per host ID
		check_idHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(actualHostID)
		if check_idHost_with_portsValues != 1:
			# search the last ports information associated to this host (mac) at the table, search the maximum previous id of this host(mac) with port values
			previousHostID = self.db.retrieve_previous_host_id(self.num_audit, mac, actualHostID)
			# ckeck if last id has values at table puertos
			check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
			# search last id for this host (mac) with ports values
			while check_idPreviousHost_with_portsValues == -1 and previousHostID > 0:
				previousHostID = self.db.retrieve_previous_host_id(self.num_audit, mac, previousHostID)
				check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
			# add previous id_host ports to the actual id_host
			if check_idPreviousHost_with_portsValues == 1:
				self.db.add_old_ports4host (previousHostID, actualHostID)

	def __addNewPorts(self, id_hostWithPorts, ports, hostWithPorts):
		# work with each port of the host
		for port in ports:
			# get port values
			portInformation = self.__getPortInformation(hostWithPorts, port) # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
			# add port
			# always add in order to know last scan time
			if self.scanOptions['portsState'] == 0:
				state = 'open'
			else:
				state = portInformation[2]
			self.db.add_port(state, id_hostWithPorts, port, portInformation[0], portInformation[1])

	def __getHostInformation(self, hostIP):
		mac = self.__getMac(hostIP)
		os = self.__getOperatingSystem(hostIP, mac)
		portsUp = self.__getPorts(hostIP)
		return mac, os, portsUp

	def __getMac (self, ip):
		# if not port information is scanned, self.nm[hostWithPorts]['addresses']['mac'] generate an exception
		try:
			return self.nm[ip]['addresses']['mac'] # addresses: addresses of the discovered host
		except:
			return None

	def __getOperatingSystem(self, ip, mac):
		# example, for a mobile phone this information will be saved: 'osclass': {'vendor': 'Apple', 'osfamily': 'iOS', 'type': 'phone', 'osgen': '6.X', 'accuracy': '100'}
		# example2, for a pc not retrieves osclass, only vendor: {'status': {'state': 'up', 'reason': 'arp-response'}, 'hostnames': [], 'vendor': {'xx:xx:xx:xx:xx:xx': 'Microsoft'}, 'addresses': {'mac': '20:62:74:DE:4D:88', 'ipv4': '172.19.221.10'}}
		try:
			return self.cf.convertDictionary2String(self.nm[ip]['osclass'])
		except: # if not information are retrieved in 'osclass' maybe are at other form like at example2
			return self.__getOperatingSystemInfoIndividually(ip, mac)

	def __getOperatingSystemInfoIndividually(self, ip, mac):
		# retreive information search directly for 'vendor', 'osfamily' etc
		vendor = self.__getOSvendor(ip,mac)
		osfamily = self.__getOSfamily(ip,mac)
		type = self.__getOStype(ip,mac)
		osgen = self.__getOSgen(ip,mac)
		accuracy = self.__getOSaccuracy(ip,mac)
		OS = 'vendor: %s \nosfamily: %s \ntype: %s \nosgen: %s  \naccuracy: %s' %(vendor, osfamily, type, osgen, accuracy)
		return OS

	def __getOSvendor(self,ip,mac):
		return self.__getOS(ip,mac,'vendor')

	def __getOSfamily(self,ip,mac):
		return self.__getOS(ip,mac,'osfamily')

	def __getOStype(self,ip,mac):
		return self.__getOS(ip,mac,'type')

	def __getOSgen(self, ip,mac):
		return self.__getOS(ip,mac,'osgen')

	def __getOSaccuracy(self, ip,mac):
		return self.__getOS(ip,mac,'accuracy')

	def __getOS(self,ip,mac,info):
		try:
			return self.nm[ip][info][mac]
		except:
			return None

	def __getPorts(self, ip):
		# retrieve ports numbers, example: [22, 8080]
		# if not port information is scanned, ports = self.nm[hostWithPorts]['tcp'].keys() generates an exception
		try:
			return self.nm[ip]['tcp'].keys()
		except:
			return None

	def __getPortInformation(self, hostWithPorts, port):
		# sometimes the results have not all those values
		# version scan information
		product = self.__getPortProduct(hostWithPorts,port)
		version = self.__getPortVersion(hostWithPorts,port)
		name = self.__getPortName(hostWithPorts,port)
		extrainfo = self.__getPortExtrainfo(hostWithPorts,port)
		portVersionInformation = 'product: %s \nversion: %s \nname: %s \nextrainfo: %s' %(product, version, name, extrainfo)
		# script scan information
		portScriptInformation = self.__getPortScript(hostWithPorts,port)
		# port scan information (state)
		# only at this option we check if state is open or closed when put the port open or closed at the table because the other scan options only retrieve open ports
		portPortInformation = self.__getPortState(hostWithPorts, port)
		return [portVersionInformation, portScriptInformation, portPortInformation]

	def __getPortProduct(self, hostWithPorts, port):
		return self.__getPortInfo(hostWithPorts,port,'product')

	def __getPortVersion(self, hostWithPorts, port):
		return self.__getPortInfo(hostWithPorts,port,'version')

	def __getPortName(self, hostWithPorts, port):
		return self.__getPortInfo(hostWithPorts,port,'name')

	def __getPortExtrainfo(self, hostWithPorts, port):
		return self.__getPortInfo(hostWithPorts,port,'extrainfo')

	def __getPortScript(self, hostWithPorts, port):
		script = self.__getPortInfo(hostWithPorts,port,'script') # dictionary
		if script != None:
			script = self.cf.convertDictionary2String(script)
		return script

	def __getPortState(self, hostWithPorts, port):
		return self.__getPortInfo(hostWithPorts,port,'state')

	def __getPortInfo(self, ip, port, info):
		try:
			return self.nm[ip]['tcp'][port][info] # name, state, etc: string. script: dictionary
		except:
			return None

	def __addClosedPorts(self, id_hostWithPorts, portsUp, portsScanned):
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

	def calcIPbase(self):
		ip_mask = raw_input('Write your ipv4/mask (e.g. 192.168.1.5/255.255.255.0 or 192.168.1.5/24): ')
		while ip_mask == "":
			ip_mask = raw_input('Write your ipv4/mask (e.g. 192.168.1.5/255.255.255.0 or 192.168.1.5/24): ')
		try:
			[ipBase, ipHost1, ipHostUltimo, ipBroadcast, mask]=self.cIP.calculate_ip(ip_mask)
			print 'base ip / mask: '+ str(ipBase)+'/'+str(mask)
			print 'first host ip: ' + str(ipHost1)
			print 'last host ip: ' + str(ipHostUltimo)
			print 'broadcast ip: '+ str(ipBroadcast)
		except:
			self.__printInvalidSyntax()

	def __ask4ports2search(self):
		ports2search = ""
		while ports2search == "":
			ports2search = raw_input('Type ports (no spaces. For no port type None): ')
			if ports2search != 'None':
				if self.ck.checkCharacter(ports2search) == 1:
					self.__printInvalidSyntax()
					ports2search = ""
		if ports2search == 'None': # At custom parameters option not always ports will be scanned
			return[None, None]
		else:
			por2search_string = ports2search # example '20-22,80'
			ports2search_listOfStrings = self.cf.convertSring2ListWitchAllValues(ports2search) # example ['20', '21', '22, '80']
			return [por2search_string, ports2search_listOfStrings]

	def __ask4AllInfoHostMode(self):
		mode = ""
		while mode == "":
			mode = raw_input('Export information in a .txt file or show in console?')

	def __printHostsScanned(self, showAllInfo=0):
		if self.scanOptions['discovery'] == 1:
			print 'Hosts up: ' + str(self.nm.all_hosts())
			print 'My IP: ' + str(self.myIP)
		else:
			if showAllInfo == 0:
				print 'Hosts scanned up: ' + str(self.nm.all_hosts())
			else:
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
						portVersionInformation = self.__getPortInformation(hostWithPorts, port)[0] # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
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
					if self.__getPortInformation(hostWithPorts, port)[2] == 'open': # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
						portsOpen.append(port)
				print str(hostWithPorts) + ' ' + str(portsOpen)

	def __searchPortHostsIP(self, port):
		# port: string
		# check if db has ports for this revision
		if self.db.check_portAtDB(self.num_audit, self.num_rev, port) != -1:
			hostsIP = []
			# get hosts IP that are up with this port open
			portHostsIP = self.__getPortHostsIP(port) # list of strings, example: [u'192.168.1.1', u'192.168.1.33']
			if portHostsIP != -1:
				for hostIP in portHostsIP:
					if self.ck.checkInt(hostIP,0) == -1: # ip is formed by four numbers sepprated with dots, is not an int number
						# convert to list of strings
						hostsIP.append(hostIP)
				return hostsIP
			else:
				return -1
		else:
			print 'Port %s not at database for this revision' %port
			return -1

	def __getPortHostsIP(self, port):
		hostsIP = []
		idOfHostsUpWithPort = self.db.retrieve_idOfHostsUpWithAPort(port) # list of int numbers or only an int number
		if self.ck.checkInt(idOfHostsUpWithPort,0) == 1:
			listAuxiliar = []
			listAuxiliar.append(idOfHostsUpWithPort)
			idOfHostsUpWithPort = listAuxiliar
		for idHost in idOfHostsUpWithPort:
			lastIDport = self.db.retrieve_idOfLastPort4anIdHost(idHost, port)
			hostIP = self.db.retrieve_hostIP4portID(self.num_audit, self.num_rev, lastIDport)
			hostsIP.append(hostIP) # list
		hostsIP = list(set(hostsIP)) # remove hosts IP repeated
		return hostsIP # example: [u'192.168.1.2', u'192.168.1.3']

	def __createFile(self, port, portHostsIP):
		name_audit = self.db.retrieve_auditName(self.num_audit)
		name_rev = self.db.retrieve_revisionName(self.num_audit, self.num_rev)
		fileName = name_audit + '_' + name_rev + '_' + port + '.txt'
		fileCompleteName = os.path.join(self.save_path, fileName)
		if self.__checkFileExists(fileCompleteName) == 1:
			if self.__askOverwriteFile(port) == -1:
				fileName = name_audit + '_' + name_rev + '_' + port + '_' + self.__getDatetime() + '.txt'
				fileCompleteName = os.path.join(self.save_path, fileName)
		file = open(fileCompleteName,'w')
		self.__writeHostsIP(file, portHostsIP)
		file.close()
		if self.ck.checkListEmpty(portHostsIP) != -1:
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
			fileOptions = raw_input('File for port ' +str(port)+ ' already exists. Select option: ' + color('cyan','\n1.Overwrite \n2.New file') + '\n>> ')
			if self.ck.checkInt(fileOptions) == -1:
				fileOptions=""
			else:
				fileOptions = int(fileOptions)
			if fileOptions == 2:
				fileOptions = -1
			if fileOptions != -1 and fileOptions != 1:
				fileOptions=""
		return fileOptions

	def __getDatetime(self):
		time2 = time.strftime("%H-%M-%S")
		date = time.strftime("%Y-%m-%d")
		datetime = '%s_%s' %(date, time2)
		return datetime

	def __writeHostsIP(self, file, hostsIP):
		for ip in hostsIP:
			file.write(ip + '\n')

	def __printInvalidSyntax(self):
		print color('rojo', 'Invalid syntax')