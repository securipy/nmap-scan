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

	def select_audit(self):
		auditNotAtDB = 0
		audit_action = raw_input(color('cyan', '1. New audit\n2. Existing audit\n')+'Select option: ')
		while audit_action == "":
			audit_action = raw_input(color('cyan', '1. New audit\n2. Existing audit\n')+'Select option: ')
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
		else: # neccesary to solve issue 1 (view Issues at github.com)
			rev_action = raw_input(color('cyan', '1. New revision\n2. Existing revision\n')+'Select option: ')
			while rev_action == "":
				rev_action = raw_input(color('cyan', '1. New revision\n2. Existing revision\n')+'Select option: ')
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
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addLastRevisionHosts()
		# ask for ip to scan
		hosts2scan = self.__ask4hosts2scan()
		# save complete hosts ip to scan
		hosts2scan_longFormat=self.cf.IP2scan(hosts2scan) # example hosts2scan_longFormat=('192.168.1.50', '192.168.1.51', '192.168.1.52')
		if hosts2scan_longFormat != -1:
			# scan
			self.nm.scan(hosts=hosts2scan, arguments='-n -sP')
			# show ip of hosts up
			print 'hosts up: '+str(self.nm.all_hosts())
			# actualice hosts table
			self.__actualiceTableHosts(hosts2scan_longFormat)

	def discoverOS(self):
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addLastRevisionHosts()
		# ask for ip to scan
		[hosts2scan_shortFormat, hosts2scan_longFormat] = self.__ask4hosts2scanOptions()
		# save ip to scan
		if hosts2scan_shortFormat != -1 and hosts2scan_longFormat != -1:
			# scan
			self.__scanDiscoverOS(hosts2scan_shortFormat)
			# show ip of hosts up
			print 'hosts up: '+str(self.nm.all_hosts())
			# add hosts and ports to their tables
			self.__actualiceTableHosts(hosts2scan_longFormat)
		# ejm movil, guardar: 'osclass': {'vendor': 'Apple', 'osfamily': 'iOS', 'type': 'phone', 'osgen': '6.X', 'accuracy': '100'}

	def version(self):
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addLastRevisionHosts()
		# ask for ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
		if hosts2scan != -1:
			# scan
			self.__scanVersion(hosts2scan)
			# add hosts and ports to their tables
			self.__actualiceTablePuertosAndHosts()

	def script(self):
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addLastRevisionHosts()
		# ask for ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
		if hosts2scan != -1:
			# scan
			self.__scanScript(hosts2scan)
			# add hosts and ports to their tables
			self.__actualiceTablePuertosAndHosts()

	def CustomParameters(self):
		print 'Coming soon'
	# # introduce custom parameters
	# 	# check if a revision and audit were selected
	# 	self.__check_audit_rev()
	# 	# add last revison hosts (once per revision)
	# 	self.__addLastRevisionHosts()
	# 	# ask for ip to scan
	# 	hosts2scan = self.__ask4hosts2scanOptions()[0]
	# 	# ask for parameters of the scan
	# 	parameters = self.__ask4parameters()
	# 	if hosts2scan != -1:
	# 		# scan
	# 		self.__scanCustomParameters(hosts2scan, parameters)
	# 		# add hosts and ports to their tables
	# 		self.__actualiceTablePuertosAndHosts()

	def puertos(self):
	# introduce hosts ip and ports to scan and check if ports are open or closed, not more information is saved
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# add last revison hosts (once per revision)
		self.__addLastRevisionHosts()
		# ask for ip to scan
		hosts2scan = self.__ask4hosts2scanOptions()[0]
		if hosts2scan != -1:
			# ask ports to export
			[ports2scan_short, ports2scan_long] = self.__ask4ports2search()
			# scan
			self.__scanPorts(hosts2scan, ports2scan_short)
			# add hosts and ports to their tables
			self.__actualiceTablePuertosAndHosts(1, ports2scan_long)

	def portsFile(self):
	# create a .txt file, one per port indicated, with hosts IP up with those ports open
		# check if a revision and audit were selected
		self.__check_audit_rev()
		# ask ports to export
		ports2File = self.__ask4ports2search()[1] # list of int numbers as strings, with all ports
		for port in ports2File:
			portHostsIP = self.__searchPortHostsIP(port)
			if portHostsIP != -1: # port at database
				self.__createFile(port, portHostsIP)

	def __check_audit_rev(self):
		if self.num_audit == None and self.nom_audit == None:
			print color('bcyan', "Select audit")
			self.select_audit()
		if self.num_rev == None and self.nom_rev == None:
			print color('bcyan', "Select revision")
			self.select_revision()

	def __ask4hosts2scan(self):
		hosts2scan=""
		while hosts2scan == "":
			hosts2scan = raw_input('Type an IP or range (no spaces): ')
		return hosts2scan

	def __ask4hosts2scanOptions(self): #__ -> class private method
		# get ip to scan
		option2scan = 0
		while option2scan != 1 and option2scan != 2:
			option2scan = raw_input ('Select IP to scan: '+color('cyan','\n1. IP discovered \n2. Specify IP')+ '\n>> ')
			if self.ck.checkInt(option2scan) == -1:
				option2scan = 0
			else:
				option2scan = int(option2scan)
		if option2scan == 1:
			# check if the discovery option was maded for this revision
			discoveryDone = self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev) # check values at hosts table for this revision
			if discoveryDone == 1:
				hosts2scan_longFormat = self.db.retrieve_hosts_ip_by_revision(self.num_audit, self.num_rev)
				hosts2scan_longFormat = tuple(hosts2scan_longFormat)
				hosts2scan_shortFormat = self.cf.hosts2nmapFormat(hosts2scan_longFormat)
				print "Hosts to scan: " + str(hosts2scan_shortFormat)
				IPdiscovered=1
			else:
				print "No hosts ip discovered for this revision"
				hosts2scan_shortFormat = -1
				hosts2scan_longFormat = -1
				IPdiscovered = -1
		elif option2scan == 2:
			hosts2scan_shortFormat = self.__ask4hosts2scan()
			hosts2scan_longFormat = self.cf.IP2scan(hosts2scan_shortFormat)
		if hosts2scan_shortFormat == -1 and IPdiscovered != -1:
			print "Error selecting ip"
		return [hosts2scan_shortFormat, hosts2scan_longFormat] # -hosts2scan_shortFormat example: '192.168.1.1,2' -hosts2scan_longFormat example ('192.168.1.1','192.168.1.2')

	def __ask4parameters(self):
		parameters=""
		while parameters == "":
			parameters = raw_input('Type parameters for the scan: ')
		return parameters

	# add last revison's hosts if this is the first discovery for actual revision
	def __addLastRevisionHosts(self):
		revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev)
		if revision_with_values == -1:
			self.db.add_old_hosts (self.num_audit, self.num_rev)

	# scan for Operatim System
	def __scanDiscoverOS(self, hosts2scan):
		print 'Discover operating system started'
		self.nm.scan(hosts=hosts2scan, arguments="-O")

	# scan for Version option
	def __scanVersion(self, hosts2scan):
		print 'Port scan started'
		self.nm.scan(hosts=hosts2scan, arguments="-sV")

	# scan for Script option
	def __scanScript(self, hosts2scan):
		print 'Port scan started'
		self.nm.scan(hosts=hosts2scan, arguments="-sV -sC")

	# scan for CustomParameters option
	def __scanCustomParameters(self, hosts2scan, parameters):
		print 'Scan started'
		self.nm.scan(hosts=hosts2scan, arguments=parameters)

	# scan for Ports option
	def __scanPorts(self, hosts2scan, ports2scan):
		# hosts2scan: string
		# ports2scan: string
		print 'Port scan started'
		self.nm.scan(hosts=hosts2scan, arguments="-p"+ports2scan)


	def __actualiceTableHosts(self, hosts2scan): # example ip2scan=('192.168.1.50', '192.168.1.51', '192.168.1.52')
		# add new hosts
		macs_up = []
		for ip in self.nm.all_hosts():
			addresses = self.nm[ip]['addresses']    # addresses of the discovered host
			try:
				macs_up.append(addresses['mac'])
				mac = macs_up[-1]
				try:
					os = self.cf.convertDictionary2String(self.nm[ip]['osclass'])
				except:
					os = None
				self.__addUpHost(ip, mac, os) # if the host is at the db, it is added again to know the last time it was scanned
			except:
				mac = "NULL"    # occurs with our own host
		# add 'down' hosts
		self.__addDownHosts(macs_up, hosts2scan)

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

	# actualice puertos table and add to hosts table new hots up scanned
	def __actualiceTablePuertosAndHosts(self, portScanOption=0, ports2scan=0):
		# ports2scan: list
		# work with scanned ports
		if self.nm.all_hosts() != []: # some ports open, if all ports are closed then nm.all_hosts()=[] (empty)
			# work with each host with ports open
			print 'Open ports'
			for hostWithPorts in self.nm.all_hosts():
				# check info scanned
				[infoMac, mac, infoTCP, portsUp] = self.__checkScannedInfo(hostWithPorts)
				# add host to hosts table (new hosts can be discovered)
				self.__addUpHost(hostWithPorts, mac)
				# get id of the host (using mac) with we are working now
				id_hostWithPorts = self.db.retrieve_host_id (self.num_audit, self.num_rev, mac)
				# add last ID host ports. One time for each host ID
				self.__addLastIDhostPorts(hostWithPorts, id_hostWithPorts, mac)
				if infoMac != 1:
					print str(hostWithPorts) + " no mac info"
				if infoTCP == 1:
					# show scanned information
					self.__printPortsScan(hostWithPorts, portsUp, portScanOption)
					# add new information to puertos table
					self.__addNewPorts(id_hostWithPorts, portsUp, hostWithPorts, portScanOption)
					# add 'closed' ports
					self.__addClosedPorts(id_hostWithPorts, portsUp, portScanOption, ports2scan)
				else:
					print str(hostWithPorts) + " no ports info"
			# put down hosts at hosts table
			# self.__addDownHosts(macs_up, self.nm.all_hosts()) #Do not do it because not scanned ports do not mean the host is down
		else:
			print 'No ports'

	# check scan results
	def __checkScannedInfo(self, hostWithPorts):
		try: # if not port information is scanned, self.nm[hostWithPorts]['addresses']['mac'] and ports = self.nm[hostWithPorts]['tcp'].keys() generate an exception
			# mac of the host
			mac = self.nm[hostWithPorts]['addresses']['mac']
			informationMac = 1
		except:
			mac = None
			informationMac = -1
		try:
			ports = self.nm[hostWithPorts]['tcp'].keys()
			informationTCP = 1
		except:
			ports = None
			informationTCP = -1
		return [informationMac, mac, informationTCP, ports]

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

	def __addNewPorts(self, id_hostWithPorts, ports, hostWithPorts, portScanOption=0):
		# work with each port of the host
		for port in ports:
			# get port values
			portInformation = self.__getPortInformation(hostWithPorts, port) # portInformation = [portVersionInformation, portScriptInformation, portPortInformation]
			# add port
			# always add in order to know last scan time
			if portScanOption == 0:
				state = 'open'
			else:
				state = portInformation[2]
			self.db.add_port(state, id_hostWithPorts, port, portInformation[0], portInformation[1])

	def __getPortInformation(self, hostWithPorts, port):
		# sometimes the results have not all those values
		# version scan information
		try:
			product = "%s" %self.nm[hostWithPorts]['tcp'][port]['product']
		except:
			product = None
		try:
			version = "%s" %self.nm[hostWithPorts]['tcp'][port]['version']
		except:
			version = None
		try:
			name = "%s" %self.nm[hostWithPorts]['tcp'][port]['name']
		except:
			name = None
		try:
			extrainfo = "%s" %self.nm[hostWithPorts]['tcp'][port]['extrainfo']
		except:
			extrainfo = None
		portVersionInformation = 'product: %s \nversion: %s \nname: %s \nextrainfo: %s' %(product, version, name, extrainfo)
		# script scan information
		try:
			script = self.nm[hostWithPorts]['tcp'][port]['script'] # dictionary
			portScriptInformation = self.cf.convertDictionary2String(script)
		except:
			portScriptInformation = None
		# port scan information (state)
		# only at this option we check if state is open or closed when put the port open or closed because the other scan options only retrieve open ports
		try:
			portPortInformation = self.nm[hostWithPorts]['tcp'][port]['state'] # string
		except:
			portPortInformation = None

		return [portVersionInformation, portScriptInformation, portPortInformation]

	def __addClosedPorts(self, id_hostWithPorts, portsUp, portScanOption=0, portsScanned=0):
		# portScanned: list of int numbers as strings
		if portScanOption == 0:
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
			print color('rojo', 'Invalid syntax')

	def __ask4ports2search(self):
		ports2search = ""
		while ports2search == "":
			ports2search = raw_input('Type ports (no spaces): ')
		por2search_string = ports2search # example '20-22,80'
		ports2search_listOfStrings = self.cf.convertSring2ListWitchAllValues(ports2search) # example ['20', '21', '22, '80']
		return [por2search_string, ports2search_listOfStrings]


	def __printPortsScan(self, hostWithPorts, ports, portScanOption):
		if portScanOption == 0:
			# show scanned ports
			print str(hostWithPorts) + ' ' + str(ports)
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