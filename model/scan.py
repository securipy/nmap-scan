#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan"""

__author__ 		= "GoldraK & Roger Serentill"
__credits__ 	= "GoldraK & Roger Serentill"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com"
__status__ 		= "Development"

import sys, nmap
sys.path.append('model')
from database import Database
from nmapscan import NmapScan
from teco import color, style
from utility2 import CalcIP, IP2scan
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
		self.h2s = IP2scan()

	def select_audit(self):
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
		elif audit_action == '2':
			# Select existing audit
			all_audits = self.db.retrieve_audits()
			if len(all_audits) == 0:
				print color("rojo", "\nNo existing audits\n")
				self.select_audit()
			for num,audit in all_audits:
				print color('verde' , str(num)+". "+audit )
			number_audit = raw_input('Number audit: ')
			while number_audit == "":
				number_audit = raw_input('Number audit: ')
			self.num_audit = number_audit
			all_audits = dict((x,y) for x, y in all_audits)
			self.nom_audit = all_audits[int(number_audit)]
			self.select_revision()
		else:
			print color('rojo', '\nInvalid option\n')
			self.select_audit()

	def select_revision(self):
		if self.num_audit == None and self.nom_audit == None:
			print "Select audit before revison"
			self.select_audit()
		rev_action = raw_input(color('cyan', '1. New revision\n2. Existing revision\n')+'Select option: ')
		while rev_action == "":
			rev_action = raw_input(color('cyan', '1. New revision\n2. Existing revision\n')+'Select option: ')
		if rev_action == '1':
			# Add new revision
			new_rev = raw_input('Name revision: ')
			while new_rev == "":
				new_rev = raw_input('Name revision: ')
			if len(self.db.retrieve_revison_name(new_rev)) == 0:
				self.num_rev = self.db.add_revision(int(self.num_audit), new_rev)
				self.nom_rev = new_rev
		elif rev_action == '2':
			# Select existing revision
			all_revs = self.db.retrieve_revison_id(self.num_audit)
			if len(all_revs) == 0:
				print color("rojo", "\nNo existing revisions\n")
			for fecha, num, id_audit, rev in all_revs:
				print color('verde' , str(num)+". "+rev+" ("+str(fecha)+")")
			number_rev = raw_input('Number revision: ')
			while number_rev == "":
				number_rev = raw_input('Number revision: ')
			self.num_rev = number_rev
			all_revs = dict((y,z) for x,y, w, z in all_revs)
			self.nom_rev = all_revs[int(number_rev)]
		else:
			print color('rojo', '\nInvalid option\n')
			self.select_revision()

	def discovery(self):
		self.__check_audit_rev()
		host_scan = raw_input('Type an IP or range: ')
		while host_scan == "":
			host_scan = raw_input('Type an IP or range')
		# save ip to scan
		ip2scan=self.h2s.IP2scan(host_scan) # example ('192.168.1.50', '192.168.1.51', '192.168.1.52')
		# add last revison's hosts if is the first discovery for actual revision
		revision_with_values = self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev)
		if revision_with_values == -1:
			self.db.add_old_hosts (self.num_audit, self.num_rev)
		# scan
		self.nm.scan(hosts=host_scan, arguments='-n -sP -PE -PA 21,23,80,3389')
		# show ip of hosts up
		print 'hosts up: '+str(self.nm.all_hosts())
		# add new hosts
		macs_up = []
		for ip in self.nm.all_hosts():
			addresses = self.nm[ip]['addresses']    # addresses of the discovered host
			try:
				macs_up.append(addresses['mac'])
				host_in_db = self.db.retrieve_last_host(self.num_audit, self.num_rev, macs_up[-1]) # get db row by num_rev and mac, for this audit
				if host_in_db == -1: # host not in db
					self.db.add_host('up', self.num_rev, ip, macs_up[-1])
				else:
					host_scanned = [['up', ip, macs_up[-1]]]
					difference = self.db.compare_hosts(host_in_db, host_scanned)
					if difference == 1:
						self.db.add_host('up', self.num_rev, ip, macs_up[-1])
			except:
				mac = "NULL"    # occurs with our own host
		# add 'down' hosts
		id_hosts2putDown = self.db.retrieve_id_hosts2putDown(self.num_audit, self.num_rev, macs_up, ip2scan)
		if id_hosts2putDown != -1:
		 	for id_host in id_hosts2putDown:
				down_host = self.db.retrieve_host_by_id(id_host)
		 		os, status, id, rev, ip, date, mac = down_host[0]
		 		self.db.add_host('down', self.num_rev, ip, mac)

	def version(self):
		self.__check_audit_rev()
		# check if the discovery option was made for this revision
		discoveryDone= self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev) # check values at hosts table for this revision
		if discoveryDone == 1:
			# # add last revison's ports if is the first scan for actual revision
			# revision_with_values = self.db.check_tablePuertosValues4ThisRevision(self.num_audit, self.num_rev)
			# if revision_with_values == -1:
			# 	self.db.add_old_ports (self.num_audit, self.num_rev)
			# scan
			host_scan = raw_input('Type an IP or range (no spaces): ')
			while host_scan == "":
				host_scan = raw_input('Type an IP or range (no spaces):')
			# save ip to scan
			ip2scan=self.h2s.IP2scan(host_scan) # example ('192.168.1.50', '192.168.1.51', '192.168.1.52')
			# chek if the ip was scanned at 'discovery' option
			check_allIPAtHostTable = 1
			for ip in ip2scan:
				check_ipAtHostTable = self.db.check_ipInTableHosts(self.num_audit, self.num_rev, str(ip))
				if check_ipAtHostTable == -1:
					check_allIPAtHostTable = -1
			if check_allIPAtHostTable == 1:
				# scan
				print 'port scan started'
				self.nm.scan(hosts=host_scan, arguments="-sV")
				# work with scanned ports
				if self.nm.all_hosts() != []: # some ports up, if all ports are down then nm.all_hosts()=[] (empty)
					# work with each host with ports ups
					for hostWithPorts in self.nm.all_hosts():
						# get id of the host (using mac) with we are working now
						id_hostWithPorts = self.db.retrieve_host_id (self.num_audit, self.num_rev, self.nm[hostWithPorts]['addresses']['mac'])
						# add port's associated to this host (mac) but at the db are associated to an old id_host. Doing it only one time per id_host (at first time working with the id_host)
						# check if the actual id host has values
						check_idHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(id_hostWithPorts) # to add old port only one time
						# check if there are port values for this host but associated to a previous id_host, search the maximum previous id with port values
						previousHostID = self.db.retrieve_previous_host_id(self.num_audit, self.nm[hostWithPorts]['addresses']['mac'], id_hostWithPorts)
						check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
						while check_idPreviousHost_with_portsValues == -1 and previousHostID > 0:
							previousHostID = self.db.retrieve_previous_host_id(self.num_audit, self.nm[hostWithPorts]['addresses']['mac'], previousHostID)
							check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
						# add previous id_host ports to the actual id_host
						if check_idHost_with_portsValues == -1 and check_idPreviousHost_with_portsValues == 1:
							self.db.add_old_ports4host (previousHostID, id_hostWithPorts)
						# show scanned ports
						ports = self.nm[hostWithPorts]['tcp'].keys()
						print str(hostWithPorts) + ' ' + str(ports)
						# work with each port of the host
						for port in ports:
							# get port values
							product = self.nm[hostWithPorts]['tcp'][port]['product']
							version = self.nm[hostWithPorts]['tcp'][port]['name']
							extrainfo = self.nm[hostWithPorts]['tcp'][port]['extrainfo']
							info_version = '%s / %s / %s' %(product, version, extrainfo)
							# check if the port is at the db associated to the same id_host
							port_at_db = self.db.retrieve_port (id_hostWithPorts, port) # retrieve last port information introduced at db for actual host id
							if port_at_db != -1: # port at db
								# check if new (different) info for the port was scanned or state was different (if state was down because now is up)
								check_newInfo = self.db.compare_port(port_at_db, info_version)
								# new row with new information for the port
								if check_newInfo !=-1: # new info scanned
									self.db.add_port('up', id_hostWithPorts, port, info_version)
								# if port information is the same, no changes for port row
							# add port
							else: # port not in db
								self.db.add_port('up', id_hostWithPorts, port, info_version)
						# add 'down' ports
						# Ports at the db for a host (search by host id) that where 'up'
						id_ports2putDown = self.db.retrieve_id_ports2putDown(id_hostWithPorts, ports)
						if id_ports2putDown != -1: # at the db are ports associated to a host
							# work with each port
							for id_port in id_ports2putDown:
								#self.db.update_port_estadoANDfecha('down', id_hostWithPorts, old_port[0])
								down_port = self.db.retrieve_port_by_id (id_port)
								id_port, id_hosts_port, puerto_port, estado_port, version_port, fecha_port, scripts_port = down_port[0]
								self.db.add_port('down', id_hostWithPorts, puerto_port, version_port)
				else:
					print 'No ports'
			else:
				print 'No Discovery option was made for specified IP'
		else:
			print "Do 'Discovery' (option 3) before"

	def script(self):
		self.__check_audit_rev()
		# check if the discovery option was made for this revision
		discoveryDone= self.db.check_tableHostsValues4ThisRevision(self.num_audit, self.num_rev) # check values at hosts table for this revision
		if discoveryDone == 1:
			# scan
			host_scan = raw_input('Type an IP or range (no spaces): ')
			while host_scan == "":
				host_scan = raw_input('Type an IP or range (no spaces):')
			# save ip to scan
			ip2scan=self.h2s.IP2scan(host_scan) # example ('192.168.1.50', '192.168.1.51', '192.168.1.52')
			# chek if the ip was scanned at 'discovery' option
			check_allIPAtHostTable = 1
			for ip in ip2scan:
				check_ipAtHostTable = self.db.check_ipInTableHosts(self.num_audit, self.num_rev, str(ip))
				if check_ipAtHostTable == -1:
					check_allIPAtHostTable = -1
			if check_allIPAtHostTable == 1:
				# scan
				print 'port scan started'
				self.nm.scan(hosts=host_scan, arguments="-sV -sC")
				# work with scanned ports
				if self.nm.all_hosts() != []: # some ports up, if all ports are down then nm.all_hosts()=[] (empty)
					# work with each host with ports ups
					for hostWithPorts in self.nm.all_hosts():
						# get id of the host (using mac) with we are working now
						id_hostWithPorts = self.db.retrieve_host_id (self.num_audit, self.num_rev, self.nm[hostWithPorts]['addresses']['mac'])
						# add port's associated to this host (mac) but at the db are associated to an old id_host. Doing it only one time per id_host (at first time working with the id_host)
						# check if the actual id host has values
						check_idHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(id_hostWithPorts) # to add old port only one time
						# check if there are port values for this host but associated to a previous id_host, search the maximum previous id with port values
						previousHostID = self.db.retrieve_previous_host_id(self.num_audit, self.nm[hostWithPorts]['addresses']['mac'], id_hostWithPorts)
						check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
						while check_idPreviousHost_with_portsValues == -1 and previousHostID > 0:
							previousHostID = self.db.retrieve_previous_host_id(self.num_audit, self.nm[hostWithPorts]['addresses']['mac'], previousHostID)
							check_idPreviousHost_with_portsValues = self.db.check_tablePuertosValues4ThisHostID(previousHostID)
						# add previous id_host ports to the actual id_host
						if check_idHost_with_portsValues == -1 and check_idPreviousHost_with_portsValues == 1:
							self.db.add_old_ports4host (previousHostID, id_hostWithPorts)
						# show scanned ports
						ports = self.nm[hostWithPorts]['tcp'].keys()
						print str(hostWithPorts) + ' ' + str(ports)
						# work with each port of the host
						for port in ports:
							# check info avaliable for this port (some ports doesn't have 'script' information)
							port_information = self.nm[hostWithPorts]['tcp'][port].keys()
							if 'script' in port_information:
								# get port script value
								script = self.nm[hostWithPorts]['tcp'][port]['script']
								# check if the port is at the db associated to the same id_host
								port_at_db = self.db.retrieve_port (id_hostWithPorts, port) # retrieve last port information introduced at db for actual host id
								if port_at_db != -1: # port at db
									# check if new (different) info for the port was scanned or state was different (if state was down because now is up)
									check_newInfo = self.db.compare_portScript(port_at_db, script)
									# new row with new information for the port
									if check_newInfo !=-1: # new info scanned
										self.db.add_portScript('up', id_hostWithPorts, port, script)
									# if port information is the same, no changes for port row
								# add port
								else: # port not in db
									self.db.add_portScript('up', id_hostWithPorts, port, script)
						# # add 'down' ports
						# # Ports at the db for a host (search by host id) that where 'up'
						# id_ports2putDown = self.db.retrieve_id_ports2putDown(id_hostWithPorts, ports)
						# if id_ports2putDown != -1: # at the db are ports associated to a host
						# 	# work with each port
						# 	for id_port in id_ports2putDown:
						# 		#self.db.update_port_estadoANDfecha('down', id_hostWithPorts, old_port[0])
						# 		down_port = self.db.retrieve_port_by_id (id_port)
						# 		id_port, id_hosts_port, puerto_port, estado_port, version_port, fecha_port, scripts_port = down_port[0]
						# 		self.db.add_port('down', id_hostWithPorts, puerto_port, version_port)
				else:
					print 'No ports'
			else:
				print 'No Discovery option was made for specified IP'
		else:
			print "Do 'Discovery' (option 3) before"

	def puertos(self): # falta (actualizado 'versiones', 'puertos' no)
		self.__check_audit_rev()
		host_scan = raw_input('Type an IP or range: ')
		while host_scan == "":
			host_scan = raw_input('Type an IP or range')
		# # Ports
		self.nm.scan(hosts=host_scan, arguments="")
		for host in self.nm.all_hosts():
			puertos = self.nm[host]['tcp'].keys()
			old_ports = self.db.retrieve_ports(self.num_rev, self.nm[host]['addresses']['mac']) # example: old_ports = [(80,), (21,), (22,), (23,)]
			print str(host) + ' ' + str(puertos)
			id_host = self.db.retrieve_host_id (self.num_rev, self.nm[host]['addresses']['mac'])
			if id_host == -1:
				id_host = 'x'
			for port in puertos:
				check_port = self.db.retrieve_port (id_host, port)
				if check_port != -1:
					self.db.update_port_estado('up', id_host, port)
				else:
					self.db.add_port('up', id_host, port, 0)# falta, hacer esto bien
			if old_ports != -1:
				for old_port in old_ports:    # update state in case to work with an old revision
					if old_port[0] not in puertos:
						self.db.update_port_estado('down', id_host, old_port[0])

	def __check_audit_rev(self):
		if self.num_audit == None and self.nom_audit == None:
			print color('bcyan', "Select audit")
			self.select_audit()
		if self.num_rev == None and self.nom_rev == None:
			print color('bcyan', "Select revision")
			self.select_revision()

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
