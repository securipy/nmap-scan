#!/usr/bin/python
#-*-coding:utf-8-*-

"""This script works directly with the database"""

import sqlite3
from utility2 import ChangeFormat

class Database:

	def __init__(self):
		# Open the database file. If it doesn't exist, create it
		self.con = sqlite3.connect('modules/nmap-scan/model/brain.db')
		self.cur = self.con.cursor()
		self.cf = ChangeFormat()

	def __del__(self):
		# Commit and close the connection
		self.con.commit()
		self.con.close()

	# Add new audit by customer name, return the given ID to this audit
	def add_audit(self, cname):
		sql = "INSERT INTO auditorias(nombre_cliente) VALUES ('%s');" % cname
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# Retrieve all audits
	def retrieve_auditsAllInfo(self):
		sql = "SELECT * FROM auditorias;"
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve audits by customer name, if doesn't exist, return -1
	def retrieve_auditAllInfoByName(self, cname):
		sql = "SELECT * FROM auditorias WHERE nombre_cliente = '%s';" % cname
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve audits by id, if doesn't exist, return -1
	def retrieve_audit(self, id_audit):
		sql = "SELECT * FROM auditorias WHERE id = '%s';" % id_audit
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve audit name by id, if doesn't exist, return -1
	def retrieve_auditName(self, id_audit):
		sql = "SELECT nombre_cliente FROM auditorias WHERE id = '%s';" % id_audit
		if self.cur.execute(sql) > 0:
			nombre_cliente = self.cf.eliminateTuplesAtList(self.cur.fetchall())  # example self.cur.tefchall() = [(u'exampleName',)] -> self.cur.tefchall()[0][0] = u'exampleName'
			return nombre_cliente
		else:
			return -1

	# Add new revision passing the audit id and the revision number as arguments. Returns the given id to the record
	def add_revision(self, id_audit, rev_name):
		sql = "INSERT INTO revision(fecha, id_auditorias, revision) VALUES (CURRENT_TIMESTAMP,'%s','%s');" % ((id_audit, rev_name))
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# Retrieve all revisions
	def retrieve_revisions(self):
		sql = "SELECT * FROM revision;"
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve all information in revision table by audit id
	def retrieve_revisonAllInfoByAuditID(self, id_audit):
		sql = "SELECT * FROM revision WHERE id_auditorias = '%s';" % id_audit
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve revision by audit name
	def retrieve_revisionAllInfoByName(self, rev_name, id_audit):
		sql = "SELECT * FROM revision WHERE revision = '%s' AND id_auditorias = '%s';" % (rev_name, id_audit)
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve revision by date
	def retrieve_revison(self, date):
		sql = "SELECT * FROM revision WHERE fecha = '%s';" % date
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve revision name by id, if doesn't exist, return -1
	def retrieve_revisionName(self, id_audit, id_rev):
		sql = "SELECT revision FROM revision WHERE id = '%s' AND id_auditorias = '%s';" % (id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			revision = self.cf.eliminateTuplesAtList(self.cur.fetchall()) # example self.cur.tefchall() = [(u'exampleName',)] -> self.cur.tefchall()[0][0] = u'exampleName'
			return revision
		else:
			return -1

	# # Retrieve max revision with hosts
	# def retrieve_revison_max(self, id_audit, id_rev):
	# 	sql = "SELECT MAX(id_revision) FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE (id_auditorias ='%s' AND id = (SELECT max(id_revision) FROM hosts)))" % id_audit # be sure the selection is in our audit
	# 	# if self.cur.execute(sql) > 0:
	# 	# 	return self.cur.fetchall()
	# 	# else:
	# 	# 	return -1
	# 	max_revision = self.cur.execute(sql)
	# 	if max_revision <= 0 or max_revision == None:
	# 		return -1
	# 	else:
	# 		return self.cur.fetchall()


	# Add new host, retun the id given to the record
	def add_host(self, state, id_rev, ip, mac, os, name):
		sql = "INSERT INTO hosts(OS, estado, id_revision, ip, fecha, mac, name) VALUES ('%s', '%s','%s','%s',CURRENT_TIMESTAMP,'%s','%s');" % (os, state, id_rev, ip, mac, name)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# Add port
	def add_port(self, state, id_host, port, info_version, script):
		sql = "INSERT INTO puertos(id_hosts, puerto, estado, version, fecha, scripts) VALUES ('%s','%s','%s','%s',CURRENT_TIMESTAMP,'%s');" % (id_host, port, state, info_version, script)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# # Add port at script scan option
	# def add_port(self, state, id_host, port, script):
	# 	sql = "INSERT INTO puertos(id_hosts, puerto, estado, fecha, scripts) VALUES ('%s','%s','%s',CURRENT_TIMESTAMP,'%s');" % (id_host, port, state, script)
	# 	self.cur.execute(sql)
	# 	self.con.commit()
	# 	return self.cur.lastrowid

	# add hosts from last revision
	def add_old_hosts(self, id_audit, id_rev_actual): # id_rev_actual[=]str
		last_revision = self.retrieve_last_revision4thisAudit(id_audit, id_rev_actual)
		if int(last_revision) >= 1: # first revision has id 1 (before this, no revision with values)
			sql = "INSERT INTO hosts (OS, estado, id_revision, ip, fecha, mac, name) SELECT OS, estado, '%s', ip, fecha, mac, name FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev_actual, last_revision, id_audit) # necessary compare audit in order not to get values of another audit
			self.cur.execute(sql)
			self.con.commit()
			return self.cur.lastrowid

	# # add ports form last revision
	# def add_old_ports(self, id_audit, id_rev): # id_rev[=]str
	# 	last_revision = self.retrieve_last_revision4thisAudit(id_audit, id_rev)
	# 	if int(last_revision) >= 1: # first revision has id 1 (before this, no revision with values)
	# 		sql = "INSERT INTO puertos(id_hosts, puerto, estado, version, fecha) SELECT id_hosts, puerto, estado, version, fecha FROM puertos WHERE id_hosts IN (SELECT id FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s'));" % (last_revision, id_audit) # necessary compare audit in order not to get values of another audit
	# 		self.cur.execute(sql)
	# 		self.con.commit()
	# 		return self.cur.lastrowid

	# add ports for the previous id host for a host
	def add_old_ports4host(self, id_previousHost, id_host):
		sql = "INSERT INTO puertos(id_hosts, puerto, estado, version, fecha, scripts) SELECT '%s', puerto, estado, version, fecha, scripts FROM puertos WHERE id_hosts = '%s';" % (id_host, id_previousHost)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# retrieve last revision for this audit
	def retrieve_last_revision4thisAudit(self, id_audit, id_rev):
		sql = "SELECT MAX(id) FROM revision WHERE id < '%s' AND id_auditorias = '%s';" % (id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			last_revisionID = self.cur.fetchall()
			if last_revisionID != [(None,)]:
				last_revisionID = self.cf.eliminateTuplesAtList(last_revisionID) # example [(1,)] -> 1
				return last_revisionID
			else:
				return -1
		else:
			return -1

	# check if there are values at hosts table for this revision
	def check_tableHostsValues4ThisRevision(self, id_audit, id_rev): # id_rev is unique (primary key)
		sql = "SELECT MAX(id) FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			id_results = self.cur.fetchall()
			if id_results == [(None,)]: # at the table there is not values for this revision
				return -1
			else: # this revision has values at the table
				return 1
		else:
			return -1

	# # check if an ip was scanned with discovery option
	# # ip: tuple
	# def check_ipInTableHosts(self, id_audit, id_rev, ip): # id_rev is unique (primary key)
	# 	# if len(ip)==1:
	# 	# 	ip = ip+ip    # avoid tuple to end with coma
	# 	# sql = "SELECT MAX(id) FROM hosts WHERE ip IN " + str(ip) +" AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev, id_audit)
	# 	sql = "SELECT MAX(id) FROM hosts WHERE ip = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (ip, id_rev, id_audit)
	# 	if self.cur.execute(sql) > 0:
	# 		exists = self.cur.fetchall()
	# 		if exists == [(None,)]: # (verify) table hosts has not those ip
	# 			return -1
	# 		else: # ip at hosts table
	# 			return 1
	# 	else:
	# 		return -1

	# # check if there are values at a puertos table for this revision
	# def check_tablePuertosValues4ThisRevision(self, id_audit, id_rev): # id_rev is unique (primary key)
	# 	sql = "SELECT MAX(id) FROM puertos WHERE id_hosts IN (SELECT id FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s'));" % (id_rev, id_audit)
	# 	if self.cur.execute(sql) > 0:
	# 		id_results = self.cur.fetchall()
	# 		if id_results == [(None,)]: # at the table there is not values for this revision
	# 			return -1
	# 		else: # this revision has values at the table
	# 			return 1
	# 	else:
	# 		return -1

	# check if the id_host has ports values
	def check_tablePuertosValues4ThisHostID(self, id_host):
		sql = "SELECT MAX(id) FROM puertos WHERE id_hosts = '%s';" % id_host
		if self.cur.execute(sql) > 0:
			id_results = self.cur.fetchall()
			if id_results == [(None,)]: # at the table puertos there is not values for this id host
				return -1
			else: # this id host has values at the table puertos
				return 1
		else:
			return -1

	# check if a port is at db for this revision by retrieving id
	def check_portAtDB(self, id_audit, id_rev, port):
		sql = "SELECT id FROM puertos WHERE puerto = '%s' AND id_hosts IN (SELECT id FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s'));" % (port, id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			id = self.cur.fetchall()
			if id != []:
				return 1
			else:
				return -1
		else:
			return -1


	# def update_host_estadoANDfecha(self, state, id_rev, mac):
	# 	sql = "UPDATE hosts SET estado = '%s', fecha = CURRENT_TIMESTAMP WHERE id_revision = '%s' AND mac = '%s'" % (state, id_rev, mac)
	# 	self.cur.execute(sql)
	# 	self.con.commit()

	# def hosts_now_down(self, id_audit, id_rev): # M
	# 	sql = "select * from hosts where mac IN (select mac from hosts where id_revision = (select id from revision where id IN (select max(id) from revision where id_auditorias = '%s' AND id != '%s'))) AND mac not IN (select mac from hosts where id_revision = '%s') AND id_revision=(select id from revision where id IN (select max(id) from revision where id_auditorias = '%s' AND id != '%s'))" % (id_audit, id_rev, id_rev, id_audit, id_rev)
	# 	if self.cur.execute(sql) > 0:
	# 		return self.cur.fetchall()
	# 	else:
	# 		return -1


	# Retrieve hosts (mac) that were up but now are down and it's IP was scanned
	def retrieve_id_hosts2putDown(self, id_audit, id_rev, macsUp, hostsIPup, hosts2scan): # mac: macsUp of actual up hosts
		# macsUp: list
		# hosts2scan: tuple
		# hostsIPup: list
		macsUp = tuple(macsUp) # necessary for the sql petition
		hostsIPup = tuple(hostsIPup) # necessary for the sql petition
		if len(macsUp) == 1:
			macsUp = macsUp+macsUp # avoid tuple to end with coma
		if len(hosts2scan) == 1:
			hosts2scan = hosts2scan+hosts2scan
		if len(hostsIPup) == 1:
			hostsIPup = hostsIPup+hostsIPup
		# takes max id of the hosts with same mac (mac different than macsUp introduced) that are up at the db for this revision
		sql="SELECT id FROM hosts WHERE ip IN " + str(hosts2scan) + " AND (ip NOT IN " + str(hostsIPup) + " OR mac NOT IN " + str(macsUp) + ") AND estado = 'up' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s') AND (id IN (SELECT id FROM (SELECT id, COUNT(*) AS c FROM hosts GROUP BY mac HAVING c>=1)) OR id IN (SELECT id FROM (SELECT id, COUNT(*) AS c FROM hosts GROUP BY ip HAVING c>=1)) );"  % (id_rev, id_audit) # COUNT... -> not add again a row as down if the last state is down
		if self.cur.execute(sql) > 0:
			id_hosts = self.cur.fetchall()
			if id_hosts == []: # at the table there are no values
				return -1
			else: # this revision has values at the table
				return id_hosts # return self.cur.fetchall() returns []
		else:
			return -1

	# Retrieve id of ports that are open at the db for this id_host but are not scanned as ports open; get last row added
	# def retrieve_id_ports2putClosed(self, id_host, portsScannedAsUp):
	# 	portsScannedAsUp = tuple(portsScannedAsUp) # necessary a tuple for the sql petition
	# 	if len(portsScannedAsUp)==1:
	# 		portsScannedAsUp = portsScannedAsUp+portsScannedAsUp    # avoid tuple to end with coma
	# 	sql = "SELECT id FROM puertos WHERE puerto NOT IN " + str(portsScannedAsUp) + " AND estado = 'open' AND id_hosts = '%s' AND id IN (SELECT id FROM (SELECT id, COUNT(*) AS c FROM puertos GROUP BY puerto HAVING c>=1));"  % id_host
	# 	if self.cur.execute(sql) > 0:
	# 		id_ports = self.cur.fetchall()
	# 		if id_ports != []: # this revision has values at the table
	# 			return id_ports
	# 		else: # at the table there are no values
	# 			return -1
	# 	else:
	# 		return -1
	def retrieve_id_ports2putClosed(self, lastPortsID, portsScannedAsUp):
		# ouput: list of one or more strings
		portsScannedAsUp = tuple(portsScannedAsUp)  # necessary a tuple for the sql petition
		if len(portsScannedAsUp) == 1:
			portsScannedAsUp = portsScannedAsUp + portsScannedAsUp  # avoid tuple to end with coma
		sql = "SELECT id FROM puertos WHERE id IN " + str(lastPortsID) + " AND puerto NOT IN " + str(portsScannedAsUp) + " AND estado = 'open' "
		if self.cur.execute(sql) > 0:
			id_ports = self.cur.fetchall()
			if id_ports != []:  # this revision has values at the table
				id_ports = self.cf.eliminateTuplesAtList(id_ports, 1)
				return id_ports
			else:  # at the table there are no values
				return -1
		else:
			return -1

	# Retrieve id of ports that are open at the db for this id_host, we said to scan them but are not scanned as ports open; get last row added
	def retrieve_id_ports2putClosedPortOption(self, id_host, portsScannedAsUp, portsScanned):
		# portsScanned: list
		portsScannedAsUp = tuple(portsScannedAsUp) # necessary a tuple for the sql petition
		if len(portsScannedAsUp)==1:
			portsScannedAsUp = portsScannedAsUp+portsScannedAsUp    # avoid tuple to end with coma
		portsScanned = tuple(portsScanned) # necessary a tuple for the sql petition
		if len(portsScanned)==1:
			portsScanned = portsScanned+portsScanned    # avoid tuple to end with coma
		sql = "SELECT id FROM puertos WHERE puerto IN " + str(portsScanned) + " AND puerto NOT IN " + str(portsScannedAsUp) + " AND estado = 'open' AND id_hosts = '%s' AND id IN (SELECT id FROM (SELECT id, COUNT(*) AS c FROM puertos GROUP BY puerto HAVING c>=1));"  % id_host
		if self.cur.execute(sql) > 0:
			id_ports = self.cur.fetchall()
			if id_ports != []: # this revision has values at the table
				return id_ports
			else: # at the table there are no values
				return -1
		else:
			return -1

	# Retrieve all host information by host id
	def retrieve_hostAllInfo_byID(self, id_host):
		sql = "SELECT * FROM hosts WHERE id = '%s';" % id_host
		if self.cur.execute(sql) > 0:
			row_db = self.cur.fetchall() # list  of tuple of strigs, example [(u'None', u'up', 1, 1, u'192.168.1.1', u'2016-04-05 17:59:40', u'xx:xx:xx:xx:xx:xx')]
			if row_db != []:
				return row_db[0] # tuple of strings, example (u'None', u'up', 1, 1, u'192.168.1.1', u'2016-04-05 17:59:40', u'xx:xx:xx:xx:xx:xx')
				# return self.cur.fetchall() returns []
			else:
				return -1
		else:
			return -1

	# Retrieve hosts ip of the indicated revision
	def retrieve_hostsIP_byRevision(self, id_audit, id_rev):
		# use all hosts scanned, if now are down too in order to use all the information saved
		sql = "SELECT DISTINCT ip FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev, id_audit)
		# distinct: avoid repeated ip
		if self.cur.execute(sql) > 0:
			hosts = self.cur.fetchall()
			if hosts != []:
				for i in range(len(hosts)): # example: hosts=[(u'192.168.1.1',), (u'192.168.1.200',), (u'192.168.1.33',)]
					hosts[i] = str(hosts[i][0])
				return hosts  # type list # return self.cur.fetchall() returns []
			else:
				return -1
		else:
			return -1

	# Retrieve hosts ip and name of the indicated revision with maximum id for each ip
	def retrieve_hostsIDipAndNames_byRevision(self, id_audit, id_rev):
		# get last information added to the database
		sql = "SELECT id, ip, name FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s') GROUP BY ip" % (id_rev, id_audit)
		# group by: select last added information grouped by the indicated field. Must be at the end of the query
		if self.cur.execute(sql) > 0:
			hostsIDipAndNames = self.cur.fetchall() # example: [(8, u'192.168.1.1', u'None'), (9, u'192.168.1.34', u'None'), (10, u'192.168.1.37', u'None')]
			if hostsIDipAndNames != []:
				return hostsIDipAndNames  # type list # return self.cur.fetchall() returns []
			else:
				return -1
		else:
			return -1

	# Retrieve hosts mac with the indicated host IP
	def retrieve_hostsMac_byIP(self, id_audit, id_rev, ip):
		sql = "SELECT DISTINCT mac FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s') AND ip = '%s';" % (id_rev, id_audit, ip)
		# distinct: avoid repeated ip
		if self.cur.execute(sql) > 0:
			hostsMac = self.cur.fetchall() # list of tuples, example: hostsMac=[(u'xx:xx:xx:xx:xx:xx',), (u'yy:yy:yy:yy:yy:yy',), (u'zz:zz:zz:zz:zz:zz',)]
			if hostsMac != []:
				for i in range(len(hostsMac)):
					hostsMac[i] = str(hostsMac[i][0])
				return hostsMac  # type list # return self.cur.fetchall() returns []. # list of strings, example:  ['xx:xx:xx:xx:xx:xx', 'yy:yy:yy:yy:yy:yy', 'zz:zz:zz:zz:zz:zz']
			else:
				return -1
		else:
			return -1

	# # Retrieve host by revision id and mac for this audit. Host with maximum id (last actualization)
	# def retrieve_last_host(self, id_audit, id_rev, mac):
	# 	sql = "SELECT * FROM hosts WHERE id = (SELECT MAX(id) FROM hosts WHERE (mac = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s')));" % (mac, id_rev, id_audit)
	# 	if self.cur.execute(sql) > 0:
	# 		row_db = self.cur.fetchall()
	# 		if row_db != []:
	# 			return row_db
	# 		else:
	# 			return -1
	# 	else:
	# 		return -1

	# # Retrieve host id by revision id and mac for this audit. Host with maximum id (last actualization)
	# def retrieve_last_host_id(self, id_audit, id_rev, mac):
	# 	sql = "SELECT id FROM hosts WHERE id = (SELECT MAX(id) FROM hosts WHERE (mac = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s')));" % (mac, id_rev, id_audit)
	# 	if self.cur.execute(sql) > 0:
	# 		id = self.cur.fetchall()
	# 		if id != [(None,)]:
	# 			return id
	# 		else:
	# 			return -1
	# 	else:
	# 		return -1

	# Retrieve previous host ID associated to a mac for this audit (information can come from previous revision). Previous to the actual host ID
	def retrieve_hostPreviousID(self, id_audit, mac, actualID):
		sql = "SELECT MAX(id) FROM hosts WHERE (id < '%s' AND mac = '%s' AND id_revision IN (SELECT id FROM revision WHERE id_auditorias = '%s'));" % (actualID, mac, id_audit)
		if self.cur.execute(sql) > 0:
			previousID = self.cur.fetchall()
			if previousID != [(None,)]:
				previousID = self.cf.eliminateTuplesAtList(previousID) # example:[(7,)] -> 7
				return previousID
			else:
				return -1
		else:
			return -1

	# Retrieve last id_host by audit, revision, mac and ip from hosts table (more actual host at host table)
	def retrieve_hostID_withIP(self, id_audit, id_rev, mac, ip):
		sql = "SELECT MAX(id) FROM hosts WHERE mac = '%s' AND ip = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (mac, ip, id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			host_id = self.cur.fetchall()
			if host_id != [(None,)]:
				host_id = self.cf.eliminateTuplesAtList(host_id) # example: id_hostWithPorts = [(20,)] -> 20
				return host_id
			else:
				return -1
		else:
			return -1

	# Retrieve hostname by host ID
	def retrieve_hostName_byHostID(self, id_host):
		sql = "SELECT name FROM hosts WHERE id = '%s'" %id_host
		if self.cur.execute(sql) > 0:
			host_name = self.cur.fetchall()
			if host_name != [('None',)] and host_name != []:
				return host_name[0][0] # example: [(u'moli-mol.cuenca.es',)]
		return -1	# host indicated with ID has not name

	# Retrieve all port information by port id
	def retrieve_portAllInfo_byPortID(self, id_port):
		sql = "SELECT * FROM puertos WHERE id = '%s';" % id_port
		if self.cur.execute(sql) > 0:
			row_db = self.cur.fetchall() # list  of tuple of strigs, example [(10, 5, 80, u'open', u'product:  \nversion:  \nname: tcpwrapped \nextrainfo: ', u'2016-04-05 23:17:51', u'None')]
			if row_db != []:
				return row_db[0]  # tuple of strings, example (10, 5, 80, u'open', u'product:  \nversion:  \nname: tcpwrapped \nextrainfo: ', u'2016-04-05 23:17:51', u'None')
				# return self.cur.fetchall() returns []
			else:
				return -1
		else:
			return -1

	# retrieve all port information if it is in db, if the same port appears more than one time at the db at the same revision, it works with the latest input
	def retrieve_port(self, id_host, port):
		sql = "SELECT * FROM puertos WHERE id = (SELECT MAX(id) FROM puertos WHERE puerto = '%s' AND id_hosts = '%s');" % (port, id_host)
		if self.cur.execute(sql) > 0:
			row_db = self.cur.fetchall()
			if row_db != []:
				return row_db
			else:
				return -1
		else:
			return -1

	# retrieve ports ID if they are open ports for ports id
	def retrieve_portsOpenID_byPortID(self, portsID):
		if len(portsID)==1:
			portsID = portsID+portsID    # avoid tuple to end with coma
		sql = "SELECT id FROM puertos WHERE id IN " + str(portsID) + " AND estado = 'open';"
		# distinct: avoid repeated information
		if self.cur.execute(sql) > 0:
			puertos = self.cur.fetchall()  # list of tuples with an integer. Example [(10,), (11,), (12,), (13,)]
			if puertos != []:
				return puertos
			else:
				return -1
		else:
			return -1

	# retrieve ports associated to a host id
	def retrieve_ports(self, id_host):
		sql = "SELECT DISTINCT puerto FROM puertos WHERE id_hosts = '%s';" % id_host
		# distinct: avoid repeated information
		if self.cur.execute(sql) > 0:
			puertos = self.cur.fetchall() # list of tuples with an integer. Example [(80,), (21,), (22,), (23,)]
			if puertos != []:
				return puertos
			else:
				return -1
		else:
			return -1

	# retrieve port number by port id
	def retrieve_portNumber_byPortsID(self, id_port):
		# id_port: tuple
		if len(id_port) == 1:
			id_port = id_port + id_port  # avoid tuple to end with coma
		sql = "SELECT puerto FROM puertos WHERE id IN " + str(id_port)
		if self.cur.execute(sql) > 0:
			puertos = self.cur.fetchall()
			if puertos != []:
				return puertos  # list of tuples. Example [(80,), (21,), (22,), (23,)]
			else:
				return -1
		else:
			return -1

	# retrieve id of the hosts with the port indicated. Hosts have to be up
	def retrieve_idOfHostsUpWithAPort (self, port):
		sql = "SELECT id FROM hosts WHERE estado = 'up' AND id IN (SELECT DISTINCT id_hosts FROM puertos WHERE puerto = '%s');" %port
		# distinct: avoid repeated values
		if self.cur.execute(sql) > 0:
			id_hosts = self.cur.fetchall() # lists of tuples, exaple: [(13,), (14,)]
			if id_hosts != []:
				id_hosts = self.cf.eliminateTuplesAtList(id_hosts) # example [13, 14]
				return id_hosts
			else:
				return -1
		else:
			return -1

	# Get last id of a port for a host. Example: for the same host a port is first open and at the end closed (different rows), with this function we only work with last state, closed in this example
	def retrieve_portLastID_byHostIDandPort (self, id_host, port):
		sql = "SELECT MAX(id) FROM puertos WHERE id_hosts='%s' AND puerto = '%s';" %(id_host, port)
		if self.cur.execute(sql) > 0:
			id_port = self.cur.fetchall() # lists of one tuple, example: [(18,)]
			if id_port != [(None,)]:
				id_port = self.cf.eliminateTuplesAtList(id_port) # int, example: 18
				return id_port
			else:
				return -1
		else:
			return -1

	# Retrieve host ip with port indicated open
	def retrieve_hostIP_byPortID(self, id_audit, id_rev, id_port):
		sql = "SELECT DISTINCT ip FROM hosts WHERE id IN (SELECT id_hosts FROM puertos WHERE id = '%s' AND estado = 'open') AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_port, id_rev, id_audit)
		# distinct: avoid repeated values
		if self.cur.execute(sql) > 0:
			host_ip = self.cur.fetchall()
			if host_ip != []:
				host_ip = self.cf.eliminateTuplesAtList(host_ip) # example: [(u'192.168.1.5',)] -> u'192.168.1.5'
				return host_ip
			else:
				return -1
		else:
			return -1

	# # Add host info
	# def add_infohost(self, id_host, port, state, version, name):
	# 	sql = "INSERT INTO info_host(id_hosts, puerto, estado, version, name) VALUES (%s,%s,%s,%s);"
	# 	args = (id_host, port, state, version, name)
	# 	self.cur.execute(sql, args)
	# 	self.con.commit()
	# 	return self.cur.lastrowid

	# Update port state
	def update_port_estadoANDfecha(self, state, id_host, port):
		sql = "UPDATE puertos SET estado = '%s', fecha = CURRENT_TIMESTAMP WHERE id_hosts = '%s' AND puerto = '%s';" % (state, id_host, port)
		self.cur.execute(sql)
		self.con.commit()

	# update host name
	def update_hostName_byID(self, id_host, newName):
		sql = "UPDATE hosts SET name = '%s' WHERE id = '%s'" % (newName, id_host)
		self.cur.execute(sql)
		self.con.commit()

	# # compare actual host values with host values at db, returns -1 if all the info is the same
	# def compare_hosts(self, host_db, host_scan):
	# 	difference = -1
	# 	# state
	# 	if str(host_db[0][1]) != host_scan[0][0]:
	# 		difference = 1
	# 	# ip
	# 	elif str(host_db[0][4]) != host_scan[0][1]:
	# 		difference = 1
	# 	# mac
	# 	# not necessary because host_db was search using host_scan's mac
	# 	elif str(host_db[0][6]) != host_scan[0][2]:
	# 		difference = 1
	# 	return difference

	# compare actual port values with port values at db, returns -1 if all the info is the same
	def compare_port(self, port_db, port_info_scan):
		if str(port_db[0][3]) == 'closed' or str(port_db[0][4]) != port_info_scan: # at the db the actual open port was closed or has differrent version information
			return 1 # differences -> new line at the db for this port
		else:
			return -1 # no differences

	# compare actual port script value with port script value at db, returns -1 if all the info is the same
	def compare_port(self, port_db, port_script_scan):
		if str(port_db[0][3]) == 'closed' or str(port_db[0][6]) != port_script_scan: # at the db the actual open port was closed or has differrent version information
			return 1 # differences -> new line at the db for this port
		else:
			return -1 # no differences