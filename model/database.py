#!/usr/bin/python
#-*-coding:utf-8-*-

import sqlite3

class Database:

	def __init__(self):

		# Open the database file. If it doesn't exist, create it
		self.con = sqlite3.connect('modules/nmap-scan/model/brain.db')
		self.cur = self.con.cursor()

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
	def retrieve_audits(self):
		sql = "SELECT * FROM auditorias;"
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve audits by customer name, if doesn't exist, return -1
	def retrieve_audit_name(self, cname):
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

	# Retrieve revision by audit id
	def retrieve_revison_id(self, id_audit):
		sql = "SELECT * FROM revision WHERE id_auditorias = '%s';" % id_audit
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve revision by audit name
	def retrieve_revison_name(self, rev_name):
		sql = "SELECT * FROM revision WHERE revision = '%s';" % rev_name
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
	def add_host(self, state, id_rev, ip, mac):
		sql = "INSERT INTO hosts(estado, id_revision, ip, fecha, mac) VALUES ('%s','%s','%s',CURRENT_TIMESTAMP,'%s');" % (state, id_rev, ip, mac)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# Add port
	def add_port(self, state, id_host, port, info_version):
		sql = "INSERT INTO puertos(id_hosts, puerto, estado, version, fecha) VALUES ('%s','%s','%s','%s',CURRENT_TIMESTAMP);" % (id_host, port, state, info_version)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# Add port at script scan option
	def add_port(self, state, id_host, port, script):
		sql = "INSERT INTO puertos(id_hosts, puerto, estado, fecha, scripts) VALUES ('%s','%s','%s',CURRENT_TIMESTAMP,'%s');" % (id_host, port, state, script)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# add hosts form last revision
	def add_old_hosts(self, id_audit, id_rev): # id_rev[=]str
		last_revision = self.retrieve_last_revision4thisAudit(id_audit, id_rev)
		if int(last_revision) >= 1: # first revision has id 1 (before this, no revision with values)
			sql = "INSERT INTO hosts (estado, id_revision, ip, fecha, mac) SELECT estado, '%s', ip, fecha, mac FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev, last_revision, id_audit) # neccesary compare audit in order not to get values of another audit
			self.cur.execute(sql)
			self.con.commit()
			return self.cur.lastrowid

	# # add ports form last revision
	# def add_old_ports(self, id_audit, id_rev): # id_rev[=]str
	# 	last_revision = self.retrieve_last_revision4thisAudit(id_audit, id_rev)
	# 	if int(last_revision) >= 1: # first revision has id 1 (before this, no revision with values)
	# 		sql = "INSERT INTO puertos(id_hosts, puerto, estado, version, fecha) SELECT id_hosts, puerto, estado, version, fecha FROM puertos WHERE id_hosts IN (SELECT id FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s'));" % (last_revision, id_audit) # neccesary compare audit in order not to get values of another audit
	# 		self.cur.execute(sql)
	# 		self.con.commit()
	# 		return self.cur.lastrowid

	# add ports for the previous id host for a host
	def add_old_ports4host(self, id_previousHost, id_host):
		sql = "INSERT INTO puertos(id_hosts, puerto, estado, version, fecha) SELECT '%s', puerto, estado, version, fecha FROM puertos WHERE id_hosts = '%s';" % (id_host, id_previousHost)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	# retrieve last revision for this audit
	def retrieve_last_revision4thisAudit(self, id_audit, id_rev):
		sql = "SELECT MAX(id) FROM revision WHERE id < '%s' AND id_auditorias = '%s';" % (id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			last_revisionID = self.cur.fetchall()
			if last_revisionID != [(None,)]:
				return last_revisionID[0][0] # example [(1,)]
			else:
				return -1
		else:
			return -1

	# check if there are values at hosts table for this revision
	def check_tableHostsValues4ThisRevision(self, id_audit, id_rev): # id_rev is unique (primary key)
		sql = "SELECT MAX(id) FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			id_results = self.cur.fetchall()
			if str(id_results) == '[(None,)]': # at the table there is not values for this revision
				return -1
			else: # this revision has values at the table
				return 1
		else:
			return -1

	# check if an ip was scanned with discovery option
	def check_ipInTableHosts(self, id_audit, id_rev, ip): # id_rev is unique (primary key)
		# if len(ip)==1:
		# 	ip = ip+ip    # avoid tuple to end with coma
		# sql = "SELECT MAX(id) FROM hosts WHERE ip IN " + str(ip) +" AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (id_rev, id_audit)
		sql = "SELECT MAX(id) FROM hosts WHERE ip = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (ip, id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			exists = self.cur.fetchall()
			if str(exists) == '[(None,)]': # table hosts has not those ip
				return -1
			else: # ip at hosts table
				return 1
		else:
			return -1

	# # check if there are values at a puertos table for this revision
	# def check_tablePuertosValues4ThisRevision(self, id_audit, id_rev): # id_rev is unique (primary key)
	# 	sql = "SELECT MAX(id) FROM puertos WHERE id_hosts IN (SELECT id FROM hosts WHERE id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s'));" % (id_rev, id_audit)
	# 	if self.cur.execute(sql) > 0:
	# 		id_results = self.cur.fetchall()
	# 		if str(id_results) == '[(None,)]': # at the table there is not values for this revision
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
			if str(id_results) == '[(None,)]': # at the table puertos there is not values for this id host
				return -1
			else: # this id host has values at the table puertos
				return 1
		else:
			return -1


	# def update_host_estadoANDfecha(self, state, id_rev, mac):
	# 	sql = "UPDATE hosts SET estado = '%s', fecha = CURRENT_TIMESTAMP WHERE id_revision = '%s' and mac = '%s'" % (state, id_rev, mac)
	# 	self.cur.execute(sql)
	# 	self.con.commit()

	# def hosts_now_down(self, id_audit, id_rev): # M
	# 	sql = "select * from hosts where mac in (select mac from hosts where id_revision = (select id from revision where id in (select max(id) from revision where id_auditorias = '%s' and id != '%s'))) and mac not in (select mac from hosts where id_revision = '%s') AND id_revision=(select id from revision where id in (select max(id) from revision where id_auditorias = '%s' and id != '%s'))" % (id_audit, id_rev, id_rev, id_audit, id_rev)
	# 	if self.cur.execute(sql) > 0:
	# 		return self.cur.fetchall()
	# 	else:
	# 		return -1


	# Retrieve hosts that were up and now are down
	def retrieve_id_hosts2putDown(self, id_audit, id_rev, macs, ip2scan): # mac: macs of actual up hosts
		macs = tuple(macs) # necessary for the sql petition
		if len(macs)==1:
			macs = macs+macs    # avoid tuple to end with coma
		if len(ip2scan)==1:
			ip2scan = ip2scan+ip2scan
		# takes max id of the hosts with same mac (mac different than macs introduced) that are up at the db for this revision
		sql="SELECT id FROM hosts WHERE ip IN " + str(ip2scan) + " AND mac NOT IN " + str(macs) + "AND estado = 'up' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s') AND id IN (SELECT id FROM (SELECT id, COUNT(*) AS c FROM hosts GROUP BY mac HAVING c>=1));"  % (id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			id_hosts = self.cur.fetchall()
			if str(id_hosts) == '[(None,)]': # at the table there are no values
				return -1
			else: # this revision has values at the table
				return id_hosts # return self.cur.fetchall() returns []
		else:
			return -1

	# Retrieve id of ports that are up at the db for this host(used host id); get last row added
	def retrieve_id_ports2putDown(self, id_host, portsUp):
		portsUp = tuple(portsUp) # necessary for the sql petition
		if len(portsUp)==1:
			portsUp = portsUp+portsUp    # avoid tuple to end with coma
		sql = "SELECT id FROM puertos WHERE puerto NOT IN " + str(portsUp) + "AND estado = 'up' AND id_hosts = '%s' AND id IN (SELECT id FROM (SELECT id, COUNT(*) AS c FROM puertos GROUP BY puerto HAVING c>=1));"  % id_host
		if self.cur.execute(sql) > 0:
			id_ports = self.cur.fetchall()
			if str(id_ports) == '[(None,)]': # at the table there are no values
				return -1
			else: # this revision has values at the table
				return id_ports
		else:
			return -1

	# Retrieve host by id
	def retrieve_host_by_id(self, id_host):
		sql = "SELECT * FROM hosts WHERE id = '%s';" % id_host
		if self.cur.execute(sql) > 0:
			row_db = self.cur.fetchall()
			return row_db    # return self.cur.fetchall() returns []
		else:
			return -1

	# Retrieve port by id
	def retrieve_port_by_id(self, id_port):
		sql = "SELECT * FROM puertos WHERE id = '%s';" % id_port
		if self.cur.execute(sql) > 0:
			row_db = self.cur.fetchall()
			return row_db    # return self.cur.fetchall() returns []
		else:
			return -1

	# Retrieve hosts by ip (one or more)
	def retrieve_mac(self, id_rev, host):
		sql = "SELECT mac FROM hosts WHERE ip IN " + str(host) + "AND id_revision = '%s';" % id_rev
		if self.cur.execute(sql) > 0:
			mac = self.cur.fetchall()
			if str(mac)!='[(None,)]':
				return mac    # return self.cur.fetchall() returns []
			else:
				return -1
		else:
			return -1

	# Retrieve host by revision id and mac for this audit. Host with maximum id (last actualization)
	def retrieve_last_host(self, id_audit, id_rev, mac):
		sql = "SELECT * FROM hosts WHERE id = (SELECT MAX(id) FROM hosts WHERE (mac = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s')));" % (mac, id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			row_db = self.cur.fetchall()
			if row_db != []:
				return row_db
			else:
				return -1
		else:
			return -1

	# # Retrieve host id by revision id and mac for this audit. Host with maximum id (last actualization)
	# def retrieve_last_host_id(self, id_audit, id_rev, mac):
	# 	sql = "SELECT id FROM hosts WHERE id = (SELECT MAX(id) FROM hosts WHERE (mac = '%s' AND id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s')));" % (mac, id_rev, id_audit)
	# 	if self.cur.execute(sql) > 0:
	# 		id = self.cur.fetchall()
	# 		if id != '[(None,)]':
	# 			return id
	# 		else:
	# 			return -1
	# 	else:
	# 		return -1

	# Retrieve previous host ID associated to a mac for this audit (information can come from previous revision). Previous to the actual host ID
	def retrieve_previous_host_id(self, id_audit, mac, actualID):
		sql = "SELECT MAX(id) FROM hosts WHERE (id < '%s' AND mac = '%s' AND id_revision IN (SELECT id FROM revision WHERE id_auditorias = '%s'));" % (actualID, mac, id_audit)
		if self.cur.execute(sql) > 0:
			previousID = self.cur.fetchall()
			if str(previousID) != '[(None,)]':
				return previousID[0][0]  # example:[(7,)]
			else:
				return -1
		else:
			return -1

	# Retrieve id_host by audit, revision and ip from hosts table (more actual host at host table)
	def retrieve_host_id(self, id_audit, id_rev, mac):
		sql = "SELECT MAX(id) FROM hosts WHERE mac = '%s' and id_revision = (SELECT id FROM revision WHERE id = '%s' AND id_auditorias = '%s');" % (mac, id_rev, id_audit)
		if self.cur.execute(sql) > 0:
			host_id = self.cur.fetchall()
			if str(host_id) != '[(None,)]':
				return host_id[0][0]# example: id_hostWithPorts = [(20,)]
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

	# retrieve ports associated to a host id
	def retrieve_ports(self, id_host):
		sql = "SELECT puerto FROM puertos WHERE id_hosts = '%s';" % id_host
		if self.cur.execute(sql) > 0:
			puerto = self.cur.fetchall()
			if str(puerto) != '[(None,)]':
				return puerto
			else:
				return -1
		else:
			return -1

	# Add host info
	def add_infohost(self, id_host, port, state, version):
		sql = "INSERT INTO info_host(id_hosts, puerto, estado, version) VALUES (%s,%s,%s);"
		args = (id_host, port, state, version)
		self.cur.execute(sql, args)
		self.con.commit()
		return self.cur.lastrowid

	# Update port state
	def update_port_estadoANDfecha(self, state, id_host, port):
		sql = "UPDATE puertos SET estado = '%s', fecha = CURRENT_TIMESTAMP WHERE id_hosts = '%s' and puerto = '%s';" % (state, id_host, port)
		self.cur.execute(sql)
		self.con.commit()

	# compare actual host values with host values at db, returns -1 if all the info is the same
	def compare_hosts(self, host_db, host_scan):
		difference = -1
		# state
		if str(host_db[0][1]) != host_scan[0][0]:
			difference = 1
		# ip
		elif str(host_db[0][4]) != host_scan[0][1]:
			difference = 1
		# mac
		# not neccesary because host_db was search using host_scan's mac
		elif str(host_db[0][6]) != host_scan[0][2]:
			difference = 1
		return difference

	# compare actual port values with port values at db, returns -1 if all the info is the same
	def compare_port(self, port_db, port_info_scan):
		if str(port_db[0][3]) == 'down' or str(port_db[0][4]) != port_info_scan: # at the db the actual up port was down or has differrent version information
			return 1 # differences -> new line at the db for this port
		else:
			return -1 # no differences

	# compare actual port script value with port script value at db, returns -1 if all the info is the same
	def compare_port(self, port_db, port_script_scan):
		if str(port_db[0][3]) == 'down' or str(port_db[0][6]) != port_script_scan: # at the db the actual up port was down or has differrent version information
			return 1 # differences -> new line at the db for this port
		else:
			return -1 # no differences