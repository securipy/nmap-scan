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

	# Retrieve revision by audit nmae
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

	# Add new host, retun the id given to the record
	def add_host(self, state, id_rev, ip, mac):
		sql = "INSERT INTO hosts(estado, id_revision, ip, fecha, mac) VALUES ('%s','%s','%s',CURRENT_TIMESTAMP,'%s');" % (state, id_rev, ip, mac)
		self.cur.execute(sql)
		self.con.commit()
		return self.cur.lastrowid

	def hosts_now_down(self, id_audit, id_rev):
		sql = "select * from hosts where mac in (select mac from hosts where id_revision = (select id from revision where id in (select max(id) from revision where id_auditorias = '%s' and id != '%s'))) and mac not in (select mac from hosts where id_revision = '%s') AND id_revision=(select id from revision where id in (select max(id) from revision where id_auditorias = '%s' and id != '%s'))" % (id_audit, id_rev, id_rev, id_audit, id_rev)
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve host by mac
	def retrieve_host(self, mac):
		sql = "SELECT * FROM hosts WHERE mac = %s;" % mac
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1
	
	# Retrieve host by revision id
	def retrieve_host(self, id_rev):
		sql = "SELECT * FROM hosts WHERE id_revision = %s;" % id_rev
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Add host info
	def add_infohost(self, id_host, port, state, version):
		sql = "INSERT INTO info_host(id_hosts, puerto, estado, version) VALUES (%s,%s,%s);"
		args = (id_host, port, state, version)
		self.cur.execute(sql, args)
		self.con.commit()
		return self.cur.lastrowid