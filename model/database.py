#!/usr/bin/python
#-*-coding:utf-8-*-

import sqlite3

class Database:

	def __init__(self):

		# Open the database file. If it doesn't exist, create it
		self.con = sqlite3.connect('brain.db')
		self.cur = self.con.cursor()

	def __del__(self):
		# Commit and close the connection
		self.con.commit()
		self.con.close()

	# Add new audit by customer name, return the given ID to this audit
	def add_audit(self, cname):
		sql = "INSERT INTO auditorias(nombre_cliente) VALUES (%s);" % cname
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
	def retrieve_audit(self, cname):
		sql = "SELECT * FROM auditorias WHERE nombre_cliente = %s;" % cname
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve audits by id, if doesn't exist, return -1
	def retrieve_audit(self, id_audit):
		sql = "SELECT * FROM auditorias WHERE id = %s;" % id_audit
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Add new revision passing the audit id and the revision number as arguments. Returns the given id to the record
	def add_revision(self, id_audit, rev_num):
		sql = "INSERT INTO revision(fecha, id_auditorias, revision) VALUES (CURRENT_TIMESTAMP,%s,%s);"
		args = (id_audit, rev_num)
		self.cur.execute(sql, args)
		self.con.commit()
		return self.cur.lastrowid

	# Retrieve revision by audit id
	def retrieve_revison(self, id_audit):
		sql = "SELECT * FROM revision WHERE id_auditorias = %s;" % id_audit
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Retrieve revision by date
	def retrieve_revison(self, date):
		sql = "SELECT * FROM revision WHERE fecha = %s;" % date
		if self.cur.execute(sql) > 0:
			return self.cur.fetchall()
		else:
			return -1

	# Add new host, retun the id given to the record
	def add_host(self, os, state, id_rev, ip, date, mac):
		sql = "INSERT INTO hosts(OS, estado, id_revision, ip, fecha, mac) VALUES (%s,%s,%s,%s,%s,%s);"
		args = (os, state, id_rev, ip, date, mac)
		self.cur.execute(sql, args)
		self.con.commit()
		return self.cur.lastrowid

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