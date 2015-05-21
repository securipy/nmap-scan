#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan"""

__author__ 		= "GoldraK & Roger Serentill"
__credits__ 	= "GoldraK & Roger Serentill"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com"
__status__ 		= "Development"

import sys
sys.path.append('model')
from database import Database
from nmapscan import NmapScan

class Scan:


	def __init__(self):
		self.num_audit = None
		self.nom_audit = None


	def selectaudit(self):
		db = Database()
		audit_action = raw_input('New audit(1)/existing audit(2): ')
		while audit_action == "":
			audit_action = raw_input('New audit(1)/existing audit(2): ')
		if audit_action == '1':
			new_audit = raw_input('Name audit: ')
			while new_audit == "":
				new_audit = raw_input('Name audit: ')
			if len(db.retrieve_audit_name(new_audit)) == 0:
				self.num_audit = db.add_audit(new_audit)
				self.nom_audit = new_audit
		else:
			all_audits = db.retrieve_audits()
			for num,audit in all_audits:
				print str(num)+". "+audit 
			number_audit = raw_input('Number audit: ')
			while number_audit == "":
				number_audit = raw_input('Number audit: ')
			self.num_audit = number_audit
			all_audits = dict((x,y) for x, y in all_audits)
			self.nom_audit = all_audits[number_audit]
			print self.nom_audit
			print self.num_audit