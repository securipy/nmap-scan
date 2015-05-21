#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan"""

__author__ 		= "GoldraK & Roger Serentill"
__credits__ 	= "GoldraK & Roger Serentill"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com"
__status__ 		= "Development"


sys.path.append('model')
from database import Database
from nmap_scan import nmap_scan

class Scan:

 
 	def __init__(self,translate):
 		self.translate = translate


 	def selectaudit(self):
 		db = Database()
 		audit_action = raw_input('New audit(1)/existing audit(2): ')
		while audit_action == "":
			audit_action = raw_input('New audit(1)/existing audit(2): ')
		if audit_action == '1':
			new_audit = raw_input('Name audit: ')
			while new_audit == "":
				new_audit = raw_input('Name audit: ')
			print db.retrieve_audit(new_audit)

		else: