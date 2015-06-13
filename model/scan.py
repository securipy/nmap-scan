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
import pprint

class Scan:


	def __init__(self):
		self.num_audit = None
		self.nom_audit = None
		self.num_rev = None
		self.nom_rev = None
		self.nm = nmap.PortScanner()
		self.db = Database()


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
			all_revs = self.db.retrieve_revisions()
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
		self.nm.scan(hosts=host_scan, arguments='-n -sP -PE -PA 21,23,80,3389')
		hosts_list = [(x, self.nm[x]['vendor'].keys()) for x in self.nm.all_hosts()]
		for host in hosts_list:
			ip, vendor, os = host
			if len(vendor) == 0:
				mac = None
			else:
				mac = vendor[0]
			print self.num_rev, ip, mac
			self.db.add_host('up', self.num_rev, ip, mac)



	def __check_audit_rev(self):
		if self.num_audit == None and self.nom_audit == None:
			print color('bcyan', "Select audit")
			self.select_audit()
		if self.num_rev == None and self.nom_rev == None:
			print color('bcyan', "Select revision")
			self.select_revision()