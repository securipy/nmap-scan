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
from teco import color, style
from utility_ask import Ask

class ChangeHostName:

	def __init__(self):
		self.ask = Ask()
		self.db = Database()

	def changeName(self, auditNumber, revisionNumber):
		hostsIDavailable = self.showListHostsIPandHostsNames(auditNumber, revisionNumber) # options available to select a host
		hostIDselected = self.ask.ask4ListOptionNumber(hostsIDavailable)
		newName = self.ask.ask4name("Type host's new")
		self.db.update_hostName_byID(hostIDselected, newName)
		print 'Name changed'

	def showListHostsIPandHostsNames(self, auditNumber, revisionNumber):
		hostsIDipAndNames = self.db.retrieve_hostsIDipAndNames_byRevision(auditNumber, revisionNumber) # example: [(8, u'192.168.1.1', u'None'), (9, u'192.168.1.34', u'None'), (10, u'192.168.1.37', u'None')]
		hostsIDavailable = []
		print color('verde', 'Available hosts for this revision')
		print color('verde','     ip             name')
		print color('verde','--------------------------')
		for idHost, ipHost, nameHost in hostsIDipAndNames:
			hostsIDavailable.append(idHost) # save id of available hosts
			print color('verde', str(idHost)+'.   ' + str(ipHost) + '   ' + str(nameHost))
		print '' # blank line
		return hostsIDavailable
