#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan. Select audit and revision"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys
sys.path.append('model')
from database import Database
from teco import color, style
from utility2 import Check
from utility_ask import Ask

class SelectAuditRev:

	def __init__(self):
		self.db = Database()
		self.ask = Ask()
		self.ck = Check()

	def selectAudit(self):
		# initialice elements
		auditNumber = None
		auditName = None
		while auditNumber == None or auditName == None:
			print color('bcyan', 'Select audit')
			print color('cyan','1. New audit\n2. Existing audit')
			auditOption = self.ask.ask4number()
			if auditOption == 1: # add new audit
				auditName = self.ask.ask4name('Audit')
				if self.checkAuditExistsAtDB(auditName) == 1:
					self.adviseRepeatedName()
				else:
					auditNumber = self.db.add_audit(auditName)
			elif auditOption == 2: # select existing audit
				auditNumber, auditName = self.selectExistingAudit()
		return auditNumber, auditName

	def selectExistingAudit(self):
		auditNumber = None
		auditName = None
		auditsDBallInfo = self.db.retrieve_auditsAllInfo()
		if self.checkDBtableEmpty(auditsDBallInfo) == 1:
			self.adviseNotExisting('audits')
		else:
			while auditNumber == None or auditName == None:
				self.showDBauditsName(auditsDBallInfo)
				auditNumber = self.ask.ask4number()
				auditsDBallInfo = dict((x, y) for x, y in auditsDBallInfo)  # convert to dictionary
				try:
					auditName = auditsDBallInfo[int(auditNumber)]
				except:
					self.adviseDoesNotExist('Audit')
		return auditNumber, auditName

	def selectRevision(self, auditNumber, auditName):
		# returns auditNumber and auditName because maybe they are not specified yet
		# initialice elements
		revisionNumber = None
		revisionName = None
		while auditNumber == None or auditName == None or revisionNumber == None or revisionName == None:
			if self.checkAuditSelected(auditNumber, auditName) == -1:
				print color('rojo','Select audit before revison')
				auditNumber, auditName = self.selectAudit()
			print color('bcyan', 'Select revision')
			print color('cyan', '1. New revision\n2. Existing revision')
			revisionOption = self.ask.ask4number()
			if revisionOption == 1:
				# Add new revision
				revisionName = self.ask.ask4name('Revision')
				if self.checkRevisionExistsAtDB(auditNumber, revisionName) == 1:
					self.adviseRepeatedName()
				else:
					revisionNumber = self.db.add_revision(int(auditNumber), revisionName)
			elif revisionOption == 2:
				revisionNumber, revisionName = self.selectExistingRevision(auditNumber)
		return auditNumber, auditName, revisionNumber, revisionName

	def selectExistingRevision(self, auditNumber):
		# select existing revision
		revisionNumber = None
		revisionName = None
		revisions4AuditDBAllInfo = self.db.retrieve_revisonAllInfoByAuditID(auditNumber)
		if self.checkDBtableEmpty(revisions4AuditDBAllInfo) == 1:
			self.adviseNotExisting('revisions')
			print "Create a revision for this audit"
		else:
			while revisionNumber == None or revisionName == None:
				self.showDBrevisionsName(revisions4AuditDBAllInfo)
				revisionNumber = self.ask.ask4number()
				revisions4AuditDBAllInfo = dict((y, z) for x, y, w, z in revisions4AuditDBAllInfo)  # convert to dictionary
				try:
					revisionName = revisions4AuditDBAllInfo[int(revisionNumber)]
				except:
					self.adviseDoesNotExist('Revision for this audit')
		return revisionNumber, revisionName

	def checkAuditExistsAtDB(self, auditNewName):
		allInfoAtDB = self.db.retrieve_auditAllInfoByName(auditNewName)
		return self.ck.checkListNotEmpty(allInfoAtDB)

	def checkRevisionExistsAtDB(self, auditNumber, revisionName):
		allInfoAtDB = self.db.retrieve_revisionAllInfoByName(revisionName, auditNumber)
		return self.ck.checkListNotEmpty(allInfoAtDB)

	def checkDBtableEmpty(self, DBallInfo):
		return self.ck.checkListEmpty(DBallInfo)

	def checkAuditSelected(self, auditNumber, auditName):
		if auditNumber == None or auditName == None:
			return -1
		else:
			return 1

	def showDBauditsName(self, auditsDBallInfo):
		print color('verde', 'Available audits')
		for num,audit in auditsDBallInfo:
			print color('verde', str(num)+". "+audit)

	def showDBrevisionsName(self, revisions4AuditDBAllInfo):
		print color('verde', 'Available revisions')
		for fecha, num, id_audit, rev in revisions4AuditDBAllInfo:
			print color('verde', str(num)+". "+rev+" ("+str(fecha)+")")

	def adviseRepeatedName(self):
		print color('rojo', 'Repeated name\n')

	def adviseDoesNotExist(self, whatDoesNotExist):
		print color('rojo', str(whatDoesNotExist)+ ' does not exist\n')

	def adviseNotExisting(self, whatDoesNotExist):
		print color('rojo', 'No existing ' + str(whatDoesNotExist) + '\n')