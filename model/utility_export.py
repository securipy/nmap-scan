#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan. Export results"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys, nmap, time, os.path
sys.path.append('model')
from database import Database
from utility2 import ChangeFormat, Check, Message
from utility_ask import Ask

class UtilityExport:

	def __init__(self):
		self.ask = Ask()
		self.cf = ChangeFormat()
		self.ck = Check()
		self.db = Database()
		self.ms = Message()
		self.nm = nmap.PortScanner()
		self.fileExtension = '.txt'

	def createFile(self, auditName, revisionName, savePath, name4file, information2save):
		fileName = auditName + '_' + revisionName + '_' + name4file + self.fileExtension
		fileName, filePathAndName = self.__checkFileExists(fileName, savePath)
		file = open(filePathAndName,'w') # create file
		file.write(information2save)	# write information in file
		file.close()	# end work with file
		self.ms.adviseFileCreated(fileName)

	def createFileHost(self, auditName, revisionName, save_path, hostIP, hostMac):
		# fileName, filePathAndName = self.__createFileName()
		print 'in process'

	def __checkFileExists(self, fileName, savePath):
		filePathAndName = os.path.join(savePath, fileName)
		if self.ck.checkFileExists(filePathAndName) == 1:
			if self.ask.askOverwriteFile(fileName) == -1:
				fileName = fileName.replace(self.fileExtension, '_'+self.__getDatetime()+'.txt')
				filePathAndName = os.path.join(savePath, fileName)
		return fileName, filePathAndName

	def __getDatetime(self):
		time2 = time.strftime("%H-%M-%S")
		date = time.strftime("%Y-%m-%d")
		datetime = '%s_%s' %(date, time2)
		return datetime