#!/usr/bin/python
#-*-coding:utf-8-*-
#- Add DNS Class

#- AdminServer / System Management Server
#- Copyright (C) 2014 GoldraK & Interhack 
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License 
# as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. 
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty 
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>

# WebSite: http://adminserver.org/
# Email: contacto@adminserver.org
# Facebook: https://www.facebook.com/pages/Admin-Server/795147837179555?fref=ts
# Twitter: https://twitter.com/4dminserver

import sys, subprocess,nmap,os
sys.path.append('model')
from utility import utility
from database import Database
from teco import color
nm = nmap.PortScanner()
directory = ""

class scan(object):
	
	@staticmethod
	def selectaudit(translate, log):
		_ = translate
		global directory
		audit_action = raw_input(_('New audit(1)/existing audit(2): '))
		while audit_action == "":
			audit_action = raw_input(_('New audit(1)/existing audit(2): '))
		if audit_action == '1':
			new_audit = raw_input(_('Name audit: '))
			while new_audit == "":
				new_audit = raw_input(_('Name audit: '))
			raiz = os.path.expanduser('~')
			directory = raiz+'/auditorias/'+new_audit+'/'
			if not os.path.exists(raiz+'/auditorias/'+new_audit+'/'):
				os.makedirs(raiz+'/auditorias/'+new_audit+'/')
			else:
				print "Esa carpeta ya existe";
		elif audit_action == '2':
			directory = utility.read_valid_dir(_)
		print directory

	@staticmethod
	def discovery(translate, log):
		_ = translate
		global directory
		if directory != "":
			print "Esta en el direcorio: "+directory
			change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			while change_directory == "":
				change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			if change_directory == "n":
				host_scan = raw_input(_('Host scan: '))
				while host_scan == "":
					host_scan = raw_input(_('Host scan: '))
				name_file = raw_input(_('Name File: '))
				while name_file == "":
					name_file = raw_input(_('Name File: '))
				if '/' in host_scan:
					if host_scan.split('/')[1] >= "24":
						nm.scan(hosts=host_scan, arguments='-n -sP -PE -PA21,23,80,3389')
						hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
						raiz = os.path.expanduser('~')
						archivo = open(directory+'/'+name_file+'.txt', 'w')
						for host, status in hosts_list:
							print host, status
							archivo.write(host+'\n')
						archivo.close()
					else:
						rangos = utility.calculaterangeip(_,host_scan)
						for rango in rangos:
							scan_host = rango+".0/24"
							result = nm.scan(hosts=host_scan, arguments='-n -sP -PE -PA21,23,80,3389')
							if int(result['nmap']['scanstats']['uphosts']) != 0:
								hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
								raiz = os.path.expanduser('~')
								archivo = open(directory+name_file+'_'+rango+'.0.txt', 'w')
								for host, status in hosts_list:
									print host, status
									archivo.write(host+'\n')
								archivo.close()	
				else:
					nm.scan(hosts=host_scan, arguments='-n -sP -PE -PA21,23,80,3389')
					hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
					raiz = os.path.expanduser('~')
					archivo = open(directory+'/'+name_file, 'w')
					for host, status in hosts_list:
						print host, status
						archivo.write(host+'\n')
					archivo.close()
			else:
				scan.selectaudit(_, log)
		else:
			print "seleciona primero una auditoria"
			scan.selectaudit(_, log)

	@staticmethod
	def version(translate, log):
		_ = translate
		global directory
		if directory != "":
			print "Esta en el direcorio: "+directory
			change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			while change_directory == "":
				change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			if change_directory == "n":
				file_host = raw_input(_('File(1)/Host(2): '))
				while file_host == "":
					file_host = raw_input(_('File(1)/Host(2): '))
				
				if file_host == '1':
					file_read = utility.read_valid_file(_,directory)
					file_to_read = open(file_read, 'r')
					for line_scan in file_to_read:
						nm.scan(hosts=line_scan, arguments='-sV')
						print nm.csv()
				elif file_host == '2':
					host_scan = raw_input(_('Host scan: '))
					while host_scan == "":
						host_scan = raw_input(_('Host scan: '))
					nm.scan(hosts=host_scan, arguments='-sV')
					print nm.csv()
			else:
				scan.selectaudit(_, log)
		else:
			print "seleciona primero una auditoria"
			scan.selectaudit(_, log)


	@staticmethod
	def script(translate, log):
		_ = translate
		global directory
		if directory != "":
			print "Esta en el direcorio: "+directory
			change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			while change_directory == "":
				change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			if change_directory == "n":
				file_host = raw_input(_('File(1)/Host(2): '))
				while file_host == "":
					file_host = raw_input(_('File(1)/Host(2): '))
				
				if file_host == '1':
					file_read = utility.read_valid_file(_,directory)
					file_to_read = open(file_read, 'r')
					for line_scan in file_to_read:
						nm.scan(hosts=line_scan, arguments='-sV -sC')
						print nm.csv()
				elif file_host == '2':
					host_scan = raw_input(_('Host scan: '))
					while host_scan == "":
						host_scan = raw_input(_('Host scan: '))
					nm.scan(hosts=host_scan, arguments='-sV -sC')
					print nm.csv()
			else:
				scan.selectaudit(_, log)
		else:
			print "seleciona primero una auditoria"
			scan.selectaudit(_, log)


	@staticmethod
	def CustomParameters(translate, log):
		_ = translate
		global directory
		if directory != "":
			print "Esta en el direcorio: "+directory
			change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			while change_directory == "":
				change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			if change_directory == "n":
				file_host = raw_input(_('File(1)/Host(2): '))
				while file_host == "":
					file_host = raw_input(_('File(1)/Host(2): '))
				customparameters = raw_input(_('Custom Parameters: '))
				while customparameters == "":
					customparameters = raw_input(_('Custom Parameters: '))
				if file_host == '1':
					file_read = utility.read_valid_file(_,directory)
					file_to_read = open(file_read, 'r')
					for line_scan in file_to_read:
						nm.scan(hosts=line_scan, arguments=customparameters)
						print nm.csv()
				elif file_host == '2':
					host_scan = raw_input(_('Host scan: '))
					while host_scan == "":
						host_scan = raw_input(_('Host scan: '))
					nm.scan(hosts=host_scan, arguments=customparameters)
					print nm.csv()
			else:
				scan.selectaudit(_, log)
		else:
			print "seleciona primero una auditoria"
			scan.selectaudit(_, log)

	@staticmethod
	def puertos(translate, log):
		_ = translate
		global directory
		if directory != "":
			print "Esta en el direcorio: "+directory
			change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			while change_directory == "":
				change_directory = raw_input(_('Quiere cambiar[s/n]: '))
			if change_directory == "n":
				file_host = raw_input(_('File(1)/Host(2): '))
				while file_host == "":
					file_host = raw_input(_('File(1)/Host(2): '))
				
				if file_host == '1':
					file_read = utility.read_valid_file(_,directory)
					file_to_read = open(file_read, 'r')
					for line_scan in file_to_read:
						nm.scan(hosts=line_scan, arguments='-p 80')
						print nm.csv()
				elif file_host == '2':
					host_scan = raw_input(_('Host scan: '))
					while host_scan == "":
						host_scan = raw_input(_('Host scan: '))
					nm.scan(hosts=host_scan, arguments='-p 80')
					print nm.csv()
			else:
				scan.selectaudit(_, log)
		else:
			print "seleciona primero una auditoria"
			scan.selectaudit(_, log)
