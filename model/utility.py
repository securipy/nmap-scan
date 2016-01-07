#!/usr/bin/python
#-*-coding:utf-8-*-
#- utility DNS Class

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

import sys, os, subprocess,re,ipcalc
sys.path.append('modules/nmap_scan/model')

class utility(object):
	@staticmethod
	def ensure_dir(f):
	    d = os.path.dirname(f)
	    if not os.path.exists(d):
	        os.makedirs(d)

	@staticmethod
	def read_valid_file(_,route):
		#raiz = os.path.expanduser('~')
		#utility.ensure_dir(raiz+'/auditorias/')
		ficheros = os.listdir(route)
		matriz_ficheros = []
		for fichero in ficheros:
			control = False;
			file_temp = open(route+'/'+fichero, 'r')
			for line in file_temp:
				if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",line):
   					control = True
   				else:
					control = False
					break
			if control == True:
				matriz_ficheros.append(fichero)
			file_temp.close()
		cant_file = 1;
		for valid_file in matriz_ficheros:
			print str(cant_file)+'. '+valid_file
			cant_file += 1
		file_host_scan = raw_input(_('File to scan: '))
		while (file_host_scan == "" or int(file_host_scan) > len(matriz_ficheros)):
			file_host_scan = raw_input(_('File to scan: '))
		return route+'/'+matriz_ficheros[int(file_host_scan)-1]

	@staticmethod
	def read_valid_dir(_):
		raiz = os.path.expanduser('~')
		#utility.ensure_dir(raiz+'/auditorias/')
		directorios = os.listdir(raiz+'/auditorias/')
		matriz_directorios = []
		cant_file = 1;
		for directorio in directorios:
			if os.path.isdir(raiz+'/auditorias/'+directorio):
				print str(cant_file)+'. '+directorio
				cant_file += 1
				matriz_directorios.append(directorio)
		directory_scan = raw_input(_('directorio de la auditoria: '))
		while (directory_scan == "" or int(directory_scan) > len(matriz_directorios)):
			directory_scan = raw_input(_('directorio de la auditoria: '))
		return raiz+'/auditorias/'+matriz_directorios[int(directory_scan)-1]

	@staticmethod
	def calculaterangeip(_,ip):
		subnet = ipcalc.Network(ip)
		lista = []
		for x in subnet:
			ipobtenida = str(x).split('.')[0] + '.' + str(x).split('.')[1] + '.' + str(x).split('.')[2]
			#print ipobtenida
			if (ipobtenida not in lista):
				lista.append(ipobtenida)
		return lista
			