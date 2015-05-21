#!/usr/bin/python
#-*-coding:utf-8-*-
#- nmap_scan Class

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

class add(object):
	#- @output.[option](default, error)(text) -> printed by stdout
	#- @translate.[option](init('nameTranslate')) -> initializes the translation file
	#- @log.[option](write)(text,*1) -> 1 is error -> saves information in the logs
	#- @installer -> module for install dependencies -> nonoperating

	def __init__(self, output, translate, log, installer,options):
		#- imports necessary
		import sys, os,signal
		sys.path.append('modules/nmap-scan/model')
		from scan import Scan
		scan = Scan()

		def apagado(sig,frame):
			output.default("Kill Scan")
			sys.exit(0)
		signal.signal(signal.SIGINT, apagado)
		#- Operations
		#- Example:
		interpret = translate.init('nmap_scan', 'modules/nmap-scan/locale')
		_ = interpret.ugettext
		output.default('Nmap Scan')
		def __menu__():
			output.default('1. Select audit')
			output.default('2. Discovery')
			output.default('3. Versiones')
			output.default('4. Script')
			output.default('5. Custom Parameters')
			output.default('6. Puertos')
			output.default('0. Exit')

		def option1():
			scan.selectaudit()

		def option2():
			scan.discovery(_, log)
		
		def option3():
			scan.version(_, log)

		def option4():
			scan.script(_, log)			

		def option5():
			scan.CustomParameters(_, log)	

		def option6():
			scan.puertos(_, log)
		
		__menu__()

		control = True
		while control == True:
			options.set_completer(help.complete)
			sentencia = raw_input("Nmap >> ")
			if sentencia == '1':
				option1()
			elif sentencia == '2':
				option2()
			elif sentencia == '3':
				option3()	
			elif sentencia == '4':
				option4()	
			elif sentencia == '5':
				option5()			
			elif sentencia == '6':
				option6()						
			elif sentencia == '0':
				sys.exit()
			elif sentencia == 'exit':
				sys.exit()
			elif sentencia == 'version':
				output.default(help.version())
			elif sentencia == 'help':
				output.default(help.help())
			elif sentencia == 'menu':
				__menu__()
			else:
				output.default('No ha seleccionado una opcion correcta')

class help(object):
	#- Commands default
	@staticmethod
	def complete(text, state):
		possibilities = ["exit", "version", "help"]
		results = [x for x in possibilities if x.startswith(text)] + [None]
		return results[state]

	#- Help for menu
	@staticmethod
	def help(translate=''):
		return "Help Module"

	@staticmethod
	def version(translate=''):
		return "Version 0.1"

	@staticmethod
	#- @translate.[option](init('nameTranslate')) -> initializes the translation file
	def info(translate):
		return 'This module is created to search info with Nmap'

	@staticmethod
	#- Especificamos si necesita el modulo paquetes adicionales.
	def package():
		#- List of extra dependencies needed by the module
		additionalPackage = ['nmap']
		return additionalPackage