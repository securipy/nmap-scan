#!/usr/bin/python
#-*-coding:utf-8-*-

import nmap

__author__ 		= "GoldraK & Roger Serentill"
__credits__ 	= "GoldraK & Roger Serentill"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com"
__status__ 		= "Development"



class NmapScan:

	def __init__(self, host='127.0.0.1'):
		self.host = host


	def scan_discover(self, arguments = None):
		nm = nmap.PortScanner()
		if arguments == None:
			nm.scan(hosts=host_scan, arguments=arguments)
		else:
			nm.scan(hosts=host_scan, arguments='-n -sP -PE -PA21,23,80,3389')
		hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
		return hosts_list

	def scan(self,arguments = None):
		nm = nmap.PortScanner()
		if arguments == None:
			nm.scan(hosts=host_scan)
		else:
			nm.scan(hosts=host_scan, arguments=arguments)
		hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
		return hosts_list