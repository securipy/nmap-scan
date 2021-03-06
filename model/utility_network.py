#!/usr/bin/python
#-*-coding:utf-8-*-

"""Nmap scan. Network connection"""

__author__ 		= "GoldraK & Roger Serentill & Carlos A. Molina"
__credits__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK & Roger Serentill & Carlos A. Molina"
__email__ 		= "goldrak@gmail.com, hello@rogerserentill.com, carlosantmolina@gmail.com"
__status__ 		= "Development"

import sys, socket, fcntl, struct
sys.path.append('model')
from teco import color, style
from utility2 import Check


class NetworkUtility:

	def __init__(self):
		self.ck = Check()

	def getMyIP(self):
		# IP form wireless interface
		myHostIP = socket.gethostbyname(socket.gethostname())
		if self.ck.checkIPstartsWith127(myHostIP) == -1: # no wireless interface is used, get IP in a different way
			try:
				myHostIP = self.getInterfaceIP('eth0') # IP from wired interface
			except:	# none network interface is used
				try:
					myHostIP = self.getInterfaceIP('enp4s0')  # IP from wired interface
				except:
					myHostIP = None
		return myHostIP

	def getInterfaceIP(self, interface):
	# get IP address of the indicated interface
	# https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return socket.inet_ntoa(fcntl.ioctl(
			s.fileno(),
			0x8915,  # SIOCGIFADDR
			struct.pack('256s', interface[:15])
		)[20:24])

	def checkNetworkConnection(self, myIP):
		if myIP == None:
			print color('rojo', "\nYou haven't got network connection\n")
			return -1
		elif self.ck.checkIPstartsWith127(myIP) == -1:
			print color('rojo', 'Are you sure you have network connection?')
			return 1
		else:
			return 1
