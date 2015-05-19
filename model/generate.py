#!/usr/bin/python
#-*-coding:utf-8-*-
#- regenerate DNS Class

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

import sqlite3

class generate(object):
	@staticmethod
	def all(domain_id, conectionBrain):
		
		if str(domain_id) == 'all':
			conectionBrain = sqlite3.connect('modules/management_apache/brain/apache.db')
			cursor = conectionBrain.cursor()
			cursor.execute("SELECT * FROM apache WHERE status = '1'")
		else:
			cursor = conectionBrain.cursor()
			cursor.execute("SELECT * FROM apache WHERE id = '" + str(domain_id) + "'")

		for info in cursor:
			domain_name = str(info[1])
			email = str(info[2])
			path_server = str(info[3])
			rewrite = str(info[4])
			indexOf = str(info[5])

			if str(rewrite) == '1':
				rewriteValues = "\n\t\tRewriteEngine On"
			else:
				rewriteValues = ""

			if str(indexOf) == '1':
				indexOfValues = "\n\t\tOptions Indexes FollowSymLinks MultiViews"
			else:
				indexOfValues = ""

			save = open('/etc/apache2/sites-available/' + domain_name, 'w')
			save.write("""<VirtualHost *:80>
	ServerAdmin """ + email + """
	ServerName """ + domain_name + """
	ServerAlias www.""" + domain_name + """
	DocumentRoot """ + path_server + """
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory """ + path_server + """>""" + indexOfValues + rewriteValues + """
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>


	ErrorLog ${APACHE_LOG_DIR}/error.log

	# Possible values include: debug, info, notice, warn, error, crit,
	# alert, emerg.
	LogLevel warn

	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>""")
