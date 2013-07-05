#!/usr/bin/env python
#
# Name: adfs2fed - Tool to convert ADFSv2 Metadata in a Shibboleth-friendly format
# Author: Cristian Mezzetti <cristian.mezzetti@unibo.it>
# Home-page: http://sourceforge.net/projects/femma
# License: GNU GPL v2
# Description: This script parses a (Shibboleth) federation 
#              metadata XML content and creates a pool of 
#              metadata files and a powershell script in order
#              to automatically configure and update an Active
#              Directory Federation Services STS (Security Token Service).
#
# Copyright (C) 2010  Cristian Mezzetti
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This script is based on the findings of the italian IDEM Federation staff during
# the interoperability test with the University of Bologna ADFS IdP.
#
# example: 
#	adfs2fed.py --idp=idp.unibo.it --scope=unibo.it

from lxml import etree
import urllib2, sys, getopt

def exportAdfs2Fed(idpUrl, scope):
	"""
	Modifies ADFS metadata removing and inserting elements in order to avoid parsing problems on Shibboleth-side
	"""
	adfsEndpoint = "/FederationMetadata/2007-06/FederationMetadata.xml"
	shibNameSpace = 'xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"'
	extensions = '<Extensions>\n    <shibmd:Scope regexp="false">' + scope + '</shibmd:Scope>\n  </Extensions>\n  '
	mdString = ""
	try:
		# get metadata
		metadata = urllib2.urlopen(idpUrl + adfsEndpoint)
		root = etree.fromstring(metadata.read())
		# remove signature, RoleDescriptor and SPSSODescriptor elements in order to avoid incompatibilities with
		# the Switch WAYF shipped parser
		root.remove(root.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))
		root.remove(root.find('{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor'))
		root.remove(root.find('{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor'))
		root.remove(root.find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor'))
		# add SAML1 SingleSignOn binding, in order to avoid Switch WAYF limitation (without this the IdP
		# configuration will not be loaded
		binding = etree.XML('<SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="' + idpUrl + '/adfs/ls/"/>')
		root[0].insert(8,binding)
		# add scope extension
		mdString = etree.tostring(root, pretty_print=True)
		mdString = mdString.replace('xmlns="urn:oasis:names:tc:SAML:2.0:metadata"', 'xmlns="urn:oasis:names:tc:SAML:2.0:metadata"' + ' ' + shibNameSpace)
		mdString = mdString.replace('<IDPSSODescriptor', extensions + '<IDPSSODescriptor')
	except Exception, e:
		print(e)
	return mdString

def usage(ret=0):
	print "-i, --idp:       Identity provider hostname (es. idp.unibo.it)"
	print "-o, --outfile:   File name of the resulting metadata"
	print "-s, --scope:     Scope of eduPersontScopedAffiliation (es. unibo.it)"
	print "-h, --help"
	sys.exit(ret)

def main():

	idpUrl = "idp.unibo.it"
	outFile = "ExportedFederationMetadata.xml"
	scope = "unibo.it"

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hti:o:s:", ["help", "test", "idp=", "outfile=", "scope="])

	except getopt.GetoptError, err:
		print str(err)
		usage(2)

	if opts.__len__() != 0:
		for o, a in opts:
			if o in ("-i", "--idp"):
				idpUrl = "https://" + a
			elif o in ("-o", "--outfile"):
				outFile = a
			elif o in ("-s", "--scope"):
				scope = a
			else:
				usage()
		of = open(outFile, "w")
		print "Writing modified IdP Metadata in " + outFile
		of.write(exportAdfs2Fed(idpUrl, scope))
		of.close()
	else:
		usage()


if __name__ == "__main__":
		main()
