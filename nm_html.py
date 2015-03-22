#!/usr/bin/env python

###############################################
# Name: nm_html.py
# Version: 0.1
# Company: InGuardians, Inc.
# Start Date: March 29, 2011
#
# Purpose:
#
#   This script will generate NMap information from an NMap XML File.
#   The details provided are not as extensive as the individual NMap
#   output.  This output merely contains useful information about 
#   the hostname, MAC address, and open TCP or UDP ports.  Users can
#   select a single or list of IP address from a large directory
#   of NMap XML files.  Output goes to standard out for user redirection
#   to an HTML file.  This file can be opened in a browser of the user's
#   choice.
#
# NOTE:
#   The version of HTMLTags has been modified to supply additional information.
#   Using a different version will result in parsing errors.
#
# Developers: 
#   Cutaway (Don C. Weber)
#
# Resources:
#   http://code.google.com/p/python-nmap-parser/
#   http://nmap.org/
#   Service overview and network port requirements for the Windows Server system - 
#       http://support.microsoft.com/kb/832017
#
# TODO: 
#
# Change Log:
#
############################################

# Import useful modules
import sys, os, glob, getopt, datetime

# Setup NmapParser module for import
nmp = os.getcwd() + "/NmapParser"
html = os.getcwd() + "/HTMLTags"
sys.path.append(nmp)
sys.path.append(html)
import Parser
from HTMLTags import *

# Configuration variables
VERSION     = '0.1'
DATE_TIME   = datetime.datetime.now().strftime("%Y%m%d%H%M")

# Booleans
FALSE = 0
TRUE = 1

# Variables
DEBUG       = FALSE
HOSTS       = []
PROTO       = 'tcp'
inf         = None
ALLHOSTS   = TRUE  # Select all hosts
SELHOSTS    = []    # Selected hosts

def usage():
    print "NMap Target List Version: " + VERSION
    print "Usage:\n nm_tlist.py -i XML_directory [-d] [-u] [-x Select_Targets] [-h] [--help] [--version]"
    print " nm_tlist.py -i XML_directory [-n USER_TARGET_NAME] [-p USER_PORT_LIST] [-s USER_SERVICE_INFO_LIST]"
    print "    -i: Directory containing the NMap XML files.  This is mandatory."
    print "    -d: Debugging mode.  Default is off"
    print "    -u: UDP mode.  Default is TCP"
    print "    -s: Select hosts mode.  Provide IP address in a comma separated list."
    print "        This supresses printing the file name of all XML files processed to only those that contain"
    print "        selected IP addresses."
    print "    --help: Seriously?  You are reading it."
    print "    --version: Version of this tool"
    print ""
    sys.exit(2)

# Process options
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:s:duh", ["help","version"])
except getopt.GetoptError, err:
    print str(err)
    usage()

for o, a in opts:
    if o in ("--version","--help","-h"):
        usage()
    elif o == "-d":
        # Set DEBUG
        DEBUG = TRUE
    elif o == "-i":
        # Get directory with NMap XML files
        indir = a
        inf = indir + "/*.xml"
    elif o == "-s":
        SELHOSTS = a.split(',')
        ALLHOSTS = FALSE
    elif o == "-u":
        TARGS = UDP_TARGS
        PROTO = 'udp'

# Test for directory with XML files
if inf == None:
    print "No input directory"
    usage()

head = HEAD(TITLE('NMap Results'))
body = BODY()
body <= H1('NMAP Results - Parsed: ' + DATE_TIME)
# Loop thru NMap XML files
for xfile in glob.glob(inf):
    pr = Parser.Parser(xfile)
    if DEBUG: print xfile
    HFILE = TRUE

    # Loop thru each host in file
    for h in pr.all_hosts():
        if h.ip in SELHOSTS or ALLHOSTS:
            if HFILE: 
                body <= H2(xfile)
                HFILE = FALSE
            body <= H3('Scan Results ' + h.ip)
            body <= ("Name: " + h.hostname + BR())
            body <= ("MAC: " + h.mac + BR())
            #body <= ("Status: " + str( h.status ) + BR())
            table = TABLE(border='2')
            tr = TR(bgcolor='gray')
            tr <= TH('PORT') + TH('SERVICE') + TH('PRODUCT') + TH('VERSION') + TH('EXTRAINFO')
            table <= tr
            # Loop thru and count all open ports
            for p in h.get_ports(PROTO,'open'):
                s = h.get_service(PROTO, p)
                tr = TR()
                tr <= TD(p)
                if s == None:
                    tr <= TD('') + TD('') + TD('') + TD('')
                else:
                    if s.name != '':
                        tr <= TD(s.name) 
                    else:
                        tr <= TD('')
                    if s.product != '':
                        tr <= TD(s.product)
                    else:
                        tr <= TD('')
                    if s.version != '':
                        tr <= TD(s.version)
                    else:
                        tr <= TD('')
                    if s.extrainfo != '':
                        tr <= TD(s.extrainfo)
                    else:
                        tr <= TD('')
                table <= tr
            body <= table

print HTML(head + body)
