#!/usr/bin/env python

###############################################
# Name: nm_tlist.py
# Version: 0.1
# Company: InGuardians, Inc.
# Start Date: March 26, 2011
#
# Purpose:
#   This script will output a list of targets according to 
#   port numbers or information provided in service information.
#   Target lists build using service information is a little
#   more accurate than going by port numbers alone.  Service 
#   information also helps identify services running on non-standard
#   ports such as management web interfaces or SSH servers that
#   have been moved by administrators from port 22.
#   Results are output to standard out in a comma separated or
#   newline separated list.
#
#   ***NOTE***: Information provided here is best guess.  Results 
#   should be double checked to verify accuracy.
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
import sys, os, glob, re, getopt, datetime

# Setup NmapParser module for import
nmp = os.getcwd() + "/NmapParser"
sys.path.append(nmp)
import Parser

# Configuration variables
VERSION     = '0.1'
DATE_TIME   = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

# Booleans
TRUE = 1
FALSE = 0

# TCP Port Lists
FTP         = ('FTP','FTP Servers',[21],['ftp'])
SSH         = ('SSH','SSH Servers',[22],['ssh','secure shell'])
TELNET      = ('TELNET','Telnet Servers',[23],['telnet'])
MAIL        = ('Mail','Mail Servers',[25,110,143,465,587,993,995],['mail','exchange','imap','pop3','smtp'])
DNS         = ('DNS','Domain Name Services',[53],['dns'])
FINGER      = ('FINGER','Finger Servers',[79],['finger'])
WEB         = ('WEB','Web Servers',[80,443,1188,5800,8000,8008,8080,8443], ['http','web','apache','iis'])
KERBEROS    = ('DERBEROS','Kerberos Servers',[88,464],['kerberos'])
MS          = ('MS','Microsoft Services',[135,139,445,1033,5722],['rpc','smb','netbios'])
LDAP        = ('LDAP','LDAP Servers',[389,636],['ldap'])
MEDIA       = ('MEDIA','Media Services',[554,1755],['rtsp','mms'])
DB          = ('DB','Database Servers',[1433,1434,1521,1522,1525,1529,3306,5432],['sql','database','oracle','postgres'])
RDA         = ('RDA','Remote Desktop Application Services',[3389,5900],['terminal','vnc'])
CONF        = ('CONF','Configuration Management Servers',[1270,2701,2702,2703,2704,51515],['sms','mom'])

# UDP Port Lists
TFTP        = ('TFTP','TFTP Servers',[69],['tftp'])
NTP         = ('NTP','Network Time Servers',[123],['ntp'])
MS          = ('MS','Microsoft Services',[137,138],['netbios'])
SNMP        = ('SNMP','SNMP Services',[161],['snmp'])

TCP_TARGS   = [FTP,SSH,TELNET,MAIL,DNS,FINGER,WEB,KERBEROS,MS,LDAP,MEDIA,DB,RDA,CONF]
UDP_TARGS   = [TFTP,NTP,MS,SNMP]

# Variables
TARGS       = TCP_TARGS
ALL_TARGS   = {}       # Hold all target lists
add_host    = FALSE
DEBUG       = FALSE
COMMA       = TRUE
HOSTS       = []
SELECTED    = []
USER_NAME   = None
USER_PORTS  = []
USER_SINFO  = []
PROTO       = 'tcp'
CHUNK       = 1
inf         = None

def usage():
    print "NMap Target List Version: " + VERSION
    print "Usage:\n nm_tlist.py -i XML_directory [-d] [-u] [-o] [-l] [-x Select_Targets] [-c size] [-h] [--help] [--version]"
    print " nm_tlist.py -i XML_directory [-n USER_TARGET_NAME] [-p USER_PORT_LIST] [-s USER_SERVICE_INFO_LIST]"
    print "    -i: Directory containing the NMap XML files.  This is mandatory."
    print "    -d: Debugging mode.  Default is off"
    print "    -u: UDP mode.  Default is TCP"
    print "    -o: Output findings one line per host IP address. Default is comma separated list of host IP addresses."
    print "    -x: Select Mode.  User selects from the selection of pregenerated target lists."
    print "        The list should be comma separated with no paces or quotes.  Use -l to print the selection."
    print "    -c <int>: User sets size of lists to create. Making large lists easier to import into other tools."
    print "    -n: Name of user created target list.  Requires -p or -s for information on ports or service information."
    print "    -p: List of ports for user created target list.  Requires -n and may be used in conjunction with -s."
    print "        The list should be comma separated with no paces or quotes."
    print "    -s: List of strings for searching service information for user created target lists."
    print "        Requires -n and may be used in conjunction with -p."
    print "        The list should be comma separated with no paces or quotes."
    print "    --help: Seriously?  You are reading it."
    print "    --version: Version of this tool"
    print ""
    sys.exit(2)

# Process options
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:n:p:c:s:x:duolh", ["help","version"])
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
    elif o == "-u":
        TARGS = UDP_TARGS
        PROTO = 'udp'
    elif o == "-o":
        # new line separated output
        COMMA = FALSE
    elif o == "-c":
        # Get the name of user ports list
        COMMA = FALSE
        CHUNK = int(a)
    elif o == "-n":
        # Get the name of user ports list
        USER_NAME = a
    elif o == "-p":
        # Get user port list
        USER_PORTS = a.split(',')
    elif o == "-s":
        # Get user service information list
        USER_SINFO = a.split(',')
    elif o == "-x":
        # Get user service information list
        SELECTED = a.split(',')
    elif o == "-l":
        # user wants a target information list
        print "TCP Target Lists:"
        for ht in TCP_TARGS:
            print "    Name: %s; Description: %s; Ports: %s; Service Info: %s" % (ht[0],ht[1], ','.join(map(str,ht[2])),','.join(map(str,ht[3])))
        print "UDP Target Lists:"
        for ht in UDP_TARGS:
            print "    Name: %s; Description: %s; Ports: %s; Service Info: %s" % (ht[0],ht[1], ','.join(map(str,ht[2])),','.join(map(str,ht[3])))
        sys.exit()

# Test for directory with XML files
if inf == None:
    print "No input directory"
    usage()

# Test for select target lists
selected_list = []
if len(SELECTED):
    for ttmp in TARGS:
        if ttmp[0] in SELECTED:
            selected_list.append(ttmp)
    TARGS = selected_list

# Test for user input target list
if USER_NAME != None:
    if len(USER_PORTS) or len(USER_SINFO):
        # see if user entered port information
        if not len(USER_PORTS): USER_PORTS = []
        # see if user entered service information
        if not len(USER_SINFO): USER_SINFO = []
        # build query list
        USER = ('USER',USER_NAME,USER_PORTS,USER_SINFO)
        TARGS = [USER]
    else:
        usage()

def add_target(in_targ,tList):
    # Test if we have added target
    if not in_targ in tList:
        # We haven't, so add it
        tList.append(in_targ)

def process_service_info(inHost,inPort,sList):
        # Get service information
        s = inHost.get_service(PROTO, inPort)
        if not s == None:
            # just throw them together
            hs = s.name + s.product + s.version
            for r in sList:
                if re.search(r.lower(),hs.lower()):
                    return TRUE

def process_port_info(inPort,pList):
    # Test for port in list
    intPort = int(inPort)
    if intPort in pList:
        return TRUE

def print_target(inTargs,comma):
    # Print list to stardard output
    for tl in inTargs.keys():
        # Only process if we have a list
        if len(inTargs[tl]):
            print "Target List:",tl
            print "Target Count:",len(inTargs[tl])
            if comma:
                # print target IP addresses in comma separated list
                print ','.join(inTargs[tl])
            else:
                if CHUNK > 1:
                    # print target IP address out one per line
                    for IP in range(0,len(inTargs[tl]),CHUNK):
                        print ' '.join(inTargs[tl][IP:IP+CHUNK])
                        print ''    # Add a space between prints
                else:
                    # print target IP address out one per line
                    for IP in inTargs[tl]:
                        print IP
            # Flush
            print "\n"


# Prep ALL_TARG Storage Dictionary
for targ in TARGS:
    ALL_TARGS[targ[1]] = []

# Loop thru NMap XML files
for xfile in glob.glob(inf):
    pr = Parser.Parser(xfile)
    if DEBUG: print xfile

    # Parse this XML file for each target list
    for targ in TARGS:
        # Loop thru each host in file
        for h in pr.all_hosts():

            tt = targ[1]        # Target list name
            tp = targ[2]        # Target list ports
            ts = targ[3]        # Target list service words

            # Loop thru and count all open ports
            for p in h.get_ports(PROTO,'open'):
                # process port list
                if len(tp):
                    add_host = process_port_info(p,tp)
                    if add_host: 
                        break
                # process service information list
                if len(ts):
                    add_host = process_service_info(h,p,ts)
                    if add_host: 
                        break

            # test for new host and add it
            if add_host and not h.ip in ALL_TARGS[tt]:
                ALL_TARGS[tt].append(h.ip)
                # Reset
                add_host = FALSE
                # Move onto next IP address in the xml file
                continue

print_target(ALL_TARGS,COMMA)
