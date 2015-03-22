#!/usr/bin/env python

###############################################
# Name: nm_pcnt.py
# Version: 0.1
# Company: InGuardians, Inc.
# Start Date: March 26, 2011
#
# Purpose:
#   This script will parse NMap xml files and output a list of
#   open ports and the count of how many times they were detected.
#   The script takes one argument, the directory to find the XML
#   files.  It outputs to standard out for user copy or redirection.
#
# Developers: 
#   Cutaway (Don C. Weber)
#
# Resources:
#   http://code.google.com/p/python-nmap-parser/
#   http://nmap.org/
#
# TODO:
#
# Change Log:
#
############################################

# Import useful modules
import sys, os, glob, getopt, operator

# Setup NmapParser module for import
nmp = os.getcwd() + "/NmapParser"
sys.path.append(nmp)
import Parser

# Variables
VERSION     = '0.1'
FALSE       = 0
TRUE        = 1
inf         = None      # Input directory
pdic        = {}       # Port storage
PROTO       = 'tcp'   # Protocol 
MODE        = 0        # Mode 0 == Top 20 ports, 1 == all ports
OUTSUM      = FALSE  # Print the sum of open ports

# Help statement
def usage():
    print "NMap Port Count Version: " + VERSION
    print "Usage:\nnm_pcnt.py -i XML_directory [-d] [-a] [-u] [-s] [-h] [--help] [--version]"
    print "    -i: Directory containing the NMap XML files.  This is mandatory."
    print "    -d: Debugging mode.  Default is off"
    print "    -a: Print all mode.  Default is print top twenty ports"
    print "    -u: UDP mode.  Default is TCP"
    print "    -s: Print the sum of all ports. Default off"
    print "    --help: Seriously?  You are reading it."
    print "    --version: Version of this tool"
    sys.exit(2)

# Process options
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:duash", ["help","version"])
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
        PROTO = 'udp'
    elif o == "-s":
        OUTSUM = TRUE
    elif o == "-a":
        # Print all ports. Default is top 20
        MODE = 1

# Test for XML directory
if inf == None:
    usage()

# Loop thru NMap XML files
for xfile in glob.glob(inf):
    pr = Parser.Parser(xfile)

    # Loop thru each host in file
    for h in pr.all_hosts():

        # Loop thru and count all open ports
        for p in h.get_ports(PROTO,'open'):
            if p in pdic.keys():
                # if we have seen it increment
                pdic[p] = pdic[p] + 1
            else:
                # if we have not seen it then add it
                # dictionary key does not work as int for some reason
                pdic[p] = 1

# Sort list of ports
plist = pdic.keys()
for n in range(len(plist)):
    # convert port number from string to int
    plist[n] = int(plist[n])
plist.sort()

# Print sum of open ports
SUM = sum(pdic.values())
if OUTSUM:
    print "Sum of open ports:",SUM

# Test for results
if not SUM:
    sys.exit()

# Print to standard output
if MODE:
    # Print all
    print "Port\tCount"
    for k in plist:
        print k,"\t",pdic[str(k)]
else:
    sorted_list = sorted(pdic.iteritems(), key=operator.itemgetter(1))
    # Print top twenty
    cnt = 20
    sorted_list.reverse()
    print "Port\tCount\tPercent"
    for k in sorted_list:
        #print k,"\t",pdic[str(k)],"\t",float(pdic[str(k)])/SUM
        print "%s%s%s%s%.2f" % (k[0],"\t",k[1],"\t",(100 * float(k[1])/SUM) )
        cnt -= 1
        if not cnt:
            break

