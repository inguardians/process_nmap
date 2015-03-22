# Process Nmap Scans
Process Nmap Scan Tools to process large and small nmap scans into different formats for reading and importing into other tools.

* nmap_xot.pl - Purpose: Parse the NMap XML output for open TCP ports and display them in a human readable format.  Currently the ports are color coded for easy of use and grouping. Also generates a list of targets according to port types (i.e Web, Telnet, MS, etc.)
* nm_html.py - This script will generate NMap information from an NMap XML File.  The details provided are not as extensive as the individual NMap output.  This output merely contains useful information about the hostname, MAC address, and open TCP or UDP ports.  Users can select a single or list of IP address from a large directory of NMap XML files.  Output goes to standard out for user redirection to an HTML file.  This file can be opened in a browser of the user's choice.
* nm_pcnt.py - This script will parse NMap xml files and output a list of open ports and the count of how many times they were detected.  The script takes one argument, the directory to find the XML files.  It outputs to standard out for user copy or redirection.
* nm_tlist.py - This script will parse NMap xml files and output a list of open ports and the count of how many times they were detected.  The script takes one argument, the directory to find the XML files.  It outputs to standard out for user copy or redirection.

NOTE: These scripts were developed using older versions of HTMLTags and NmapParser. These projects may have been updated since originally used here. For now the code has been included as I imported it originally. If there is interest I can update these projects to ensure they leverage the most recent versions and remove their direct inclusion here. - cutaway
