#!/usr/bin/perl
#######################################################
#  Name: 	nmap_xot.pl
#  Version:  	1.0
#  Author:  	Don C. Weber
#  Company: 	Cutaway Security
#  Date: 	03/13/2006
#  Usage: 	nmap_xot.pl {-h -d -i <input directory> -o <output file>]
#  Purpose:	Parse the NMap XML output for open TCP ports
#           	and display them in a human readable format.
#           	Currently the ports are color coded for easy
#           	of use and grouping. Also generates a list of 
#           	targets according to port types (i.e Web,
#           	Telnet, MS, etc.)
#
#  Notes:  	File must be in the same directory as the 
#  	   	XML files being parsed.  The file will
#  	   	output the resulting HTML file to the 
#  	   	same directory.  The -d option is used for
#  	   	debugging.
#
#  Notes:  
#  	  	-d  Debugging mode will output information not
#  	            necessarily required
#  	  	-i  The input directory should contain the XML
#  	            files that need to be parsed.  The value of
#  	            this input will also be used as the output
#  	            directory.  This defaults to the local
#  	            directory.
#  	  	-o  The name of the file to output the results.
#  	            Default is open_ports_nmap_<date>.html
#  	  	-h  Sometimes everybody needs a little help.
#
#  ToDo (no order):
#  	  	1.  Print the host lists to text files for
#  	            new target lists that can be used by
#  	            other tools.
#  	  	2.  Sort the HTML table according to IP
#  	            addresses.  (attempted to do this 
#  	            without very much luck).  The reason
#  	            for the problem is that the incoming
#  	            XML files may include the same IP with
#  	            different results.
#  	  	3.  Update the color codings.  Move from the
#  	            switch statement to a hash of values.
#		4.  Move to style sheet.
#######################################################

use Nmap::Parser;
use Getopt::Std;
use Switch;
use vars qw($DEBUG $prog $date $num_hosts @host_list @finger_target @other_target @ms_target @web_target @telnet_target @mail_target @dns_target @ssh_target @ftp_target);
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

# Process User Input
$prog = $0;
$DEBUG = 0;
$date = ($mon+1) . "." . $mday . "." . (1900+$year);
my %opts = ();
getopts('dhi:o:', \%opts);
usage() if defined $opts{h};
$DEBUG=(defined $opts{d}?1:0);
my $inDir=(defined $opts{i}?$opts{i}. "/":"./");
die usage() unless (-d $inDir);
my $outputFile=(defined $opts{o}?$inDir . "/" . $opts{o}:$inDir . "open_ports_nmap_" . $date . ".html");
die "$prog: Output file $outputFile already exists." if (-e $outputFile);

print "System time: " . $date . ".\n" if $DEBUG;
print "Input directory: " . $inDir . ".\n" if $DEBUG;
print "Outputing file: " . $outputFile . ".\n" if $DEBUG;

my $np = new Nmap::Parser;
my @xmlFiles = ();
my $nmapXML = "";
my $numHosts = 0;
my @newTargets = ();
$num_hosts = 0;

sub usage
{
   print "$prog version 1.0: usage.\n";
   print "$prog [-h -d -i <input directory> -o <output filename>].\n";
   print "   -h - you're looking at it\n";
   print "   -d - debuggin mode - default = off\n";
   print "   -i - location of input directory with NMap XML files - default = ./\n";
   print "   -o - name of html output file - default = open_ports_nmap_<date>.html\n";
   print "        The input directory will be used as the output directory.\n";
   print "\n";
   exit;
}

sub getFileNames
{
   print "In subfunction getFileNames.\n" if $DEBUG;
   #declare local variables
   #my $dir = "./";
   my $dir = shift;
   print "Looking for XML files in " . $dir . ".\n" if $DEBUG;
   my $file = "";
   my @nmapFiles = ();

   #print "Text files in $dir are:\n";
   opendir(BIN, $dir) or die "$prog: Could not open $dir: $!";
   while( defined ($file = readdir BIN) )
   {
      next if $file =~ /^\.\.?$/; # skip . and ..
      next unless $file =~ /\.xml$/; # skip if not an xml file
      print "Found XML file " . $file . ".\n" if $DEBUG;
      push @nmapFiles,$dir . $file;
   } 
   closedir(BIN);
   print "Number of XML files found: " . ($#nmapFiles+1) . ".\n" if $DEBUG;
   die "$prog: Could not find any XML files in $dir.\n" unless ($#nmapFiles+1);
   return @nmapFiles;
}

# print html header to file
# pass in file handle fileHeader(*FH)
sub fileHeader
{
   print "In subfunction fileHeader.\n" if $DEBUG;
   # variables
   my @header;
   my $in = shift;

   push(@header, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");
   push(@header, "<html>\n");
   push(@header, "<head><title>NMAP XML FILES</title></head>\n");
   push(@header, "<body>\n");
   push(@header, "<h1>NMap Discovered Open Ports - " . $date . "</h1>\n");
   push(@header, "The following table contains a list of open TCP ports found on each specific server.\n");

   # Print to file
   print "Contents of \@header.\n" if $DEBUG;
   print join("\n",@header) if $DEBUG;
   print "\n" if $DEBUG;
   print $in @header;
}

# print html footer to file
# pass in file handle fileFooter(*FH)
sub fileFooter
{
   print "In subfunction fileFooter.\n" if $DEBUG;
   # variables
   my @footer;
   my $in = shift;
   my @xmlIN = @_;

   push(@footer, "<h2>Generated from NMAP XML FILES</h2>\n");
   # process each XML file
   foreach $inXML (@xmlIN)
   {
      push(@footer,$inXML . "<BR>\n");
   }
   push(@footer, "<P>Generated using " . $0 . "</P>\n");
   push(@footer,"</body></html>");

   # Print to file
   print "Contents of \@footer.\n" if $DEBUG;
   print join("\n",@footer) if $DEBUG;
   print "\n" if $DEBUG;
   print $in @footer;
}

# print html table header to file
# pass in file handle fileTableH(*FH)
sub fileTableH
{
   print "In subfunction fileTableH.\n" if $DEBUG;
   # variables
   my @table;
   my $in = shift;

   push(@table,"<TABLE border=\"1\"><tr bgcolor=\"black\"><th><font color=\"white\">HOSTS</font></th><th colspan=\"100\"><font color=\"white\">PORTS</font></th></tr>\n");
   #push(@table,"<TABLE border=\"1\"><tr><th>HOSTS</th><th colspan=\"100\">PORTS</th></tr>\n");

   # Print to file
   print "Contents of \@table.\n" if $DEBUG;
   print join("\n",@table) if $DEBUG;
   print "\n" if $DEBUG;
   print $in @table;
}

# print html table footer to file
# pass in file handle fileTableH(*FH)
sub fileTableF
{
   print "In subfunction fileTableF.\n" if $DEBUG;
   # variables
   my @table;
   my $in = shift;

   push(@table,"</TABLE>\n");

   # Print to file
   print "Contents of \@table.\n" if $DEBUG;
   print join("\n",@table) if $DEBUG;
   print "\n" if $DEBUG;
   print $in @table;
}

# print target lists
# pass in file handle fileTargets(*FH)
sub fileTargets
{
   print "In subfunction fileTargets.\n" if $DEBUG;

   # variables
   my $in = shift;
   my @all_targets;
   # don't do anything if you don't have to
   print $in "<P>The number of hosts with open ports " . $numHosts . ".</P>\n";
   print "The number of hosts with open ports " . $numHosts . ".\n" if $DEBUG;
   return if ($numHosts == 0);
   #grab all targets
   push(@all_targets,@other_target,@ms_target,@telnet_target,@ftp_target,@web_target,@ssh_target,@finger_target,@dns_target);

   # input:  output array, target array, target name
   # ALL
   processTargets($in,"ALL",@all_targets);
   # MS
   processTargets($in,"MS",@ms_target);
   # TELNET
   processTargets($in,"TELNET",@telnet_target);
   # WEB
   processTargets($in,"WEB",@web_target);
   # FTP
   processTargets($in,"FTP",@ftp_target);
   # FINGER
   processTargets($in,"FINGER",@finger_target);
   # SSH
   processTargets($in,"SSH",@ssh_target);
   # DNS
   processTargets($in,"DNS",@dns_target);
   # Other
   processTargets($in,"Other",@other_target);

}

# input:  filehandle, target name, target array
sub processTargets
{
   my %seen = ();
   my @outs = "";
   my $fh = shift;
   my $targ_name = shift;
   my @targs = @_;
   # make list unique
   print "Processing " . $targ_name . " targets.\n" if $DEBUG;
   @targs = grep { ! $seen{$_} ++ } @targs;
   my $numtars = @targs;
   unless ($numtars == 0){
      push(@outs,"<P>\n");
      push(@outs, "New " . $targ_name . " targets: " . $numtars . ".<BR>\n");
      print "New " . $targ_name . " targets: " . $numtars . ".\n" if $DEBUG;
      foreach ( @targs )
      {
         push(@outs, $_ . "<BR>\n");
      }
      push(@outs, "</P>\n");
      print "Found the following targets.\n" if $DEBUG;
      print join("\n",@targs) if $DEBUG;
      print "\n" if $DEBUG;
   }
   print $fh @outs;
}

# process each host in each xml file
sub processXML
{

   print "In subfunction processXML.\n" if $DEBUG;
   my $host = shift;
   my @op = $host->tcp_open_ports;
   my $numop = @op;
   my $out_string = "";
   return if ($numop == 0);

   # Build table rows and place in string
   $numHosts++;
   print "Processing host: " . $host->addr . ".\n" if $DEBUG;
   $out_string = $out_string . "<tr><th>" . $host->addr . "<BR>";
   $out_string = $out_string . $host->hostname unless ($host->hostname eq 0);
   $out_string = $out_string . "</th>";
   for my $port ($host->tcp_ports('open')){;
	 switch ($port){
             # Web Safe Colors
             #AQUA BLACK BLUE FUCHSIA GRAY GREEN LIME MAROON 
	     #NAVY OLIVE PURPLE RED SILVER TEAL WHITE YELLOW
	     # Other Named Colors
             #ALICEBLUE ANTIQUEWHITE AQUA AQUAMARINE AZURE
	     #BEIGE BISQUE BLACK BLANCHEDALMOND BLUE BLUEVIOLET
	     #BROWN BURLYWOOD CADETBLUE CHARTREUSE CHOCOLATE
	     #CORAL CORNFLOWERBLUE CORNSILK CRIMSON CYAN DARKBLUE
	     #DARKCYAN DARKGOLDENROD DARKGRAY DARKGREEN DARKKHAKI
	     #DARKMAGENTA DARKOLIVEGREEN DARKORANGE DARKORCHID
	     #DARKRED DARKSALMON DARKSEAGREEN DARKSLATEBLUE
	     #DARKSLATEGRAY DARKTURQUOISE DARKVIOLET DEEPPINK
	     #DEEPSKYBLUE DIMGRAY DODGERBLUE FIREBRICK FLORALWHITE
	     #FORESTGREEN FUCHSIA GAINSBORO GHOSTWHITE GOLD
	     #GOLDENROD GRAY GREEN GREENYELLOW HONEYDEW HOTPINK
	     #INDIANRED INDIGO IVORY KHAKI LAVENDER LAVENDERBLUSH
	     #LAWNGREEN LEMONCHIFFON LIGHTBLUE LIGHTCORAL LIGHTCYAN
	     #LIGHTGOLDENRODYELLOW LIGHTGREEN LIGHTGREY LIGHTPINK
	     #LIGHTSALMON LIGHTSEAGREEN LIGHTSKYBLUE LIGHTSLATEGRAY
	     #LIGHTSTEELBLUE LIGHTYELLOW LIME LIMEGREEN LINEN
	     #MAGENTA MAROON MEDIUMAQUAMARINE MEDIUMBLUE
	     #MEDIUMORCHID MEDIUMPURPLE MEDIUMSEAGREEN MEDIUMSLATEBLUE
	     #MEDIUMSPRINGGREEN MEDIUMTURQUOISE MEDIUMVIOLETRED
	     #MIDNIGHTBLUE MINTCREAM MISTYROSE MOCCASIN NAVAJOWHITE
	     #NAVY OLDLACE OLIVE OLIVEDRAB ORANGE ORANGERED ORCHID
	     #PALEGOLDENROD PALEGREEN PALETURQUOISE PALEVIOLETRED
	     #PAPAYAWHIP PEACHPUFF PERU PINK PLUM POWDERBLUE PURPLE
	     #RED ROSYBROWN ROYALBLUE SADDLEBROWN SALMON SANDYBROWN
	     #SEAGREEN SEASHELL SIENNA SILVER SKYBLUE SLATEBLUE
	     #SLATEGRAY SNOW SPRINGGREEN STEELBLUE TAN TEAL THISTLE
	     #TOMATO TURQUOISE VIOLET WHEAT WHITE WHITESMOKE YELLOW
	     #YELLOWGREEN
	     case 21 { $out_string = $out_string . "<td bgcolor=\"pink\">" ;
		     push(@ftp_target,$host->addr) }
	     case 22 { $out_string = $out_string . "<td bgcolor=\"darkblue\">" ;
		     push(@ssh_target,$host->addr) }
	     case 23 { $out_string = $out_string . "<td bgcolor=\"red\">" ;
		     push(@telnet_target,$host->addr) }
	     case 25 { $out_string = $out_string . "<td bgcolor=\"orange\">" ;
		     push(@mail_target,$host->addr) }
	     case 53 { $out_string = $out_string . "<td bgcolor=\"yellow\">" ;
		     push(@dns_target,$host->addr) }
	     case 79 { $out_string = $out_string . "<td bgcolor=\"red\">" ;
		     push(@finger_target,$host->addr) }
	     case 80 { $out_string = $out_string . "<td bgcolor=\"green\">" ;
		     push(@web_target,$host->addr) }
	     case 135 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 136 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 137 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 138 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 139 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 443 { $out_string = $out_string . "<td bgcolor=\"green\">" ;
		     push(@web_target,$host->addr) }
	     case 445 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 1033 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 3389 { $out_string = $out_string . "<td bgcolor=\"lightblue\">" ;
		     push(@ms_target,$host->addr) }
	     case 8008 { $out_string = $out_string . "<td bgcolor=\"green\">" ;
		     push(@web_target,$host->addr) }
	     case 8080 { $out_string = $out_string . "<td bgcolor=\"green\">" ;
		     push(@web_target,$host->addr) }
	     case 8443 { $out_string = $out_string . "<td bgcolor=\"green\">" ;
		     push(@web_target,$host->addr) }
	     else { $out_string = $out_string . "<td>" ;
	             push(@other_target,$host->addr) }
	 }
         print "   Added port: " . $port . ".\n" if $DEBUG;
         $out_string = $out_string . $port . "<BR>" . $host->tcp_service($port)->name . "<BR>" . $host->tcp_service($port)->product . "</td>";
      }
      $out_string = $out_string . "</tr>\n";

      push(@host_list,$out_string);
   
}

#####################################################################
# Main
#####################################################################
# Get XML files in the current directory
@xmlFiles = getFileNames($inDir);

# Open output file
open(OUTFILE,">$outputFile") || die "$prog: Could not open output file: $!.\n";

# Start output file html
fileHeader(*OUTFILE);

# Start table
fileTableH(*OUTFILE);

# process each XML file
$np->callback(\&processXML);
foreach $nmapXML (@xmlFiles)
{
   print "Processing: $nmapXML\n" if $DEBUG;
   push(@host_list,"<tr><th colspan=100 bgcolor=\"gray\">" . $nmapXML . "</th></tr>");
   $np->parsefile($nmapXML);
}

#print results to file
print OUTFILE @host_list;

# close tabel
fileTableF(*OUTFILE);

# build target lists
fileTargets(*OUTFILE);

# close file html
fileFooter(*OUTFILE,@xmlFiles);

#close output file
close(OUTFILE);
