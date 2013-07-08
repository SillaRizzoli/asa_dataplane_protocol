Disclaimer:
This program is not sponsored or endorsed by Cisco Systems in any way. It's
just a little script that I wrote for my own convenience and it's released
in the hope that it will be useful and that people will improve it for the
benefit of everyone. I'm pretty sure that it's full of bugs and badly written
code so, if you decide to use it, it's entirely at your own risk.

What this plugin does:
This Wireshark plugin is meant to decode the pcap files created by Cisco ASA
Firewall "capture" command when used with the asa_dataplane switch; this switch
instructs the ASA to capture traffic that is being redirected from the ASA to
another hardware module (and back again, usually), for example an IPS sensor or
the CSC module from Trendmicro. This command creates perfectly valid pcap
files, however it inserts a protocol unknown to Wireshark, making the capture
file pretty useless unless you are fluent in reading the matrix.

So I reverse-engineered the protocol (not all of it, many details still escape
me) and wrote this plugin; the protocol looks pretty simple:

The lowest layer protocol is Ethernet II; this however is not the original
frame, but an encapsulation. The source and destination mac addresses have only
two valid values, 00:00:00:01:00:02 and 00:00:00:02:00:02; my guess is that one
identifies the ASA and the other the module. This ethernet frame ends with the
ethertype field, which is always set to 0x855e; this ethertype number is not
officialy registered, but it identifies what I called the asa_dataplane
protocol; this header can be 16 or 20 bytes long and after that comes the
original ethernet frame.

So, the structure of the asa_dataplane pcap file is:
"Fake" Ethernet II frame
ASA Dataplane Header (ethertype 0x855e)
Original Ethernet II frame
IP or IPv6

How to install:
Copy the asa_dataplane.lua file to the plugins directory for
your version of wireshark; for example, on Windows and for wireshark version
1.10 the directory is C:\Program Files\Wireshark\plugins\1.10.0

How to use: after installing the file, launch wireshark and open a .pcap
file captured on a Cisco ASA firewall with the asa_dataplane capture command
switch.


