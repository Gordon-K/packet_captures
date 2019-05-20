# packet_captures
Script to assist with taking packet captures on Checkpoint GWs
## To Use
1. Put Script on GW  
2. Run the following commands from expert mode:  
  `dos2unix packet_captures.sh`  
  `chmod +x packet_captures.sh`  
  `./packet_captures.sh`  

### Usage ./packet_captures.sh [-s \<source IP\>] [-d \<destination IP\>] [-p \<port\>] [-t] [-f] [-k]  
 Flag | Description
 --- | ---  
  [ -s ] | Used to specify source IP for filtering tcpdump and FW Monitor captures. Multiple source IPs can be entered, each IP must be entered in [-s \<source IP\>] format  
  [ -d ] | Used to specify destination IP for filtering tcpdump and FW Monitor captures. Multiple destination IPs can be entered, each IP must be entered in [-d \<destination IP\>] format  
  [ -p ] | Used to specify port for filtering tcpdump and FW Monitor captures. Multiple ports can be entered, each port must be entered in [-p \<port\>] format  
  [ -t ] | Tells script to take a tcpdump on all relevent interfaces based on IPs provided with -s and -d flags. Tcpdump will be filtered according to source IP(s), dedstination IP(s), and port(s) provided to script.  
  [ -f ] | Tells script to take a FW Monitor capture. SecureXL will be disabled for captures on versions R80.10 and below. FW Monitor will be filtered according to source IP(s), dedstination IP(s), and port(s) provided to script.  
  [ -k ] | Tells script to take Kernel Debugs. Entering only -k flag will default to debugging the fw module with the drop flag (fw ctl debug -m fw + drop). You can select the module and flags that you want to debug by running the -k flag followed by the module and flags in double-quotes like so: -k \"-m fw + drop\".  

### Eample Usage:
`./packet_captures.sh -s 10.10.0.2 -s 10.10.0.3 -d 8.8.8.8 -d 123.123.123.123 -p 80 -p 443 -t -f -k "-m fw + conn drop vm" -k "-m APPI all"`

#### Runs the following:  
tcpdump commands  
`nohup tcpdump -s 0 -nnei eth0 "(host 10.10.0.2 or host 10.10.0.3) and (host 8.8.8.8 or host 123.123.123.123) and (port 443 or port 80)" -C 100 -W 10 -w /var/log/tmp/packet_capture_script/tcpdump-eth0.pcap -Z admin >/dev/null 2>&1 &`  
`nohup tcpdump -s 0 -nnei eth1.10 "(host 10.10.0.2 or host 10.10.0.3) and (host 8.8.8.8 or host 123.123.123.123) and (port 443 or port 80)" -C 100 -W 10 -w /var/log/tmp/packet_capture_script/tcpdump-eth1.10.pcap -Z admin >/dev/null 2>&1 &`  

FW Monitor commands  
`fw monitor -e "(host(10.10.0.2) or host(10.10.0.3)) and (host(123.123.123.123) or host(8.8.8.8)) and (port(443) or port(80)), accept;" -o /var/log/tmp/packet_capture_script/fw_mon.pcap >/dev/null 2>&1 &`  

Kernel Debug commands  
`fw ctl debug 0`  
`fw ctl debug -buf 32768`  
`fw ctl debug -m fw + conn drop vm`  
`fw ctl debug -m APPI all`  
`nohup fw ctl kdebug -f -o /var/log/tmp/packet_capture_script/kdebug.txt -m 10 -s 100000 >/dev/null 2>&1 &`  
