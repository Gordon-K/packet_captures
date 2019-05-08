# packet_captures
Script to assist with taking packet captures on Checkpoint GWs
## To Use
1. Put Script on GW  
2. Run the following commands from expert mode:  
  `dos2unix packet_captures.sh`  
  `chmod +x packet_captures.sh`  
  `./packet_captures.sh`  
Usage ./packet_captures.sh [-s <source IP>] [-d <destination IP>] [-p <port>] [-t] [-f] [-k]  
  
Flags:  
  [ -s ] : Used to specify source IP for filtering tcpdump and FW Monitor captures. Multiple source IPs can be entered, each IP must be entered in [-s <source IP>] format  
  [ -d ] : Used to specify destination IP for filtering tcpdump and FW Monitor captures. Multiple destination IPs can be entered, each IP must be entered in [-d <destination IP>] format  
  [ -p ] : Used to specify port for filtering tcpdump and FW Monitor captures. Multiple ports can be entered, each port must be entered in [-p <port>] format  
  [ -t ] : Tells script to take a tcpdump on all relevent interfaces based on IPs provided with -s and -d flags. Tcpdump will be filtered according to source IP(s), dedstination IP(s), and port(s) provided to script.  
  [ -f ] : Tells script to take a FW Monitor capture. SecureXL will be disabled for captures on versions R77.30 and below. FW Monitor will be filtered according to source IP(s), dedstination IP(s), and port(s) provided to script.  
  [ -k ] : Tells script to take Kernel Debugs. Currently script defaults to '-m fw + drop' kernel debug. This is the same as running 'fw ctl zdebug drop'.  
