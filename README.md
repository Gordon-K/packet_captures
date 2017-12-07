# packet_captures
Script to help look for memory leaks on Checkpoint appliances  
## To Use
1. Put Script on GW  
2. Run the following commands from expert mode:  
  `dos2unix packet_captures.sh`  
  `chmod +x packet_captures.sh`  
  `./packet_captures.sh`  
  Script can be run with the following flags:  
  Help Menu: -h --help -help  
  SIM debug: -s --sim-debug  
3. Script will ask for Source and Destination IPs as well as a time in seconds to run
