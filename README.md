# packet_captures
Script to help look for memory leaks on Checkpoint appliances  
## To Use
1. Put Script on GW  
2. Run the following commands from expert mode:  
  `dos2unix packet_captures.sh`  
  `chmod +x chmod +x packet_captures.sh`  
  `./packet_captures.sh`  
3. Script will ask for Source and Destination IPs as well as a time in seconds to run
4. After script finishes it will delete itself and leave behind a file packet_captures.tgz, collect this file and upload to support
