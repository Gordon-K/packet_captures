#!/bin/bash

# Kyle Gordon 
# HE T3 Engineer
# Check Point Software Technologies Ltd.
# 
# Version 0.2.0

###############################################################################
# Functions
###############################################################################
function logo {

echo "    ____             __        __     ______            __                "
echo "   / __ \____ ______/ /_____  / /_   / ____/___ _____  / /___  __________ "
echo "  / /_/ / __ \`/ ___/ //_/ _ \\/ __/  / /   / __ \`/ __ \/ __/ / / / ___/ _ \\"
echo " / ____/ /_/ / /__/ ,< /  __/ /_   / /___/ /_/ / /_/ / /_/ /_/ / /  /  __/"
echo "/_/    \__,_/\___/_/|_|\___/\__/   \____/\__,_/ .___/\__/\__,_/_/   \___/ "
echo "                                             /_/                          "
echo ""
echo "=========================================================================="
echo "|                     Script Created By: Kyle Gordon                     |"
echo "|               This script is not supported by Checkpoint,              |"
echo "|                  it was created because Kyle is lazy.                  |"
echo "=========================================================================="

}

function getTestHost {
	printf "Enter Source IP address: "
	read srcIP
	printf "Enter Destination IP address: "
	read dstIP
	printf "Please enter the amount of time in seconds that you would like these packet captures to run for: "
	read sleepTimer
	printf "If any of the above fields are incorrect then press Ctrl+C to stop this script NOW!\n"
	sleep 5s
}

function findInterfaces {
	findInterfacesCounter=0

	for line in $(ifconfig -a | sed 's/[ \t].*//;/^$/d')
	do 
		array[$findInterfacesCounter]=$line
		findInterfacesCounter=$findInterfacesCounter+1
	done

	for i in ${array[*]}
	do
		if [[ $(ip route get $srcIP) == *$i* ]]; then
			ingress=$i
			echo $i
		elif [[ $(ip route get $dstIP) == *$i* ]]; then
			egress=$i
			echo $i
		fi
	done
}


function startCaptures {
	# Create log file
	touch ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "| Commands ran for packet captures\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt

	printf "Starting Packet Captures...\n"
	printf "Starting Ingress TCPdump on interface ${ingress}\n"
	nohup tcpdump -s 0 -nnei ${ingress} -C 10 -W 100 -w ~/tcpdump-ingress.pcap -Z ${USER} & &> /dev/null
	echo "nohup tcpdump -s 0 -nnei ${ingress} -C 10 -W 100 -w ~/tcpdump-ingress.pcap -Z ${USER} &" >> ~/logs.txt

	printf "Starting Egress TCPdump on interface ${egress}\n"
	nohup tcpdump -s 0 -nnei ${egress} -C 10 -W 100 -w ~/tcpdump-egress.pcap -Z ${USER} & &> /dev/null
	echo "nohup tcpdump -s 0 -nnei ${egress} -C 10 -W 100 -w ~/tcpdump-egress.pcap -Z ${USER} &" >> ~/logs.txt

	printf "Starting FW Monitor\n"
	fwaccel off &> /dev/null
	nohup fw monitor -o ~/fw_mon.pcap & &> /dev/null
	echo "nohup fw monitor -o ~/fw_mon.pcap &" >> ~/logs.txt

	printf "Starting Zdebug drop\n"
	fw ctl zdebug drop &> ~/zdebug.txt & &> /dev/null
	echo "fw ctl zdebug drop &> ~/zdebug.txt &" >> ~/logs.txt
}

function stopCaptures {
	for LINE in $(jobs -p)
	do
		kill ${LINE}
	done
	fwaccel on
}

function cleanup {
	printf "===============================================\n" >> ~/logs.txt
	printf "| IPs Src and Dst\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "Src: ${srcIP}\n" >> ~/logs.txt
	printf "Dst: ${dstIP}\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "| How long were the packet captures taken for?\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "${sleepTimer}s\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "| What interfaces were the tcpdumps taken on?\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "Ingress: ${ingress}\n" >> ~/logs.txt
	printf "Egress:  ${egress}\n" >> ~/logs.txt

	tar -zcvf ~/packet_captures.tgz ~/tcpdump-ingress* ~/tcpdump-egress* ~/fw_mon.pcap ~/zdebug.txt ~/logs.txt &> /dev/null
	rm ~/tcpdump-ingress* ~/tcpdump-egress* ~/fw_mon.pcap ~/zdebug.txt ~/logs.txt ~/nohup.out
	
	# suicide command
	rm -- "$0"
}

###############################################################################
# Main
###############################################################################
clear
logo
getTestHost
findInterfaces
startCaptures
sleep ${sleepTimer}s
stopCaptures
cleanup
