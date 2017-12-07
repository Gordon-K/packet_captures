#!/bin/bash

# Kyle Gordon 
# HE T3 Engineer
# Check Point Software Technologies Ltd.
# Version: 0.3.1
# Last Modified Dec 07, 2017

###############################################################################
# Functions
###############################################################################
function help {
if [[ "$1" == "-h"  ||  "$1" == "--help" ||  "$1" == "-help" ]]; then
	clear
	tput bold
	printf "==========================================================================\n"
	printf "|                     Script Created By: Kyle Gordon                     |\n"
	printf "|               This script is not supported by Checkpoint,              |\n"
	printf "|                  it was created because Kyle is lazy.                  |\n"
	printf "==========================================================================\n"
	printf "\n"
	printf "\t Script will ask user to enter in a source IP, destination IP, and amount of time\n"
	printf "\tin seconds that they would like the script to run for"
	printf "\n"
	printf "\t By default the script will collect TCPdumps, FW Monitor, and ZDebug drop. To change\n"
	printf "\tthe default setting use the below flags:\n"
	printf "\n"
	printf "\t-s --sim-debug ***THIS SHOULD BE DONE DURRING A MAINTENANCE WINDOW***
	\t\tDebug commands:
	\t\tDebug Start
	\t\t# fw ctl debug 0
	\t\t# fw ctl debug -buf 32000
	\t\t# fw ctl debug -m fw + conn drop tcpstr vm
	\t\t# fwaccel dbg -m general + offload
	\t\t# sim dbg -m pkt all
	\t\t# fw ctl kdebug -T -f > ~/kernel_debug
	
	\t\tDebug Stop
	\t\t# fw ctl debug 0
	\t\t# sim dbg resetall
	\t\t# fwaccel dbg resetall\n"
	tput sgr0
	exit 0

fi
}

function logo {
	clear
	printf "    ____             __        __     ______            __                \n"
	printf "   / __ \____ ______/ /_____  / /_   / ____/___ _____  / /___  __________ \n"
	printf "  / /_/ / __ \`/ ___/ //_/ _ \\/ __/  / /   / __ \`/ __ \/ __/ / / / ___/ _ \\ \n"
	printf " / ____/ /_/ / /__/ ,< /  __/ /_   / /___/ /_/ / /_/ / /_/ /_/ / /  /  __/\n"
	printf "/_/    \__,_/\___/_/|_|\___/\__/   \____/\__,_/ .___/\__/\__,_/_/   \___/ \n"
	printf "                                             /_/                          \n"
	printf "\n"
	printf "==========================================================================\n"
	printf "|                     Script Created By: Kyle Gordon                     |\n"
	printf "|               This script is not supported by Checkpoint,              |\n"
	printf "|                  it was created because Kyle is lazy.                  |\n"
	printf "==========================================================================\n"
}

function getTestHost {
	if [[ $1 != "" ]]; then
		printf "This script was run with the $1 flag, information about flags can be found by starting the script with the -h flag\n"
	fi
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
			printf "Ingress interface is: $i\n"
		elif [[ $(ip route get $dstIP) == *$i* ]]; then
			egress=$i
			printf "Egress interface is: $i\n"
		fi
	done
}

function checkSecureXL {
	yesno_securexl=$(fwaccel stat | grep -E "Accelerator Status")

	if [[ $yesno_securexl == *"on"* ]]; then
		printf "SecureXL is on\n"
		yesno_securexl=1
	else
		printf "SecureXL is off\n"
		yesno_securexl=0
	fi
}

function startCaptures {
	# Create log file
	touch ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "| Commands ran for packet captures\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt

	printf "Starting Packet Captures...\n"
	printf "Starting Ingress TCPdump on interface ${ingress}\n"
	nohup tcpdump -s 0 -nnei ${ingress} -C 100 -W 10 -w ~/tcpdump-ingress.pcap -Z ${USER} & &> /dev/null
	echo "nohup tcpdump -s 0 -nnei ${ingress} -C 100 -W 10 -w ~/tcpdump-ingress.pcap -Z ${USER} &" >> ~/logs.txt

	printf "Starting Egress TCPdump on interface ${egress}\n"
	nohup tcpdump -s 0 -nnei ${egress} -C 100 -W 10 -w ~/tcpdump-egress.pcap -Z ${USER} & &> /dev/null
	echo "nohup tcpdump -s 0 -nnei ${egress} -C 100 -W 10 -w ~/tcpdump-egress.pcap -Z ${USER} &" >> ~/logs.txt

	# if SecureXL is on turn it off
	if [[ $yesno_securexl == 1 ]]; then
		printf "Disabling SecureXL\n"
		fwaccel off &> /dev/null
	fi

	printf "Starting FW Monitor\n"

	nohup fw monitor -o ~/fw_mon.pcap & &> /dev/null
	echo "nohup fw monitor -o ~/fw_mon.pcap &" >> ~/logs.txt

	# If user specified a debug flag
	if [[ "$1" == "-s"  ||  "$1" == "--sim-debug" ]]; then
		printf "Starting Sim Debug\n"
		fw ctl debug 0 &> /dev/null
		echo "fw ctl debug 0" >> ~/logs.txt
		fw ctl debug -buf 32000 &> /dev/null
		echo "fw ctl debug -buf 32000" >> ~/logs.txt
		fw ctl debug -m fw + conn drop tcpstr vm &> /dev/null
		echo "fw ctl debug -m fw + conn drop tcpstr vm" >> ~/logs.txt
		fwaccel dbg -m general + offload &> /dev/null
		echo "fwaccel dbg -m general + offload" >> ~/logs.txt
		sim dbg -m pkt all &> /dev/null
		echo "sim dbg -m pkt all" >> ~/logs.txt
		fw ctl kdebug -T -f > ~/sim_debug & &> /dev/null
		echo "fw ctl kdebug -T -f > ~/sim_debug &" >> ~/logs.txt
	else 
		printf "Starting Zdebug drop\n"
		fw ctl zdebug drop &> ~/zdebug.txt & &> /dev/null
		echo "fw ctl zdebug drop &> ~/zdebug.txt &" >> ~/logs.txt
	fi
}

function stopCaptures {
	for LINE in $(jobs -p)
	do
		kill ${LINE}
	done

	# if SecureXL was off already leave it off
	if [[ $yesno_securexl == 1 ]]; then
		printf "Enabling SecureXL\n"
		fwaccel on &> /dev/null
	fi

	# If user specified a debug flag
	if [[ "$1" == "-s"  ||  "$1" == "--sim-debug" ]]; then
		fw ctl debug 0 &> /dev/null
		sim dbg resetall &> /dev/null
		fwaccel dbg resetall &> /dev/null
	fi
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

	# If user specified a debug flag
	if [[ "$1" == "-s"  ||  "$1" == "--sim-debug" ]]; then
		printf "===============================================\n" >> ~/logs.txt
		printf "| What debug flag was used?\n" >> ~/logs.txt
		printf "===============================================\n" >> ~/logs.txt
		echo "${1}" >> ~/logs.txt
	fi

	tar -zcvf ~/packet_captures.tgz ~/tcpdump-ingress* ~/tcpdump-egress* ~/fw_mon.pcap ~/zdebug.txt ~/logs.txt ~/*_debug &> /dev/null
	rm ~/tcpdump-ingress* ~/tcpdump-egress* ~/fw_mon.pcap ~/zdebug.txt ~/logs.txt ~/*_debug ~/nohup.out &> /dev/null
}

###############################################################################
# Main
###############################################################################
help $1
logo
getTestHost $1
findInterfaces
checkSecureXL
startCaptures $1
sleep ${sleepTimer}s
stopCaptures $1
cleanup $1
