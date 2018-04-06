#!/bin/bash

# Kyle Gordon
# HE T3 Engineer
# Check Point Software Technologies Ltd.
# Version: 0.4.0
# Last Modified Mar 21, 2018

###############################################################################
# Help Screen
###############################################################################
HELP_USAGE="Usage: $0 [OPTIONS]

Miscellaneous:
	-h    Display this help
	-v    Version information
	-d    Debug this script. a log file named 'script_debug.txt' will be
        	created in the current working directory

Packet Capture Options:
	-a	appi debug	***THIS SHOULD BE DONE DURRING A MAINTENANCE WINDOW***
			This debug should be used if you suspect Application Control is dropping traffic.
			This can be the reason why traffic is dropping on an accept rule.

	-i	ips debug		***THIS SHOULD BE DONE DURRING A MAINTENANCE WINDOW***
	 		This debug should be used if you suspect IPS is dropping traffic.
			This can be the reason why traffic is dropping on an accept rule.

	-s	SecureXL debug	***THIS SHOULD BE DONE DURRING A MAINTENANCE WINDOW***

	-S	This will force SecureXL to stay on during the debugs

	-b	FW Module debug with flags: conn drop vm
"

HELP_VERSION="
Packet Capture Script
Script Created By Kyle Gordon
Version 0.4.0 March 21, 2018
"

while getopts ":hvdaisSb" HELP_OPTION; do
	case "$HELP_OPTION" in
		h) echo "$HELP_USAGE" ; exit ;;
		v) echo "$HELP_VERSION" ; exit ;;
		d) set -vx ; exec &> >(tee script_debug.txt) ;;
		a) DBG_FLAG="a" ;;
		i) DBG_FLAG="i" ;;
		s) DBG_FLAG="s" ;;
		S) DBG_FLAG="S" ;;
		b) DBG_FLAG="b" ;;
		\?) echo "Invalid option: -$OPTARG" >&2
			echo "$HELP_USAGE" >&2 ; exit 1 ;;
	esac
done
shift $(( OPTIND - 1 ))

if [[ "$#" -gt "0" ]]; then
	echo -e "Error: Illegal number of parameters\\n$HELP_USAGE"
	exit 1
fi

###############################################################################
# Functions
###############################################################################
function logo()
{
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
	printf "==========================================================================\n"
}

function getTestHost()
{
	# Create log file
	touch ~/logs.txt
	echo "" > ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "| User Input\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt

	printf "Enter Source IP address: "
	read srcIP
	printf "[ $(date) ] " >> ~/logs.txt
	printf "Enter Source IP address: $srcIP\n" >> ~/logs.txt

	printf "Enter Destination IP address: "
	read dstIP
	printf "[ $(date) ] " >> ~/logs.txt
	printf "Enter Destination IP address: $dstIP\n" >> ~/logs.txt

	printf "Please enter the amount of time in seconds that you would like these packet captures to run for: "
	read sleepTimer
	printf "[ $(date) ] " >> ~/logs.txt
	printf "Please enter the amount of time in seconds that you would like these packet captures to run for: $sleepTimer\n" >> ~/logs.txt

	printf "If any of the above fields are incorrect then press Ctrl+C to stop this script NOW!\n"
	sleep 5s
}

function findInterfaces()
{
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
			if [[ $ingress == "" ]]; then
				printf "Script unable to find correct interface for IP $srcIP\n
				Please enter the name of the interface that $srcIP should enter\n
				the firewall on as it appears in the output of ifconfig\n
				Interface Name: "
				read ingress
			fi
		elif [[ $(ip route get $dstIP) == *$i* ]]; then
			egress=$i
			if [[ $egress == "" ]]; then
				printf "Script unable to find correct interface for IP $dstIP\n
				Please enter the name of the interface that $dstIP should enter\n
				the firewall on as it appears in the output of ifconfig\n
				Interface Name: "
				read egress
			fi
		fi
	done

	printf "===============================================\n" >> ~/logs.txt
	printf "| Interfaces\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt
	printf "Ingress interface is: $ingress\n"
	printf "[ $(date) ] " >> ~/logs.txt
	printf "Ingress interface is: $ingress\n" >> ~/logs.txt
	printf "Egress interface is: $egress\n"
	printf "[ $(date) ] " >> ~/logs.txt
	printf "Egress interface is: $egress\n" >> ~/logs.txt
	printf "If the interfaces above are incorrect the tcpdumps taken will be inaccurate\n"
	sleep 5s
}

function checkSecureXL()
{
	yesno_securexl=$(fwaccel stat | grep -E "Accelerator Status")

	printf "===============================================\n" >> ~/logs.txt
	printf "| SecureXL Initial Status\n" >> ~/logs.txt
	printf "===============================================\n" >> ~/logs.txt

	if [[ $yesno_securexl == *"on"* ]]; then
		printf "SecureXL is on\n"
		printf "[ $(date) ] " >> ~/logs.txt
		printf "SecureXL is on\n" >> ~/logs.txt
		yesno_securexl=1
		printf "[ $(date) ] " >> ~/logs.txt
		printf "yesno_securexl = $yesno_securexl \n" >> ~/logs.txt
	else
		printf "SecureXL is off\n"
		printf "[ $(date) ] " >> ~/logs.txt
		printf "SecureXL is off\n" >> ~/logs.txt
		yesno_securexl=0
		printf "[ $(date) ] " >> ~/logs.txt
		printf "yesno_securexl = $yesno_securexl \n" >> ~/logs.txt
	fi
}

function startCaptures()
{
	printf "===============================================\n" >> ~/logs_"$(date +%m-%d-%Y)".txt
	printf "| Commands ran for packet captures\n" >> ~/logs_"$(date +%m-%d-%Y)".txt
	printf "===============================================\n" >> ~/logs_"$(date +%m-%d-%Y)".txt

	# if SecureXL is on turn it off
	if [[ "$DBG_FLAG" == "S" ]]; then
		printf "Enabling SecureXL\n"
		printf "[ $(date) ] " >> ~/logs.txt
		printf "Enabling SecureXL\n" >> ~/logs.txt
		fwaccel on &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel on &> /dev/null" >> ~/logs.txt
	elif [[ ($yesno_securexl == 1 || $yesno_securexl == 0) && !("$DBG_FLAG" == "s") ]]; then
		printf "Disabling SecureXL\n"
		printf "[ $(date) ] " >> ~/logs.txt
		printf "Disabling SecureXL\n" >> ~/logs.txt
		fwaccel off &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel off &> /dev/null" >> ~/logs.txt
	else
		printf "Enabling SecureXL\n"
		printf "[ $(date) ] " >> ~/logs.txt
		printf "Enabling SecureXL\n" >> ~/logs.txt
		fwaccel on &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel on &> /dev/null" >> ~/logs.txt
	fi

	sleep 1

	printf "Starting Packet Captures...\n"
	printf "Starting Ingress TCPdump on interface ${ingress}\n"
	nohup tcpdump -s 0 -nnei ${ingress} -C 100 -W 10 -w ~/tcpdump-ingress.pcap -Z ${USER} >/dev/null 2>&1 &
	printf "[ $(date) ] " >> ~/logs.txt
	echo "nohup tcpdump -s 0 -nnei ${ingress} -C 100 -W 10 -w ~/tcpdump-ingress.pcap -Z ${USER} >/dev/null 2>&1 &" >> ~/logs.txt

	printf "Starting Egress TCPdump on interface ${egress}\n"
	nohup tcpdump -s 0 -nnei ${egress} -C 100 -W 10 -w ~/tcpdump-egress.pcap -Z ${USER} >/dev/null 2>&1 &
	printf "[ $(date) ] " >> ~/logs.txt
	echo "nohup tcpdump -s 0 -nnei ${egress} -C 100 -W 10 -w ~/tcpdump-egress.pcap -Z ${USER} >/dev/null 2>&1 &" >> ~/logs.txt

	printf "Starting FW Monitor\n"
	printf "[ $(date) ] " >> ~/logs.txt
	printf "Starting FW Monitor\n" >> ~/logs.txt

	nohup fw monitor -o ~/fw_mon.pcap >/dev/null 2>&1 &
	printf "[ $(date) ] " >> ~/logs.txt
	echo "nohup fw monitor -o ~/fw_mon.pcap >/dev/null 2>&1 &" >> ~/logs.txt

	# If user specified a debug flag
	if [[ "$DBG_FLAG" == "s" ]]; then
		printf "Starting Sim Debug\n"
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0" >> ~/logs.txt
		fw ctl debug -buf 32000 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -buf 32000" >> ~/logs.txt
		fw ctl debug -m fw + conn drop tcpstr vm &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -m fw + conn drop tcpstr vm" >> ~/logs.txt
		fwaccel dbg -m general + offload &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel dbg -m general + offload" >> ~/logs.txt
		sim dbg -m pkt all &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "sim dbg -m pkt all" >> ~/logs.txt
		fw ctl kdebug -T -f > ~/sim_debug & &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl kdebug -T -f > ~/sim_debug &" >> ~/logs.txt
	elif [[ "$DBG_FLAG" == "i" ]]; then
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0" >> ~/logs.txt
		fw ctl debug -buf 32000 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -buf 32000" >> ~/logs.txt
		fw ctl debug -m fw + conn drop tcpstr vm aspii spii cmi &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -m fw + conn drop tcpstr vm aspii spii cmi" >> ~/logs.txt
		fw ctl kdebug -T -f > ~/ips_debug & &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl kdebug -T -f > ~/ips_debug &" >> ~/logs.txt
	elif [[ "$DBG_FLAG" == "a" ]]; then
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0" >> ~/logs.txt
		fw ctl debug -buf 32000 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -buf 32000" >> ~/logs.txt
		fw ctl debug -m APPI all &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -m APPI all &> /dev/null" >> ~/logs.txt
		fw ctl kdebug -T -f > ~/appi_debug & &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl kdebug -T -f > ~/appi_debug &" >> ~/logs.txt
	elif [[ "$DBG_FLAG" == "b" ]]; then
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0" >> ~/logs.txt
		fw ctl debug -buf 32000 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -buf 32000" >> ~/logs.txt
		fw ctl debug -m fw + conn drop vm &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug -m fw + conn drop vm &> /dev/null" >> ~/logs.txt
		fw ctl kdebug -T -f > ~/kernel_debug & &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl kdebug -T -f > ~/kernel_debug &" >> ~/logs.txt
	else
		printf "Starting Zdebug drop\n"
		fw ctl zdebug drop &> ~/zdebug.txt & &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl zdebug drop &> ~/zdebug.txt & &> /dev/null" >> ~/logs.txt
	fi

	printf ""

	# Wait for the specified amout of time
	sleep ${sleepTimer}s
}

function stopCaptures()
{
	for LINE in $(jobs -p)
	do
		RIPid="$(ps aux | grep $LINE)"
		kill ${LINE} >/dev/null 2>&1
		printf "[ $(date) ] " >> ~/logs.txt
		echo "kill ${LINE} - $RIPid" >> ~/logs.txt
	done

	# if SecureXL was off already leave it off
	if [[ $yesno_securexl == 1 ]]; then
		printf "Enabling SecureXL\n"
		fwaccel on &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel on &> /dev/null" >> ~/logs.txt
	else
		printf "Disabling SecureXL\n"
		fwaccel off &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel off &> /dev/null" >> ~/logs.txt
	fi

	# If user specified a debug flag
	if [[ "$DBG_FLAG" == "s" ]]; then
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0 &> /dev/null" >> ~/logs.txt
		sim dbg resetall &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "sim dbg resetall &> /dev/null" >> ~/logs.txt
		fwaccel dbg resetall &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fwaccel dbg resetall &> /dev/null" >> ~/logs.txt
	elif [[ "$DBG_FLAG" == "i" ]]; then
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0 &> /dev/null" >> ~/logs.txt
	elif [[ "$DBG_FLAG" == "a" ]]; then
		fw ctl debug 0 &> /dev/null
		printf "[ $(date) ] " >> ~/logs.txt
		echo "fw ctl debug 0 &> /dev/null" >> ~/logs.txt
	fi
}

function cleanup()
{
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
	if [[ $DBG_FLAG != "" ]]; then
		printf "===============================================\n" >> ~/logs.txt
		printf "| What debug flag was used?\n" >> ~/logs.txt
		printf "===============================================\n" >> ~/logs.txt
		echo "${1}" >> ~/logs.txt
	fi

	tar -zcvf ~/packet_captures_"$(date +%m-%d-%Y_%H:%M:%S)".tgz ~/tcpdump-ingress* ~/tcpdump-egress* ~/fw_mon.pcap ~/zdebug.txt ~/logs.txt ~/*_debug &> /dev/null
	rm ~/tcpdump-ingress* ~/tcpdump-egress* ~/fw_mon.pcap ~/zdebug.txt ~/logs.txt ~/*_debug ~/nohup.out &> /dev/null

	printf "Files located in "
	printf ~/packet_captures_"$(date +%m-%d-%Y_%H:%M:%S)".tgz
	printf "\n"
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
stopCaptures $1
cleanup $1
