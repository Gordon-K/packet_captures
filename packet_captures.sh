#!/bin/bash

# Kyle Gordon
# Diamond Services Engineer
# Check Point Software Technologies Ltd.
# Version: 0.5.1
# Last Modified May 07, 2019

###############################################################################
# Help and Usage Information
###############################################################################
HELP_USAGE="
Usage: $0 [-s|--source <source IP>] [-s|--destination <destination IP>] [-p|--port <port>] [-t|--tcpdump] [-f|--fw_mon] [-k|--kernel_debug]

"

HELP_VERSION="
Packet Capture Script
Script Created By Kyle Gordon
Version: 0.5.1 May 07, 2019

"
###############################################################################
# Variables
###############################################################################
SOURCE_IP_LIST=()		# empty array
DESTINATION_IP_LIST=()	# empty array
PORT_LIST=()			# empty array

TRUE=1
FALSE=0

RUN_TCPDUMP=$FALSE
RUN_FW_MONITOR=$FALSE
RUN_KDEBUG=$FALSE

SHELL="[Expert@$HOSTNAME:$INSTANCE_VSID]#"
DATE=$(date +%m-%d-%Y_h%Hm%Ms%S)

LOGDIR="/var/log/tmp/packet_capture_script"
LOGFILE="$LOGDIR/logs.txt"
OUTPUTDIR="/var/log/tmp/packet_capture_script/outputs"
OUTPUTFILE="$OUTPUTDIR/$SCRIPT_NAME_$DATE.tgz"
###############################################################################
# Functions
###############################################################################
function DisplayScriptLogo()
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

function DisplayInteractiveMenu()
{
	# this will eventually get added
	echo "Interactive menu is a WIP..."
}

function InitializeLogs()
{
	# create log directory
	printf "Creating log directory: $LOGDIR\n"
	mkdir -p $LOGDIR
	rm $LOGDIR/* 2>/dev/null
	mkdir -p $OUTPUTDIR

	# create log file
	touch $LOGDIR/logs.txt
	printf "" > $LOGFILE
	printf "===============================================\n" >> $LOGFILE
	printf "| User Input\n" >> $LOGFILE
	printf "===============================================\n" >> $LOGFILE
}

function GetDeviceInterfaces()
{
	NUMBER_OF_INTERFACES=0

	for line in $(ifconfig -a | sed 's/[ \t].*//;/^$/d'); do
		LIST_OF_INTERFACES[$NUMBER_OF_INTERFACES]=$line
		NUMBER_OF_INTERFACES=$NUMBER_OF_INTERFACES+1
	done
}

function ParseUniqueInterfacesAndPorts()
{
	# array of interfaces to filter tcpdump capture with
	USED_INTERFACES=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ]; then
		echo "Source IPs found!" >> $LOGFILE
		for SOURCE_IP in ${SOURCE_IP_LIST[*]}; do
			printf "$SOURCE_IP : " >> $LOGFILE
			for INTERFACE in ${LIST_OF_INTERFACES[*]}; do
				if [[ $(ip route get $SOURCE_IP) == *$INTERFACE* ]]; then
					INTERFACE=$( echo "$INTERFACE" | sed 's/\..*$//'  ) # remove VLAN tags
					printf "$INTERFACE\n" >> $LOGFILE
					USED_INTERFACES+=("$INTERFACE")
				fi
			done
		done
	fi

	if [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		echo "Destination IPs found!" >> $LOGFILE
		for DESTINATION_IP in ${DESTINATION_IP_LIST[*]}; do
			printf "$DESTINATION_IP : " >> $LOGFILE
			for INTERFACE in ${LIST_OF_INTERFACES[*]}; do
				if [[ $(ip route get $DESTINATION_IP) == *$INTERFACE* ]]; then
					INTERFACE=$( echo "$INTERFACE" | sed 's/\..*$//'  ) # remove VLAN tags
					printf "$INTERFACE\n" >> $LOGFILE
					USED_INTERFACES+=("$INTERFACE")
				fi
			done
		done
	fi

	# remove duplicates from USED_INTERFACES
	TCPDUMP_UNIQUE_INTERFACES=($(echo "${USED_INTERFACES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

	# array or ports to filter tcpdump capture with
	USED_PORTS=()
	if [ ${#PORT_LIST[@]} -gt 0 ]; then
		echo "Ports found!" >> $LOGFILE
		for PORT in ${PORT_LIST[*]}; do
		echo "$PORT" >> $LOGFILE
			USED_PORTS+=("$PORT")
		done
	fi

	# remove duplicates from USED_PORTS
	TCPDUMP_UNIQUE_PORTS=($(echo "${USED_PORTS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function CreateTcpdumpSourceFilter()
{ 
	TcpdumpSourceFilter="(" # (
	for i in `seq 0 ${#SOURCE_IP_LIST[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			TcpdumpSourceFilter=$TcpdumpSourceFilter"host ${SOURCE_IP_LIST[$i]}"
			continue
		fi
		# last IP
		if [ $i -eq ${#SOURCE_IP_LIST[@]} ]; then 
			TcpdumpSourceFilter=$TcpdumpSourceFilter")" # )
			break 
		fi
		TcpdumpSourceFilter=$TcpdumpSourceFilter" or host ${SOURCE_IP_LIST[$i]}"
	done
}

function CreateTcpdumpDestinationFilter()
{ 
	TcpdumpDestinationFilter="(" # (
	for i in `seq 0 ${#DESTINATION_IP_LIST[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			TcpdumpDestinationFilter=$TcpdumpDestinationFilter"host ${DESTINATION_IP_LIST[$i]}"
			continue
		fi
		# last IP
		if [ $i -eq ${#DESTINATION_IP_LIST[@]} ]; then 
			TcpdumpDestinationFilter=$TcpdumpDestinationFilter")" # )
			break 
		fi
		TcpdumpDestinationFilter=$TcpdumpDestinationFilter" or host ${DESTINATION_IP_LIST[$i]}"
	done
}

function CreateTcpdumpPortFilter()
{ 
	TcpdumpPortFilter="(" # (
	for i in `seq 0 ${#TCPDUMP_UNIQUE_PORTS[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			TcpdumpPortFilter=$TcpdumpPortFilter"port ${TCPDUMP_UNIQUE_PORTS[$i]}"
			continue
		fi
		# last IP
		if [ $i -eq ${#TCPDUMP_UNIQUE_PORTS[@]} ]; then 
			TcpdumpPortFilter=$TcpdumpPortFilter")" # )
			break 
		fi
		TcpdumpPortFilter=$TcpdumpPortFilter" or port ${TCPDUMP_UNIQUE_PORTS[$i]}"
	done
}

function BuildTcpdumpSyntax()
{
	TCPDUMP_SYNTAX=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] &&  [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter and $TcpdumpDestinationFilter and $TcpdumpPortFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter and $TcpdumpDestinationFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter and $TcpdumpPortFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] && [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpDestinationFilter and $TcpdumpPortFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done	
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpDestinationFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		# 'any' interface is used if only port is entered because there's no IP to get an interface from
		#  this may be more intensive and should probably have a warning attached
		#  TODO: add warning
		TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei any \"$TcpdumpPortFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-ports.pcap -Z ${USER} >/dev/null 2>&1 &")
	else
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	fi
}

function RunTcpdumpCommands()
{
	echo "Starting tcpdumps"
	for i in "${TCPDUMP_SYNTAX[@]}"; do
		eval $i # run command
	done
}

function CreateFwMonitorSourceFilter()
{ 
	FwMonitorSourceFilter="("
	for i in `seq 0 ${#SOURCE_IP_LIST[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			FwMonitorSourceFilter=$FwMonitorSourceFilter"host(${SOURCE_IP_LIST[$i]})"
			continue
		fi
		# last IP
		if [ $i -eq ${#SOURCE_IP_LIST[@]} ]; then 
			FwMonitorSourceFilter=$FwMonitorSourceFilter")"
			break 
		fi
		FwMonitorSourceFilter=$FwMonitorSourceFilter" or host(${SOURCE_IP_LIST[$i]})"
	done
}

function CreateFwMonitorDestinationFilter()
{ 
	FwMonitorDestinationFilter="("
	for i in `seq 0 ${#DESTINATION_IP_LIST[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			FwMonitorDestinationFilter=$FwMonitorDestinationFilter"host(${DESTINATION_IP_LIST[$i]})"
			continue
		fi
		# last IP
		if [ $i -eq ${#DESTINATION_IP_LIST[@]} ]; then 
			FwMonitorDestinationFilter=$FwMonitorDestinationFilter")"
			break 
		fi
		FwMonitorDestinationFilter=$FwMonitorDestinationFilter" or host(${DESTINATION_IP_LIST[$i]})"
	done
}

function CreateFwMonitorPortFilter()
{ 
	FwMonitorPortFilter="("
	for i in `seq 0 ${#TCPDUMP_UNIQUE_PORTS[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			FwMonitorPortFilter=$FwMonitorPortFilter"port(${TCPDUMP_UNIQUE_PORTS[$i]})"
			continue
		fi
		# last IP
		if [ $i -eq ${#TCPDUMP_UNIQUE_PORTS[@]} ]; then 
			FwMonitorPortFilter=$FwMonitorPortFilter")"
			break 
		fi
		FwMonitorPortFilter=$FwMonitorPortFilter" or port(${TCPDUMP_UNIQUE_PORTS[$i]})"
	done
}

function BuildFwMonitorSyntax()
{
	FW_MONITOR_SYNTAX=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] &&  [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter and $FwMonitorDestinationFilter and $FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter and $FwMonitorDestinationFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter and $FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] && [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorDestinationFilter and $FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")	
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorDestinationFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#TCPDUMP_UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	else
		FW_MONITOR_SYNTAX+=("fw monitor -e \"accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	fi
}

# working on this
function CheckSecureXLStatus()
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

function RunFwMonitorCommands()
{
	echo "Starting FW Monitor"
	for i in "${FW_MONITOR_SYNTAX[@]}"; do
		eval $i # run command
	done
}

function BuildKernelDebugSyntax()
{
	KERNEL_DEBUG_SYNTAX=()

	KERNEL_DEBUG_SYNTAX+=("fw ctl debug 0")
	KERNEL_DEBUG_SYNTAX+=("fw ctl debug -buf 32768")
	KERNEL_DEBUG_SYNTAX+=("fw ctl debug -m fw + drop")
	KERNEL_DEBUG_SYNTAX+=("nohup fw ctl kdebug -f -o $LOGDIR/kdebug.txt -m 10 -s 100000 >/dev/null 2>&1 &")
}

function RunKernelDebugCommands()
{
	echo "Starting Kernel Debug"
	for i in "${KERNEL_DEBUG_SYNTAX[@]}"; do
		eval $i # run command
	done
}

function StopCapturesAndDebugs()
{
	# kill all processes spawned by this script
	for LINE in $(jobs -p); do
		RIPid="$(ps aux | grep $LINE)"
		kill ${LINE} >/dev/null 2>&1
	done

	# remove all kernel debug flags
	fw ctl debug 0
}

function ZipAndClean()
{
	tar --exclude="$OUTPUTDIR" -zcvf $OUTPUTFILE $LOGDIR/*
	rm $LOGDIR/* 2>/dev/null
	DisplayScriptLogo
	echo "File Location: $OUTPUTFILE"
	echo "Check for updates at: https://github.com/Gordon-K/packet_captures"
}
###############################################################################
# Argument handling
###############################################################################
# if script ran with no args 
if [[ $# -eq 0 ]]; then
	DisplayScriptLogo
	echo "$HELP_VERSION"
	echo "$HELP_USAGE"
	exit
	# DisplayInteractiveMenu
fi

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h | --help 		) 	# display help info
								DisplayScriptLogo
							  	echo "$HELP_USAGE"
							  	exit 
							  	;;
		-v | --version  	) 	# display verison info
								DisplayScriptLogo
						  	  	echo "$HELP_VERSION"
						  	  	exit 
						  	  	;;
		-s | --source		) 	# add one or more source IPs to filter captures by
								SOURCE_IP_LIST+=( $2 )
								shift
								shift
						  	  	;;
		-d | --destination	) 	# add one or more destination IPs to filter captures by
								DESTINATION_IP_LIST+=( $2 )
								shift
								shift
						  	  	;;
		-p | --port			) 	# add one or more ports to filter captures by
								PORT_LIST+=( $2 )
								shift
								shift
						  	  	;;
		-t | --tcpdump		) 	# enable tcpdump
								RUN_TCPDUMP="$TRUE"
								shift
						  	  	;;
		-f | --fw_mon		) 	# enable FW Monitor
								RUN_FW_MONITOR="$TRUE"
								shift
						  	  	;;
		-k | --kernel_debug	) 	# enable kernel debug
								# will replace '-zdebug | --zdebug'
								RUN_KDEBUG="$TRUE"
								shift
						  	  	;;
		* 					) 	# invalid arg used
								echo "Invalid option: -$1" >&2
								echo "$HELP_USAGE" >&2
								exit 1 
								;;
	esac
done
###############################################################################
# Main
###############################################################################
DisplayScriptLogo				# tell everyone who made this steaming pile of script
InitializeLogs					# create $LOGDIR

#
# log information collected from user
# information collected from args or interactive menu
#

# source IP logs
printf "\n================================\n" >> $LOGFILE
printf "| Source IPs Entered           |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ -z ${SOURCE_IP_LIST+x} ]; then 
	echo "SOURCE_IP_LIST is empty" >> $LOGFILE
else
	counter=1
	for i in "${SOURCE_IP_LIST[@]}"; do
		echo "Source IP $counter : $i" >> $LOGFILE
		counter=$(( counter + 1 ))
	done
	
fi

# destination IP logs
printf "\n================================\n" >> $LOGFILE
printf "| Destination IPs Entered      |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ -z ${DESTINATION_IP_LIST+x} ]; then 
	echo "DESTINATION_IP_LIST is empty" >> $LOGFILE
else
	counter=1
	for i in "${DESTINATION_IP_LIST[@]}"; do
		echo "Destination IP $counter : $i" >> $LOGFILE
		counter=$(( counter + 1 ))		# increment counter
	done
fi

# port logs
printf "\n================================\n" >> $LOGFILE
printf "| Ports Entered                |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ -z ${PORT_LIST+x} ]; then 
	echo "PORT_LIST is empty" >> $LOGFILE
else
	counter=1
	for i in "${PORT_LIST[@]}"; do
		echo "Port $counter : $i" >> $LOGFILE
		counter=$(( counter + 1 ))		# increment counter
	done
fi

#
# prep tcpdump
#
printf "\n================================\n" >> $LOGFILE
printf "| tcpdump                      |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_TCPDUMP" -eq "$TRUE" ]; then
	echo "RUN_TCPDUMP: $RUN_TCPDUMP" >> $LOGFILE

	GetDeviceInterfaces
	ParseUniqueInterfacesAndPorts

	# confirm that there is an interface that leads to any of the IPs that were provided by the user
	if [ -z ${TCPDUMP_UNIQUE_INTERFACES+x} ]; then 
		echo "TCPDUMP_UNIQUE_INTERFACES is empty" >> $LOGFILE
	else
		counter=1
		for i in "${TCPDUMP_UNIQUE_INTERFACES[@]}"; do
			echo "TCPDUMP_UNIQUE_INTERFACES $counter : $i" >> $LOGFILE
			counter=$(( counter + 1 ))		# increment counter
		done
		CreateTcpdumpSourceFilter
		echo "TcpdumpSourceFilter: $TcpdumpSourceFilter" >> $LOGFILE
		CreateTcpdumpDestinationFilter
		echo "TcpdumpDestinationFilter: $TcpdumpDestinationFilter" >> $LOGFILE
	fi

	if [ -z ${TCPDUMP_UNIQUE_PORTS+x} ]; then 
		echo "TCPDUMP_UNIQUE_PORTS is empty" >> $LOGFILE
	else
		counter=1
		for i in "${TCPDUMP_UNIQUE_PORTS[@]}"; do
			echo "TCPDUMP_UNIQUE_PORTS $counter : $i" >> $LOGFILE
			counter=$(( counter + 1 ))		# increment counter
		done
		CreateTcpdumpPortFilter
		echo "TcpdumpPortFilter: $TcpdumpPortFilter" >> $LOGFILE
	fi

	BuildTcpdumpSyntax
	echo "tcpdump syntax: " >> $LOGFILE
	for i in "${TCPDUMP_SYNTAX[@]}"; do
		echo "$SHELL $i" >> $LOGFILE
	done

else
	echo "RUN_TCPDUMP: $RUN_TCPDUMP" >> $LOGFILE
fi

#
# prep fw monitor
#
printf "\n================================\n" >> $LOGFILE
printf "| FW Monitor                   |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_FW_MONITOR" -eq "$TRUE" ]; then
	echo "RUN_FW_MONITOR: $RUN_FW_MONITOR" >> $LOGFILE

	CreateFwMonitorSourceFilter
	CreateFwMonitorDestinationFilter
	CreateFwMonitorPortFilter
	BuildFwMonitorSyntax

	echo "FW Monitor syntax: " >> $LOGFILE
	for i in "${FW_MONITOR_SYNTAX[@]}"; do
		echo "$SHELL $i" >> $LOGFILE
	done
else
	echo "RUN_FW_MONITOR: $RUN_FW_MONITOR" >> $LOGFILE
fi

#
# prep zdebug
#
printf "\n================================\n" >> $LOGFILE
printf "| Kernel Debug                 |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	echo "RUN_KDEBUG: $RUN_KDEBUG" >> $LOGFILE
	BuildKernelDebugSyntax
	echo "Kernel Debug syntax: " >> $LOGFILE
	for i in "${KERNEL_DEBUG_SYNTAX[@]}"; do
		printf "$SHELL $i\n" >> $LOGFILE
	done
else
	echo "RUN_KDEBUG: $RUN_KDEBUG" >> $LOGFILE
fi

#
# start captures and debugs
#
if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Starting Kernel Debug:" >> $LOGFILE
	RunKernelDebugCommands # start kernel debug first cause it takes longest to get up and running
fi

if [ "$RUN_TCPDUMP" -eq "$TRUE" ]; then
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Starting tcpdump:" >> $LOGFILE
	RunTcpdumpCommands
fi

if [ "$RUN_FW_MONITOR" -eq "$TRUE" ]; then
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Starting FW Monitor:" >> $LOGFILE
	RunFwMonitorCommands
fi

#
# prompt user to enter key to stop captures
#  this only runs if a capture or debug has been set to run
#
if [ "$RUN_TCPDUMP" -eq "$TRUE" ] || [ "$RUN_FW_MONITOR" -eq "$TRUE" ] || [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	echo "Captures/Debugs are running!"
	echo "Press any key to stop captures/debugs"
	read -n 1
	StopCapturesAndDebugs
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Captures/Debugs Stopped:" >> $LOGFILE
fi

#
# cleanup
#  no point in running this if a capture was not taken
#
if [ "$RUN_TCPDUMP" -eq "$TRUE" ] || [ "$RUN_FW_MONITOR" -eq "$TRUE" ] || [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	ZipAndClean
fi
