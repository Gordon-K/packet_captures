#!/bin/bash

# Kyle Gordon
# Diamond Services Engineer
# Check Point Software Technologies Ltd.
# Version: 0.5.5
# Last Modified May 20, 2019

###############################################################################
# Help and Usage Information
###############################################################################
HELP_USAGE="
Usage: $0 [-s <source IP>] [-d <destination IP>] [-p <port>] [-t] [-f] [-k]

Flags:
  [ -s ] : Used to specify source IP for filtering tcpdump and FW Monitor captures. Multiple source IPs can be entered, each IP must be entered in [-s <source IP>] format
  [ -d ] : Used to specify destination IP for filtering tcpdump and FW Monitor captures. Multiple destination IPs can be entered, each IP must be entered in [-d <destination IP>] format
  [ -p ] : Used to specify port for filtering tcpdump and FW Monitor captures. Multiple ports can be entered, each port must be entered in [-p <port>] format
  [ -t ] : Tells script to take a tcpdump on all relevent interfaces based on IPs provided with -s and -d flags. Tcpdump will be filtered according to source IP(s), dedstination IP(s), and port(s) provided to script.
  [ -f ] : Tells script to take a FW Monitor capture. SecureXL will be disabled for captures on versions R80.10 and below. FW Monitor will be filtered according to source IP(s), dedstination IP(s), and port(s) provided to script.
  [ -k ] : Tells script to take Kernel Debugs. Entering only -k flag will default to debugging the fw module with the drop flag (fw ctl debug -m fw + drop). You can select the module and flags that you want to debug by running the -k flag followed by the module and flags in double-quotes like so: -k \"-m fw + drop\".
"

HELP_VERSION="
Packet Capture Script
Script Created By Kyle Gordon
Version: 0.5.5 May 20, 2019
Check for updates to this script at: https://github.com/Gordon-K/packet_captures

"
###############################################################################
# Variables
###############################################################################
# empty arrays to be filled in with user input
SOURCE_IP_LIST=()						# empty array
DESTINATION_IP_LIST=()					# empty array
PORT_LIST=()							# empty array
CUSTOM_KERNEL_DEBUG_MODULE_AND_FLAGS=()	# empty array

# to be or not to be
TRUE=1
FALSE=0

# so we know to run captures/debugs or not
RUN_TCPDUMP=$FALSE
RUN_FW_MONITOR=$FALSE
RUN_KDEBUG=$FALSE

SCRIPT_NAME=($(basename $0))
SHELL="[Expert@$HOSTNAME:$INSTANCE_VSID]#"
DATE=$(date +%m-%d-%Y_h%Hm%Ms%S)
MAJOR_VERSION=$(fw ver | awk '{print $7}')

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
	if (( $(df -P | grep /$ | awk '{ print $4 }') < "2000000" )); then
		if (( $(df -P | egrep "/var$|/var/log$" | awk '{ print $4 }') < "2000000" )); then
			printf "\nThere is not enough disk space available\n"
			printf "Please follow sk60080 to clear disk space\n"
			exit 1
		else
			# Not enough space in root. Enough in /var/log
			LOGDIR="/var/log/tmp/packet_capture_script"
		fi
	else
		# Enough space in root
		LOGDIR="/tmp/packet_capture_script"
	fi

	# Log files and directories
	LOGFILE="$LOGDIR/logs.txt"
	OUTPUTDIR="$LOGDIR/outputs"
	OUTPUTFILE="$OUTPUTDIR/${SCRIPT_NAME}_${DATE}.tgz"

	# create log directory
	printf "Creating log directory: $LOGDIR\n"
	mkdir -p $LOGDIR
	rm $LOGDIR/* 2>/dev/null
	mkdir -p $OUTPUTDIR

	# create log file
	touch $LOGFILE
	printf "" > $LOGFILE
	printf "===============================================\n" >> $LOGFILE
	printf "| User Input\n" >> $LOGFILE
	printf "===============================================\n" >> $LOGFILE
}

function ParseUniqueSourceIP()
{
	echo "Removing any duplicate source IPs" >> $LOGFILE
	# remove duplicates from SOURCE_IP_LIST
	UNIQUE_SOURCE_IPS=($(echo "${SOURCE_IP_LIST[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function ParseUniqueDestinationIP()
{
	echo "Removing any duplicate destination IPs" >> $LOGFILE
	# remove duplicates from DESTINATION_IP_LIST
	UNIQUE_DESTINATION_IPS=($(echo "${DESTINATION_IP_LIST[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function ParseUniqueInterfaces()
{
	# array of interfaces to filter tcpdump capture with
	USED_INTERFACES=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ]; then
		echo "Source IPs found!" >> $LOGFILE
		for SOURCE_IP in ${SOURCE_IP_LIST[*]}; do
			printf "$SOURCE_IP : " >> $LOGFILE
			INTERFACE="$(ip route get $SOURCE_IP | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
			printf "$INTERFACE\n" >> $LOGFILE
			USED_INTERFACES+=("$INTERFACE")
		done
	fi

	if [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		echo "Destination IPs found!" >> $LOGFILE
		for DESTINATION_IP in ${DESTINATION_IP_LIST[*]}; do
			printf "$DESTINATION_IP : " >> $LOGFILE
			INTERFACE="$(ip route get $DESTINATION_IP | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
			printf "$INTERFACE\n" >> $LOGFILE
			USED_INTERFACES+=("$INTERFACE")
		done
	fi

	echo "Removing any duplicate interfaces" >> $LOGFILE
	# remove duplicates from USED_INTERFACES
	TCPDUMP_UNIQUE_INTERFACES=($(echo "${USED_INTERFACES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function ParseUniquePorts()
{
	echo "Removing any duplicate ports" >> $LOGFILE
	# remove duplicates from PORT_LIST
	UNIQUE_PORTS=($(echo "${PORT_LIST[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
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
	for i in `seq 0 ${#UNIQUE_PORTS[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			TcpdumpPortFilter=$TcpdumpPortFilter"port ${UNIQUE_PORTS[$i]}"
			continue
		fi
		# last IP
		if [ $i -eq ${#UNIQUE_PORTS[@]} ]; then 
			TcpdumpPortFilter=$TcpdumpPortFilter")" # )
			break 
		fi
		TcpdumpPortFilter=$TcpdumpPortFilter" or port ${UNIQUE_PORTS[$i]}"
	done
}

function BuildTcpdumpSyntax()
{
	TCPDUMP_SYNTAX=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] &&  [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter and $TcpdumpDestinationFilter and $TcpdumpPortFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter and $TcpdumpDestinationFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
		for UNIQUE_INTERFACE in ${TCPDUMP_UNIQUE_INTERFACES[*]}; do
			TCPDUMP_SYNTAX+=("nohup tcpdump -s 0 -nnei $UNIQUE_INTERFACE \"$TcpdumpSourceFilter and $TcpdumpPortFilter\" -C 100 -W 10 -w $LOGDIR/tcpdump-$UNIQUE_INTERFACE.pcap -Z ${USER} >/dev/null 2>&1 &")
		done
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] && [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
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
	elif [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
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
	for i in `seq 0 ${#UNIQUE_SOURCE_IPS[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			FwMonitorSourceFilter=$FwMonitorSourceFilter"host(${UNIQUE_SOURCE_IPS[$i]})"
			continue
		fi
		# last IP
		if [ $i -eq ${#UNIQUE_SOURCE_IPS[@]} ]; then 
			FwMonitorSourceFilter=$FwMonitorSourceFilter")"
			break 
		fi
		FwMonitorSourceFilter=$FwMonitorSourceFilter" or host(${UNIQUE_SOURCE_IPS[$i]})"
	done
}

function CreateFwMonitorDestinationFilter()
{ 
	FwMonitorDestinationFilter="("
	for i in `seq 0 ${#UNIQUE_DESTINATION_IPS[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			FwMonitorDestinationFilter=$FwMonitorDestinationFilter"host(${UNIQUE_DESTINATION_IPS[$i]})"
			continue
		fi
		# last IP
		if [ $i -eq ${#UNIQUE_DESTINATION_IPS[@]} ]; then 
			FwMonitorDestinationFilter=$FwMonitorDestinationFilter")"
			break 
		fi
		FwMonitorDestinationFilter=$FwMonitorDestinationFilter" or host(${UNIQUE_DESTINATION_IPS[$i]})"
	done
}

function CreateFwMonitorPortFilter()
{ 
	FwMonitorPortFilter="("
	for i in `seq 0 ${#UNIQUE_PORTS[@]}`; do
		# first IP
		if [ $i -eq 0 ]; then
			FwMonitorPortFilter=$FwMonitorPortFilter"port(${UNIQUE_PORTS[$i]})"
			continue
		fi
		# last IP
		if [ $i -eq ${#UNIQUE_PORTS[@]} ]; then 
			FwMonitorPortFilter=$FwMonitorPortFilter")"
			break 
		fi
		FwMonitorPortFilter=$FwMonitorPortFilter" or port(${UNIQUE_PORTS[$i]})"
	done
}

function BuildFwMonitorSyntax()
{
	FW_MONITOR_SYNTAX=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] && [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter and $FwMonitorDestinationFilter and $FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter and $FwMonitorDestinationFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ] && [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter and $FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ] && [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorDestinationFilter and $FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#SOURCE_IP_LIST[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorSourceFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")	
	elif [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorDestinationFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	elif [ ${#UNIQUE_PORTS[@]} -gt 0 ]; then
		FW_MONITOR_SYNTAX+=("fw monitor -e \"$FwMonitorPortFilter, accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	else
		FW_MONITOR_SYNTAX+=("fw monitor -e \"accept;\" -o $LOGDIR/fw_mon.pcap >/dev/null 2>&1 &")
	fi
}

function CheckSecureXLStatus()
{
	SecureXLEnabled=$(fwaccel stat | grep -E "Accelerator Status")

	if [[ $SecureXLEnabled == *"on"* ]]; then
		printf "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] " >> $LOGFILE
		printf "SecureXL is on\n" | tee -a $LOGFILE
		SecureXLEnabled=$TRUE
		printf "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] " >> $LOGFILE
		printf "SecureXLEnabled: $SecureXLEnabled \n" >> $LOGFILE
	else
		printf "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] " >> $LOGFILE
		printf "SecureXL is off\n" | tee -a $LOGFILE
		SecureXLEnabled=$FALSE
		printf "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] " >> $LOGFILE
		printf "SecureXLEnabled: $SecureXLEnabled \n" >> $LOGFILE
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
	# syntax for all kernel debug commands that will be run
	KERNEL_DEBUG_SYNTAX=()

	# add the following lines to the syntax for all kernel debug commands that will be run
	KERNEL_DEBUG_SYNTAX+=("fw ctl debug 0")
	KERNEL_DEBUG_SYNTAX+=("fw ctl debug -buf 32768")

	if [ -z ${CUSTOM_KERNEL_DEBUG_MODULE_AND_FLAGS+x} ]; then
		# if CUSTOM_KERNEL_DEBUG_MODULE_AND_FLAGS is empty
		KERNEL_DEBUG_SYNTAX+=("fw ctl debug -m fw + drop")
	else
		for MODULE_AND_FLAG in "${CUSTOM_KERNEL_DEBUG_MODULE_AND_FLAGS[@]}"; do
			KERNEL_DEBUG_SYNTAX+=("fw ctl debug $MODULE_AND_FLAG")
		done
	fi

	KERNEL_DEBUG_SYNTAX+=("nohup fw ctl kdebug -T -f > $LOGDIR/kdebug.txt 2>&1 &")
}

function RunKernelDebugCommands()
{
	echo "Starting Kernel Debug" | tee -a $LOGFILE
	for i in "${KERNEL_DEBUG_SYNTAX[@]}"; do
		echo "$i" | tee -a $LOGFILE
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

	# check if SecureXL needs to be enabled again or not
	#  in R80.20 SecureXL module was changed (sk151114)
	if ([ "$MAJOR_VERSION" != "R80.20" ] || [ "$MAJOR_VERSION" != "R80.30" ]) && [ "$SecureXLEnabled" == "$TRUE" ];then
		echo "Enabling SecureXL" | tee -a $LOGFILE
		fwaccel on
	else
		echo "SecureXL disabled when script started, leaving it that way" | tee -a $LOGFILE
	fi

	# stop kernel debug if it was running
	if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
		fw ctl debug 0
	fi
}

function ZipAndClean()
{
	echo "Creating tarball and cleaning up after myself..." | tee -a $LOGFILE
	cd $LOGDIR && tar --exclude='./outputs' -zcvf $OUTPUTFILE .
	rm $LOGDIR/* 2>/dev/null
	echo ""
	echo "File Location: $OUTPUTFILE"
	echo "Check for updates to this script at: https://github.com/Gordon-K/packet_captures"
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
								RUN_KDEBUG="$TRUE"
								# check if arg after -k contains spaces
								if [[ "$2" == *"-m"* ]]; then
									CUSTOM_KERNEL_DEBUG_MODULE_AND_FLAGS+=( "$2" )
									shift
									shift
								else
									shift
								fi
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
if [ "$RUN_TCPDUMP" -eq "$FALSE" ] && [ "$RUN_FW_MONITOR" -eq "$FALSE" ] && [ "$RUN_KDEBUG" -eq "$FALSE" ]; then
	echo "No capture or debug was selected, please run the script with one of the following flags: -t, -f, -k"
	exit
fi
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
	ParseUniqueSourceIP
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
	ParseUniqueDestinationIP
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
	ParseUniquePorts
fi

#
# prep tcpdump
#
printf "\n================================\n" >> $LOGFILE
printf "| tcpdump Prep                 |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_TCPDUMP" -eq "$TRUE" ]; then
	echo "RUN_TCPDUMP: $RUN_TCPDUMP" >> $LOGFILE

	ParseUniqueInterfaces

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

	if [ -z ${UNIQUE_PORTS+x} ]; then 
		echo "UNIQUE_PORTS is empty" >> $LOGFILE
	else
		counter=1
		for i in "${UNIQUE_PORTS[@]}"; do
			echo "UNIQUE_PORTS $counter : $i" >> $LOGFILE
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
printf "| FW Monitor Prep              |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_FW_MONITOR" -eq "$TRUE" ]; then
	echo "RUN_FW_MONITOR: $RUN_FW_MONITOR" >> $LOGFILE

	# FW Monitor syntax changed from R80.20 take 76 onwards
	#TODO: Create different FW Monitor filters for new and old syntax
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
printf "| Kernel Debug Prep            |\n" >> $LOGFILE
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
printf "\n================================\n" >> $LOGFILE
printf "| Run Kernel Debug             |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Starting Kernel Debug:" >> $LOGFILE
	RunKernelDebugCommands # start kernel debug first cause it takes longest to get up and running
else
	echo "No Kernel Debugs set to run, skipping" >> $LOGFILE
fi

printf "\n================================\n" >> $LOGFILE
printf "| Run FW Monitor               |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_FW_MONITOR" -eq "$TRUE" ]; then

	if [ "$MAJOR_VERSION" != "R80.20" ] || [ "$MAJOR_VERSION" != "R80.30" ];then
		echo "SecureXL does need to be disabled for FW Monitor, checking status" | tee -a $LOGFILE
		echo "MAJOR_VERSION: $MAJOR_VERSION" >> $LOGFILE
		CheckSecureXLStatus

		if [ "$SecureXLEnabled" -eq "$TRUE" ]; then
			echo "Disabling SecureXL" | tee -a $LOGFILE
			fwaccel off
		else
			echo "SecureXL already disabled, leaving it that way" | tee -a $LOGFILE
		fi
	else
		echo "SecureXL does not need to be disabled for FW Monitor, skipping check" | tee -a $LOGFILE
		echo "MAJOR_VERSION: $MAJOR_VERSION" >> $LOGFILE
	fi

	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Starting FW Monitor:" >> $LOGFILE
	RunFwMonitorCommands
else
	echo "No FW Monitor capture set to run, skipping" >> $LOGFILE
fi

printf "\n================================\n" >> $LOGFILE
printf "| Run tcpdump                  |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_TCPDUMP" -eq "$TRUE" ]; then
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Starting tcpdump:" >> $LOGFILE
	RunTcpdumpCommands
else
	echo "No tcpdump captures set to run, skipping" >> $LOGFILE
fi

#
# prompt user to enter key to stop captures
#  this only runs if a capture or debug has been set to run
#
printf "\n================================\n" >> $LOGFILE
printf "| Stopping Captures/Debugs     |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_TCPDUMP" -eq "$TRUE" ] || [ "$RUN_FW_MONITOR" -eq "$TRUE" ] || [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	echo "Captures/Debugs are running!"
	echo "Press any key to stop captures/debugs"
	read -n 1
	echo "" # blank line to make things look nicer when pressing [the] any key
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Stopping Captures/Debugs..." >> $LOGFILE
	StopCapturesAndDebugs
	echo "[ $(date +%m-%d-%Y_h%Hm%Ms%S) ] Captures/Debugs Stopped" >> $LOGFILE
fi

#
# cleanup
#  no point in running this if a capture was not taken
#
printf "\n================================\n" >> $LOGFILE
printf "| Cleanup                      |\n" >> $LOGFILE
printf "================================\n" >> $LOGFILE
if [ "$RUN_TCPDUMP" -eq "$TRUE" ] || [ "$RUN_FW_MONITOR" -eq "$TRUE" ] || [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	ZipAndClean
fi
