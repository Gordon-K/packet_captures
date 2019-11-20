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
Version: 0.6.0 Nov 20, 2019
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
# Start script session logging
###############################################################################
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

# Printf to log file only
printf_log()
{
	printf "$1" >> "$LOGFILE"
}

# Prints to terminal and log file
printf_shell_log()
{
	printf "$1" | tee -a "$LOGFILE"
}

printf_log "$HELP_VERSION"
START_DATE=$(/bin/date "+%d %b %Y %H:%M:%S %z")
printf_log "Script Started at $START_DATE\n\n"

###############################################################################
# Disk and CPU Monitoring
###############################################################################
function disk_space_check()
{
	while true; do
		DISKCHECK=$(df -P $LOGDIR | grep / | awk '{ print $4 }')
		if (( "$DISKCHECK" < "500000" )); then
			printf_shell_log "\n\nDisk space is now less than 500MB. Stopping script...\n"
			df -h "$LOGDIR"
			kill -15 $$
		fi
	sleep 5
	done
}
disk_space_check &

cpu_check()
{
	while true; do
		CPUCHECK=$(vmstat | tail -1 | awk '{print $15}')
		if (( "$CPUCHECK" < "20" )); then
			printf_shell_log "\n\nCPU utilization is above 80%. Stopping script...\n"
			kill -15 $$
		fi
	sleep 5
	done
}
cpu_check &

###############################################################################
# Functions
###############################################################################
function DisplayScriptLogo()
{
	clear
	printf_shell_log "    ____             __        __     ______            __                \n"
	printf_shell_log "   / __ \____ ______/ /_____  / /_   / ____/___ _____  / /___  __________ \n"
	printf_shell_log "  / /_/ / __ \`/ ___/ //_/ _ \\/ __/  / /   / __ \`/ __ \/ __/ / / / ___/ _ \\ \n"
	printf_shell_log " / ____/ /_/ / /__/ ,< /  __/ /_   / /___/ /_/ / /_/ / /_/ /_/ / /  /  __/\n"
	printf_shell_log "/_/    \__,_/\___/_/|_|\___/\__/   \____/\__,_/ .___/\__/\__,_/_/   \___/ \n"
	printf_shell_log "                                             /_/                          \n"
	printf_shell_log "\n"
	printf_shell_log "==========================================================================\n"
	printf_shell_log "|                     Script Created By: Kyle Gordon                     |\n"
	printf_shell_log "==========================================================================\n"
}

function DisplayInteractiveMenu()
{
	# this will eventually get added
	printf_shell_log "Interactive menu is a WIP..."
}

function ParseUniqueSourceIP()
{
	printf_log "Removing any duplicate source IPs\n"
	# remove duplicates from SOURCE_IP_LIST
	UNIQUE_SOURCE_IPS=($(echo "${SOURCE_IP_LIST[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function ParseUniqueDestinationIP()
{
	printf_log "Removing any duplicate destination IPs\n"
	# remove duplicates from DESTINATION_IP_LIST
	UNIQUE_DESTINATION_IPS=($(echo "${DESTINATION_IP_LIST[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function ParseUniqueInterfaces()
{
	# array of interfaces to filter tcpdump capture with
	USED_INTERFACES=()

	if [ ${#SOURCE_IP_LIST[@]} -gt 0 ]; then
		printf_log "Source IPs found!\n"
		for SOURCE_IP in ${SOURCE_IP_LIST[*]}; do
			printf_log "$SOURCE_IP : "
			INTERFACE="$(ip route get $SOURCE_IP | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
			printf_log "$INTERFACE\n"
			USED_INTERFACES+=("$INTERFACE")
		done
	fi

	if [ ${#DESTINATION_IP_LIST[@]} -gt 0 ]; then
		printf_log "Destination IPs found!"
		for DESTINATION_IP in ${DESTINATION_IP_LIST[*]}; do
			printf_log "$DESTINATION_IP : "
			INTERFACE="$(ip route get $DESTINATION_IP | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
			printf_log "$INTERFACE\n"
			USED_INTERFACES+=("$INTERFACE")
		done
	fi

	printf_log "Removing any duplicate interfaces"
	# remove duplicates from USED_INTERFACES
	TCPDUMP_UNIQUE_INTERFACES=($(echo "${USED_INTERFACES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

function ParseUniquePorts()
{
	printf_log "Removing any duplicate ports\n"
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
	printf_shell_log "Starting tcpdumps\n"
	for i in "${TCPDUMP_SYNTAX[@]}"; do
		printf_shell_log "$i"
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
		printf_log "SecureXL is on\n"
		SecureXLEnabled=$TRUE
		printf_log "SecureXLEnabled: $SecureXLEnabled \n"
	else
		printf_log "SecureXL is off\n"
		SecureXLEnabled=$FALSE
		printf_log "SecureXLEnabled: $SecureXLEnabled \n"
	fi
}

function RunFwMonitorCommands()
{
	printf_shell_log "Starting FW Monitor\n"
	for i in "${FW_MONITOR_SYNTAX[@]}"; do
		printf_shell_log "$i"
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
	printf_shell_log "Starting Kernel Debug\n"
	for i in "${KERNEL_DEBUG_SYNTAX[@]}"; do
		printf_shell_log "$i"
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
		printf_shell_log "Enabling SecureXL\n"
		fwaccel on
	else
		printf_shell_log "SecureXL disabled when script started, leaving it that way\n"
	fi

	# stop kernel debug if it was running
	if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
		printf_log "fw ctl debug 0\n"
		fw ctl debug 0
	fi
}

function ZipAndClean()
{
	printf_shell_log "Creating tarball and cleaning up after myself...\n"
	cd $LOGDIR && tar --exclude='./outputs' -zcvf $OUTPUTFILE .
	rm $LOGDIR/* 2>/dev/null
	printf_shell_log "\n"
	printf_shell_log "File Location: $OUTPUTFILE \n"
	printf_shell_log "Check for updates to this script at: https://github.com/Gordon-K/packet_captures \n"
}
###############################################################################
# Process cleanup AND termination signals
###############################################################################
function interrupted()
{
	printf_shell_log "\n\nScript interrupted, stopping captures and debugs...\n"
	StopCapturesAndDebugs
	ZipAndClean
	printf_shell_log "Cleaning temporary files...\n"
	clean_up # Calling manually and again below
	printf_shell_log "Completed\n"
	exit 1 # Triggers clean_up
}
trap interrupted SIGHUP SIGINT SIGTERM # 1 2 15

function clean_up()
{
	pkill -P $$
	rm $LOGDIR/* 2>/dev/null
}
trap clean_up EXIT

###############################################################################
# Argument handling
###############################################################################
# if script ran with no args 
if [[ $# -eq 0 ]]; then
	DisplayScriptLogo
	printf_shell_log "$HELP_VERSION \n"
	printf_shell_log "$HELP_USAGE \n"
	exit
	# DisplayInteractiveMenu
fi

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h | --help 		) 	# display help info
								DisplayScriptLogo
							  	printf_shell_log "$HELP_USAGE \n"
							  	exit 
							  	;;
		-v | --version  	) 	# display verison info
								DisplayScriptLogo
						  	  	printf_shell_log "$HELP_VERSION \n"
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
								printf_shell_log "Invalid option: -$1 \n" >&2
								printf_shell_log "$HELP_USAGE \n" >&2
								exit 1 
								;;
	esac
done
###############################################################################
# Main
###############################################################################
DisplayScriptLogo				# tell everyone who made this steaming pile of script
if [ "$RUN_TCPDUMP" -eq "$FALSE" ] && [ "$RUN_FW_MONITOR" -eq "$FALSE" ] && [ "$RUN_KDEBUG" -eq "$FALSE" ]; then
	printf_shell_log "No capture or debug was selected, please run the script with one of the following flags: -t, -f, -k\n"
	exit
fi
InitializeLogs					# create $LOGDIR

#
# log information collected from user
# information collected from args or interactive menu
#

# source IP logs
printf_log "\n================================\n"
printf_log "| Source IPs Entered           |\n"
printf_log "================================\n"
if [ -z ${SOURCE_IP_LIST+x} ]; then 
	printf_log "SOURCE_IP_LIST is empty\n"
else
	counter=1
	for i in "${SOURCE_IP_LIST[@]}"; do
		printf_log "Source IP $counter : $i\n"
		counter=$(( counter + 1 ))
	done
	ParseUniqueSourceIP
fi

# destination IP logs
printf_log "\n================================\n"
printf_log "| Destination IPs Entered      |\n"
printf_log "================================\n"
if [ -z ${DESTINATION_IP_LIST+x} ]; then 
	printf_log "DESTINATION_IP_LIST is empty\n"
else
	counter=1
	for i in "${DESTINATION_IP_LIST[@]}"; do
		printf_log "Destination IP $counter : $i\n"
		counter=$(( counter + 1 ))		# increment counter
	done
	ParseUniqueDestinationIP
fi

# port logs
printf_log "\n================================\n"
printf_log "| Ports Entered                |\n"
printf_log "================================\n"
if [ -z ${PORT_LIST+x} ]; then 
	printf_log "PORT_LIST is empty\n"
else
	counter=1
	for i in "${PORT_LIST[@]}"; do
		printf_log "Port $counter : $i\n"
		counter=$(( counter + 1 ))		# increment counter
	done
	ParseUniquePorts
fi

#
# prep tcpdump
#
printf_log "\n================================\n"
printf_log "| tcpdump Prep                 |\n"
printf_log "================================\n"
if [ "$RUN_TCPDUMP" -eq "$TRUE" ]; then
	printf_log "RUN_TCPDUMP: $RUN_TCPDUMP\n"

	ParseUniqueInterfaces

	# confirm that there is an interface that leads to any of the IPs that were provided by the user
	if [ -z ${TCPDUMP_UNIQUE_INTERFACES+x} ]; then 
		printf_log "TCPDUMP_UNIQUE_INTERFACES is empty\n"
	else
		counter=1
		for i in "${TCPDUMP_UNIQUE_INTERFACES[@]}"; do
			printf_log "TCPDUMP_UNIQUE_INTERFACES $counter : $i\n"
			counter=$(( counter + 1 ))		# increment counter
		done
		CreateTcpdumpSourceFilter
		printf_log "TcpdumpSourceFilter: $TcpdumpSourceFilter\n"
		CreateTcpdumpDestinationFilter
		printf_log "TcpdumpDestinationFilter: $TcpdumpDestinationFilter\n"
	fi

	if [ -z ${UNIQUE_PORTS+x} ]; then 
		printf_log "UNIQUE_PORTS is empty\n"
	else
		counter=1
		for i in "${UNIQUE_PORTS[@]}"; do
			printf_log "UNIQUE_PORTS $counter : $i\n"
			counter=$(( counter + 1 ))		# increment counter
		done
		CreateTcpdumpPortFilter
		printf_log "TcpdumpPortFilter: $TcpdumpPortFilter\n"
	fi

	BuildTcpdumpSyntax
	printf_log "tcpdump syntax: \n"
	for i in "${TCPDUMP_SYNTAX[@]}"; do
		printf_log "$SHELL $i\n"
	done

else
	printf_log "RUN_TCPDUMP: $RUN_TCPDUMP\n"
fi

#
# prep fw monitor
#
printf_log "\n================================\n"
printf_log "| FW Monitor Prep              |\n"
printf_log "================================\n"
if [ "$RUN_FW_MONITOR" -eq "$TRUE" ]; then
	printf_log "RUN_FW_MONITOR: $RUN_FW_MONITOR\n"

	# FW Monitor syntax changed from R80.20 take 76 onwards
	#TODO: Create different FW Monitor filters for new and old syntax
	CreateFwMonitorSourceFilter
	CreateFwMonitorDestinationFilter
	CreateFwMonitorPortFilter
	BuildFwMonitorSyntax

	printf_log "FW Monitor syntax: \n"
	for i in "${FW_MONITOR_SYNTAX[@]}"; do
		printf_log "$SHELL $i\n"
	done
else
	printf_log "RUN_FW_MONITOR: $RUN_FW_MONITOR\n"
fi

#
# prep zdebug
#
printf_log "\n================================\n"
printf_log "| Kernel Debug Prep            |\n"
printf_log "================================\n"
if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	printf_log "RUN_KDEBUG: $RUN_KDEBUG\n"
	BuildKernelDebugSyntax
	printf_log "Kernel Debug syntax: \n"
	for i in "${KERNEL_DEBUG_SYNTAX[@]}"; do
		printf_log "$SHELL $i\n"
	done
else
	printf_log "RUN_KDEBUG: $RUN_KDEBUG \n"
fi

#
# start captures and debugs
#
printf_log "\n================================\n"
printf_log "| Run Kernel Debug             |\n"
printf_log "================================\n"
if [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	printf_log "Starting Kernel Debug:\n"
	RunKernelDebugCommands # start kernel debug first cause it takes longest to get up and running
else
	printf_log "No Kernel Debugs set to run, skipping\n"
fi

printf_log "\n================================\n"
printf_log "| Run FW Monitor               |\n"
printf_log "================================\n"
if [ "$RUN_FW_MONITOR" -eq "$TRUE" ]; then

	if [ "$MAJOR_VERSION" != "R80.20" ] || [ "$MAJOR_VERSION" != "R80.30" ];then
		printf_shell_log "SecureXL does need to be disabled for FW Monitor, checking status\n"
		printf_log "MAJOR_VERSION: $MAJOR_VERSION\n"
		CheckSecureXLStatus

		if [ "$SecureXLEnabled" -eq "$TRUE" ]; then
			printf_shell_log "Disabling SecureXL\n"
			fwaccel off
		else
			printf_shell_log "SecureXL already disabled, leaving it that way\n"
		fi
	else
		printf_shell_log "SecureXL does not need to be disabled for FW Monitor, skipping check\n"
		printf_log "MAJOR_VERSION: $MAJOR_VERSION\n"
	fi

	printf_log "Starting FW Monitor:\n"
	RunFwMonitorCommands
else
	printf_log "No FW Monitor capture set to run, skipping\n"
fi

printf_log "\n================================\n"
printf_log "| Run tcpdump                  |\n"
printf_log "================================\n"
if [ "$RUN_TCPDUMP" -eq "$TRUE" ]; then
	printf_log "Starting tcpdump:\n"
	RunTcpdumpCommands
else
	printf_log "No tcpdump captures set to run, skipping\n"
fi

#
# prompt user to enter key to stop captures
#  this only runs if a capture or debug has been set to run
#
printf_log "\n================================\n"
printf_log "| Stopping Captures/Debugs     |\n"
printf_log "================================\n"
if [ "$RUN_TCPDUMP" -eq "$TRUE" ] || [ "$RUN_FW_MONITOR" -eq "$TRUE" ] || [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	printf_shell_log "Captures/Debugs are running!\n"
	printf_shell_log "Press any key to stop captures/debugs\n"
	read -n 1
	printf_shell_log "\n" # blank line to make things look nicer when pressing [the] any key
	printf_shell_log "Stopping Captures/Debugs...\n"
	StopCapturesAndDebugs
	printf_shell_log "Captures/Debugs Stopped\n"
fi

#
# cleanup
#  no point in running this if a capture was not taken
#
printf_log "\n================================\n"
printf_log "| Cleanup                      |\n"
printf_log "================================\n"
if [ "$RUN_TCPDUMP" -eq "$TRUE" ] || [ "$RUN_FW_MONITOR" -eq "$TRUE" ] || [ "$RUN_KDEBUG" -eq "$TRUE" ]; then
	ZipAndClean
fi
