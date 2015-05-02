#!/bin/bash

load_config()
{
	CONFIG="/usr/local/ddos/ddos_detector.config"
	# Check if the file exists
	if [ -f "$CONFIG" ] && [ ! "$CONFIG" ==	"" ]; then
		head
		# read the variables from the file
		source $CONFIG
	else
		head
		echo "\$CONFIG file not found."
		exit 1
	fi
}

# Print info (not-important)
head()
{
	echo
	echo "DDoS-Detector (version 1.0)"
	echo "Detect & Block DDoS Attacks"
	echo "Handle TCP, UDP, ICMP Attacks"
	echo
}

unbanip()
{
	UNBAN_SCRIPT=`mktemp /tmp/unban.XXXXXXXX`
	TMP_FILE=`mktemp /tmp/unban.XXXXXXXX`
	UNBAN_IP_LIST=`mktemp /tmp/unban.XXXXXXXX`
	echo '#!/bin/bash' > $UNBAN_SCRIPT
	echo "sleep $BAN_PERIOD" >> $UNBAN_SCRIPT

	while read line; do
		echo "$IPT -D INPUT -s $line -j DROP" >> $UNBAN_SCRIPT
		echo $line >> $UNBAN_IP_LIST
	done < $BANNED_IP_LIST
	
	echo "grep -v --file=$UNBAN_IP_LIST $IGNORE_IP_LIST > $TMP_FILE" >> $UNBAN_SCRIPT
	echo "mv $TMP_FILE $IGNORE_IP_LIST" >> $UNBAN_SCRIPT
	echo "rm -f $UNBAN_SCRIPT" >> $UNBAN_SCRIPT
	echo "rm -f $UNBAN_IP_LIST" >> $UNBAN_SCRIPT
	echo "rm -f $TMP_FILE" >> $UNBAN_SCRIPT
	. $UNBAN_SCRIPT &
}

# Count-down timer
countdown()
{
	date1=$((`date +%s` + $1)); 
	while [ "$date1" -ne `date +%s` ]; do 
		echo -ne " Re-running in $(date -u --date @$(($date1 - `date +%s`)) +%H:%M:%S)\r";
		sleep 0.1
	done
}

# Analyse and ban then wait for the specified time set in config file
ddos_cycle()
{
	analyse_n_ban
	countdown $[FREQ*60]
}

# initial (start) function
ddos_start()
{
	# load configurations
	load_config

	# Re-call the ddos_cycle
	while [ true ]
	do
		ddos_cycle
		# sleep $[FREQ*60]
	done
}

# The heart of the algorithm
analyse_n_ban()
{
	echo "Analysing connections"
	TMP_PREFIX='tmp/ddos'
	BANNED_IP_MAIL='tmp/ddos_ip_mail'
	BANNED_IP_LIST='tmp/ddos_ip_list'
	BAD_IP_LIST='tmp/ddos_bad_list'
	echo "Banned the following ip addresses on `date`" > $BANNED_IP_MAIL
	echo >>	$BANNED_IP_MAIL
	echo "" > $BANNED_IP_LIST
	# netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr > $BAD_IP_LIST
	netstat -ntu | grep ESTAB | grep ':' | awk '{print $5}' | sed 's/::ffff://' | cut -f1 -d ':' | sort | uniq -c | sort -nr > $BAD_IP_LIST
	cat $BAD_IP_LIST

	if [ $KILL -eq 1 ]; then
		IP_BAN_NOW=0
		
		# Analyse all connections in Bad_ip_list (all current connections)
		while read line; do
			# Get the Ip & the number of connections
			CURR_LINE_CONN=$(echo $line | cut -d" " -f1)
			CURR_LINE_IP=$(echo $line | cut -d" " -f2)
			
			# Check if the number of connections > Connections_threshold
			if [ $CURR_LINE_CONN -lt $NO_OF_CONNECTIONS ]; then
				break
			fi
			
			# Check if the current ip is in ignore_list, if so it won't be blocked
			IGNORE_BAN=`grep -c $CURR_LINE_IP $IGNORE_IP_LIST`
			if [ $IGNORE_BAN -ge 1 ]; then
				continue
			fi
			
			# Set Banned flag to true, used to send mail(below)
			IP_BAN_NOW=1
			
			# Log ip and connections to the console and the mail
			echo "Banned the following ip addresses on `date` $CURR_LINE_IP with $CURR_LINE_CONN connections"
			echo "$CURR_LINE_IP with $CURR_LINE_CONN connections" >> $BANNED_IP_MAIL
			
			# Add the current ip to the banned_list file
			echo $CURR_LINE_IP >> $BANNED_IP_LIST
			
			# Add the current ip to ignore list so it won't be blocked again until
			# it is un-banned.
			echo $CURR_LINE_IP >> $IGNORE_IP_LIST

			# Block the current Ip by adding it to Iptables
			$IPT -I INPUT -s $CURR_LINE_IP -j DROP
		done < $BAD_IP_LIST
		
		# If atleast one ip is banned send the mail
		if [ $IP_BAN_NOW -eq 1 ]; then
			dt=`date`
			if [ $EMAIL_TO != "" ]; then
				# send email to the email specified in the config file
				cat $BANNED_IP_MAIL | mail -s "IP addresses banned on $dt" $EMAIL_TO
			fi
			# Call unbanip to unbanip after they wait for the specified time in config file
			unbanip
		fi
	fi
}

ddos_start
