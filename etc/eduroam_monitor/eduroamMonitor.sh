#!/bin/bash

tests_path="/etc/eduroam_monitor/tests/"

function getScan() {

        #######
        # Kill any existing wpa_supplicant sessions
        # Then connect to eduroam with working credentials
        #######

	if [ -a /var/run/wpa_supplicant-wlan0 ]
	then
		/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 logoff  
		/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 terminate  
	fi

        /usr/sbin/wpa_supplicant -Dnl80211 -iwlan0 -c /etc/eduroam_monitor/wpa_conf/eduroam-peap.conf -B

	echo "waiting 8s for wpa_supplicant"
        sleep 8

        local scan=$(/usr/sbin/wpa_cli scan)
	echo "scan=$scan"

        # Wait for APs to beacon
        sleep 5

	echo "scan=$scan"

        if [[ $scan =~ OK$ ]]
        then
                local retval='OK'
        else
                local retval='FAIL'
        fi

        local __result=$1
        eval $__result="'$retval'"
}

function getConnection() {

	#######
	# Kill any existing wpa_supplicant sessions
	# Then connect to eduroam with working credentials
	#######

	if [ -a /var/run/wpa_supplicant-wlan0 ]
	then
		/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 logoff  
		/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 terminate  
	fi
        /usr/sbin/wpa_supplicant -Dnl80211 -iwlan0 -c /etc/eduroam_monitor/wpa_conf/eduroam-peap.conf -B
	sleep 2

	######
	# Check for Connection
	######
	local counter=0
	local connected=0
	while [[ $counter -lt 30 ]] && [[ $connected == 0 ]]
	do
		local connection_status=$(/usr/sbin/wpa_cli status)
		if [[ $connection_status =~ Supplicant\ PAE\ state=AUTHENTICATED.* ]]
		then
			connected=1
			break
		elif [[ $connection_status =~ Supplicant\ PAE\ state=.* ]]
		then
			echo "waiting 2s for connection $counter"
			sleep 2
		fi
		counter=$(( $counter + 1 ))
	done

	#######
	# Get an IP Address
	#######
	if [[ $connected == 1 ]]                                                        
	then                                                                      
		/sbin/udhcpc -p /var/run/udhcpc-wlan0.pid -q -t 0 -i wlan0 -s /etc/eduroam_monitor/scripts/udhcpc -C eduProbe  
	fi  

	#######
	# Ensure probe has an IP Addr
	#######
	local counter=0
	local __result=$1
	local ipaddr='FAIL'
	while [[ $counter -lt 30 ]] && [[ "$ipaddr" == "FAIL" ]]
	do
		if [[ ! `ifconfig wlan0` =~ .*inet\s(addr:)?(([0-9]*\.){3}[0-9]*).*/\2 ]]
		then
			ipaddr='OK'
			break
		else
			echo "waiting 2s for IP $counter"
			sleep=2
		fi
		counter=$(( $counter + 1 ))
	done
	
	#TODO: check gateway

	eval $__result="'$ipaddr'"
}


## Allow bash completion                                                                                                                                                                              
#if [ ! -L "/dev/fd" ]                                                                                                                                                                                 
#then                                                                                                                                                                                                  
#	ln -s /proc/self/fd /dev/fd                                                                                                                                                                   
#fi

#####
# Kill OpenWRT wpa_supplicant
#####
if [ -a /var/run/wpa_supplicant-wlan0 ]
then
	/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 logoff 
	/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 terminate  
fi

#####
# Set Date
####
# TODO: put into a firstboot script
# TODO: check timefile contains a time
#if [ -a /etc/eduroam_monitor/time ]
#then
#	cat /etc/eduroam_monitor/time | date -s 
#	date -s "$(cat /etc/eduroam_monitor/time)"
#else
#	date -s "2013-11-07 13:00"
#fi

##############################################
# Run each test                              #
# Store result in array for reporting later  #
##############################################

###
# tests which require wpa_supplicant but no eduroam
###
getScan HAS_SCAN

if [[ "$HAS_SCAN" == "OK" ]]
then

        #
        # if get scan run tests
        #
	for FILE in $(/bin/ls "${tests_path}scan")
	do
		RAW_RESULT=$(${tests_path}scan/$FILE | awk 'END{print}')
		if [[ ! -z "$RAW_RESULT" ]]
		then
			RESULTS=("${RESULTS[@]}" "$RAW_RESULT")
		fi
	done
	
	# Disconnect and tidy up
	
        if [ -a /var/run/wpa_supplicant-wlan0 ]
        then
                /usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 logoff
                /usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 terminate
        fi

else
	echo "scan failed, skipping scan tests - HAS_SCAN=$HAS_SCAN"
fi 

###
# test which require eduroam to be disconnected
###
for FILE in $(/bin/ls "${tests_path}connectionless")
do
	RAW_RESULT=$(${tests_path}connectionless/$FILE | awk 'END{print}')
	if [[ ! -z "$RAW_RESULT" ]]
	then
		RESULTS=("${RESULTS[@]}" "$RAW_RESULT")
	fi
done

####
# Get Connection to eduroam
####
getConnection HAS_CONNECT 

###
# If connection suceeds run connection tests and send all results to server
###
if [[ "$HAS_CONNECT" == "OK" ]]
then
	####
	# Sync time
	####
	#/usr/sbin/ntpd -q -p ntp0.ja.net
	/usr/sbin/ntpdate -b ntp0.ja.net
	
	# TODO: check time is accurate
	
	####
	# Write time to file
	####
	echo "$(date '+%Y-%m-%d %H:%M')" > /etc/eduroam_monitor/time
	
	###
	# tests which require an eduroam connection
	###
	for FILE in $(/bin/ls "${tests_path}connectionful")                                                                                                                                                            
	do                                                                                                                               
		if [[ $FILE =~ "_multi" ]]
		then
			while read line
			do
				if [[ ! -z $line ]]
				then
					RESULTS+=($line)
				fi

			done < <(${tests_path}connectionful/$FILE)
			continue
		fi

	        RAW_RESULT=$(${tests_path}connectionful/$FILE | awk 'END{print}')                                                                                                                                                        
	        if [[ ! -z "$RAW_RESULT" ]]                                                                                                                                                                   
	        then                                                                                                                                                                                          
	        	RESULTS=("${RESULTS[@]}" "$RAW_RESULT")                                                                                                                                               
	        fi                                                                                                                                                                                            
	done 

	########################
	# process test results #
	########################

	#####
	# salt for result hash is eth0 Mac Addr
	#####
	SALT=`ip link show eth0 | awk '/ether/ {print $2}'`
	
	#or read from file
	if [[ $SALT = "" ]]
	then
		while read line
		do
			SALT=$line
		done < "/etc/eduroam_monitor/salt"		
	fi
	
	#####
	# send results to server
	#####
	if [ -a /etc/eduroam_monitor/probeId ]
	then
		while read line   
		do
			PROBE_ID=$line
		done < "/etc/eduroam_monitor/probeId"
	else
		PROBE_ID=100
	fi
	
	
	####
	#  Send results to server
	###
	for T_RESULT in "${RESULTS[@]}"
	do
		TEST_ID=""
		TEST_RESULT=""
		TEST_MESSAGE=""
		TEST_TIME=""
		TOKEN_COUNTER=4
	
		while read line
		do 	
			if [[ $line =~ ^test=.* ]]
			then
				TEST_ID=$(echo $line | cut -d'=' -f2)
				TOKEN_COUNTER=$(( $TOKEN_COUNTER - 1 ))  
			elif [[ $line =~ ^result=.* ]]
			then
				TEST_RESULT=$(echo $line | cut -d'=' -f2)
				TOKEN_COUNTER=$(( $TOKEN_COUNTER - 1 ))
			elif [[ $line =~ ^message=.+ ]]                  
			then
			        TEST_MESSAGE=$(echo $line | cut -d'=' -f2)                            
			        TOKEN_COUNTER=$(( $TOKEN_COUNTER - 1 ))
			elif [[ $line =~ ^message=$ ]]
			then
				TEST_MESSAGE=""
				TOKEN_COUNTER=$(( $TOKEN_COUNTER - 1 ))
			elif [[ $line =~ ^time=.* ]]
			then
				TEST_TIME=$(echo $line | cut -d'=' -f2)
				TOKEN_COUNTER=$(( $TOKEN_COUNTER - 1 ))
			fi
		done < <(echo $T_RESULT | tr "&" "\n")
		
		if [[ "$TOKEN_COUNTER" == 0 ]] 
		then
			#####
			# Convert test result to html
			#####
			TEST_INFO_HTML=$(echo $TEST_MESSAGE | sed -e 's/\#/%23/g' -e 's/\ /%20/g')
			
			#####                                                                                                                                                                         
			# Generate hash of results using salt                                                                                                                                         
			#####                                                                                                                                                                         
			RESULT_DIGEST=$(echo -n "$PROBE_ID$TEST_ID$TEST_RESULT$TEST_MESSAGE$TEST_TIME$SALT" | sha1sum | awk '{ print $1 }')   
				
			#TODO: set up real server for receving results		
			
			#####
			# Create reporting URL for test results
			#####
			GET_STRING="https://support.roaming.ja.net/cgi-bin/probe/probe?probe=$PROBE_ID&test=$TEST_ID&result=$TEST_RESULT&message=$TEST_INFO_HTML&time=$TEST_TIME&check=$RESULT_DIGEST"
			echo "$GET_STRING"
			
			######
			# send test result to server with HTTP GET
			######
# UNCOMMENT THIS TO ENABLE RESULT SUBMISSION
#			RESPONSE=$(curl --cacert /etc/eduroam_monitor/ca.crt --capath /etc/eduroam_monitor $GET_STRING)
			
#			echo "$RESPONSE"
			
		fi
	done
	
else

	echo "no connection detected, skipping connectionfull tests and results submission: HAS_CONNECT=$HAS_CONNECT"

fi

####
# disconnect from eduroam
####
if [ -a /var/run/wpa_supplicant-wlan0 ]
then
	/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 logoff  
	/usr/sbin/wpa_cli -p /var/run/wpa_supplicant-wlan0 terminate  
fi


