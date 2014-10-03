#!/bin/bash
# Configuration script for my customized onionpi. Codenamed: Pinball.
# Menus to change wifi configuration or switch between TOR and VPN modes
#
# TODO list:
# 
# HIGH - Double Check output files.
# Add a check for connectivity - low priority
# Tighten up the iptables for "NONE MODE" so that only allow http and https for landing pages at public wifi networks are allowed through.
# Check into cert handling for VPN access.
# Add warning if "NONE MODE" is selected.
# Insert confirmation dialog at the end of the WIFI setup.
# Insert warnings about the lameness of WEP and Open WiFi connections when selected
# Verify configuration directories exist.
# Create an installation script
# Function to easily import VPN configurations.

# Variables imported from pinball.cfg
# PREVIOUS_CONFIG_DIR=
# OUTPUT_CONFIG=
# OVPN_DIR=
# WAN_SSID=
# WIFI_PASS=
# WIFI_SECURE=
# MODE=
# VPN=
# WAN=
# AP_IF=
# AP_SSID=
# AP_MODE=
# AP_CHANNEL=
# AP_BROADCAST=
# AP_KEY=
# IP_SUBNET=
# IP_RANGE_FROM=
# IP_RANGE_TO=

TITLEBAR=""
ERRORMSG=""
OUTPUT_FILE=""



function rootcheck
{
	#Check that script was executed as root
	if [[ $EUID -ne 0 ]]; then
		echo "This script must be run as root" 1>&2
		exit 1
	fi
}





function error_quit # pass $? as arguement
{
	exitstatus=$1 #Grab error code from previous command
	if [ $exitstatus -ne 0 ]; then #Was above command was successful?
		echo "Something went wrong.  Exiting with error code: $exitstatus"
		exit $1
	fi
	return
}





function error_msg
{
	case "$1" in
		quit)
			#Replace error_quit?
		;;
		
		incomplete)
			ERRORMSG="This sript is a work in progress. The function you selected has not been completed yet."
		;;
		
		ssid)
			#SSID too long
			ERRORMSG="An SSID can not be blank and can not be longer than 32 characters"
		;;
		
		wpa)
			ERRORMSG="The WPA key you entered is invalid.  A valid WPA key cannot be blank or greater than 64 characters in length."
		;;
		
		wep)
			ERRORMSG="The WEP key you entered is invalid.  A valid WEP key must not be blank, is no more than 58 characters in length, and is a HEX value only"
		;;
		
		config)
			ERRORMSG="Some settings were not configured.  Check your configuration and try again."
		;;
	esac
		
		#Display Error
		whiptail --title "ERROR!" --msgbox "$ERRORMSG" 8 78
		echo "$PREVIOUS_CONFIG_DIR"
		echo "$OUTPUT_CONFIG"
		echo "$OVPN_DIR"
		echo "$WAN_SSID"
		echo "$WIFI_PASS"
		echo "$WIFI_SECURE"
		echo "$MODE"
		echo "$VPN"
		echo "$WAN"
		echo "$AP_IF"
		echo "$AP_SSID"
		echo "$AP_MODE"
		echo "$AP_CHANNEL"
		echo "$AP_BROADCAST"
		echo "$AP_KEY"
		echo "$IP_SUBNET"
		echo "$IP_RANGE_FROM"
		echo "$IP_RANGE_TO"
}






function internet_config
{
	TITLEBAR="Change Internet Settings"
	
	
	
	#Prompt for SSID.  If SSID is blank, then use eth0 as the internet connection
	WAN_SSID=$(whiptail --title "$TITLEBAR" --nocancel --inputbox "Enter SSID of the WiFi network you want to connect to.  Leave it blank to use an Ethernet connection instead." 9 78 3>&1 1>&2 2>&3)
	#error_quit $? #Error check
		
	while [ ${#WAN_SSID} -gt 32 ]; do #Check that length of SSID is less than or equal to 32 characters
		#SSID too long
		error_msg ssid
		WAN_SSID=$(whiptail --title "$TITLEBAR" --nocancel --inputbox "Enter SSID of the WiFi network you want to connect to.  Leave it blank to use an Ethernet connection instead." 9 78 3>&1 1>&2 2>&3)
	done
	
	#Check if SSID is blank.
	if [ -z $WAN_SSID ]; then #Is the lenth of the SSID entered is zero?
		WAN="eth0"
		WAN_SSID="NONE"
		WIFI_PASS="NONE"
		return
	fi
	
	
	
	#Above if statments should break away from below if necessary
	WAN="wlan0" #Sets to wlan0, in case it was previously eth0
	
	#Prompt for encryption protocol
	WIFI_SECURE=$(whiptail --title "$TITLEBAR" --nocancel --radiolist \
				"Choose security type:" 20 78 12 \
				"WPA" "Wi-Fi Protected Access" ON \
				"WEP" "Wired Equivalent Privacy" OFF \
				"OPEN" "Unsecured Wireless" OFF \
				3>&1 1>&2 2>&3)
	
	#error_quit $?
	
	if [ $WIFI_SECURE == "OPEN" ]; then
		#TODO: Insert warnings about the lameness of WEP and Open WiFi connections
		return
	else
		WIFI_PASS=$(whiptail --title "$TITLEBAR" --nocancel --passwordbox "Enter $WIFI_SECURE Key" 8 78 3>&1 1>&2 2>&3)
		#error_quit $?

		#Validate Key input
		case "$WIFI_SECURE" in
			WPA) 
				while [ $WIFI_SECURE == "WPA" ] && [[ ${#WIFI_PASS} -gt 64 || -z $WIFI_PASS ]]; do
					WIFI_PASS=$(whiptail --title "$TITLEBAR" --nocancel --passwordbox "Enter $WIFI_SECURE Key" 8 78 3>&1 1>&2 2>&3)
					if [[ ${#WIFI_PASS} -gt 64 || -z $WIFI_PASS ]]; then
						error_msg wpa
					fi
				done
			;;
			WEP)
				#TODO: Insert warnings about the lameness of WEP and Open WiFi connections
				while [ $WIFI_SECURE == "WEP" ] && [ ${#WIFI_PASS} -gt 58 ] || [ -z $WIFI_PASS ] || [[ ! $WIFI_PASS =~ ^[0-9A-Fa-f]+$ ]]; do
					WIFI_PASS=$(whiptail --title "$TITLEBAR" --nocancel --passwordbox "Enter $WIFI_SECURE Key" 8 78 3>&1 1>&2 2>&3)
					if [ ${#WIFI_PASS} -gt 58 ] || [ -z $WIFI_PASS ] || [[ ! $WIFI_PASS =~ ^[0-9A-Fa-f]+$ ]]; then
						error_msg wep
					fi
				done
			;;
		esac
	fi
	# TODO: Insert Confirmation box
}





function mode_config
{
	TITLEBAR="TOR or VPN Mode Selection"
	
	MODE=$(whiptail --title "$TITLEBAR" --nocancel --radiolist \
			"Do you wish to anonymize by TOR or VPN?" 20 78 12 \
			"TOR" "Forward traffic through The Onion Router network" ON \
			"VPN" "Forward traffic through an OpenVPN connection" OFF \
			"NONE" "Do not forward traffic.  Use only basic NAT firewalling." OFF \
			3>&1 1>&2 2>&3)
				# TODO: Add warning if "NONE" is selected.
	
	if [ $MODE == "VPN" ]; then # Prompt to select VPN configuration file.
		i=0
		for f in $OVPN_DIR/*.ovpn; do # Add path to where ovpn files will be kept
			files[i]="${f##*/}"    # save file name without path
			files[i+1]="${files[i]%.*}" #Cut extension for menu description
			((i+=2))
		done
		TITLEBAR="Select VPN Client"
		VPN=$(whiptail --title "$TITLEBAR" --nocancel --menu "Please select the VPN client configuration you wish to use:" 14 75 6 "${files[@]}" 3>&1 1>&2 2>&3)
	fi
}





function ap_config
{
	TITLEBAR="Chanage Access Point Settings"
	
	# Set and verify SSID for Access Point
	AP_SSID=$(whiptail --title "$TITLEBAR" --nocancel --inputbox "Enter the desired SSID:" 9 78 3>&1 1>&2 2>&3)
	#error_quit $?
	while [ ${#AP_SSID} -gt 32 ] || [ -z $AP_SSID ]; do
		error_msg ssid
		
		AP_SSID=$(whiptail --title "$TITLEBAR" --nocancel --inputbox "Enter the desired SSID:" 9 78 3>&1 1>&2 2>&3)
	done
	
	# Set and verify WPA key for Access Point
	# WPA only because anything else is stupid.
	AP_KEY=$(whiptail --title "$TITLEBAR" --nocancel --passwordbox "Enter the desire WPA password:" 9 78 3>&1 1>&2 2>&3)
	#error_quit $?
	while [ ${#AP_KEY} -gt 64 ] || [ -z $AP_KEY ]; do
		error_msg wpa
		AP_KEY=$(whiptail --title "$TITLEBAR" --nocancel --passwordbox "Enter the desire WPA password:" 9 78 3>&1 1>&2 2>&3)
	done
	
	AP_MODE=$(whiptail --title "$TITLEBAR" --nocancel --radiolist \
			"Which mode do you want to use?" 20 78 12 \
			"n" "Up to 100+ Mbit/s at 2.4 and 5 Ghz" OFF \
			"g" "Up to 54 Mbit/s at 2.4 Ghz" ON \
			"a" "Up to 54 Mbit/s at 5 Ghz" OFF \
			"b" "Up to 11 Mbit/s at 2.4 Ghz" OFF \
			3>&1 1>&2 2>&3)
	#error_quit $?
	
	case "$AP_MODE" in
		n)
			AP_CHANNEL=$(whiptail --title "$TITLEBAR" --nocancel --radiolist \
						"Select a channel to operate on.  Valid channels are: 1 through 11 for 2.4 Ghz band.  36, 40, 44, and 48 for 5 Ghz band." 25 78 17 \
						"1" "2.412 Ghz (Modes n,g, and b)" OFF \
						"2" "2.417 Ghz (Modes n,g, and b)" OFF \
						"3" "2.422 Ghz (Modes n,g, and b)" OFF \
						"4" "2.427 Ghz (Modes n,g, and b)" OFF \
						"5" "2.432 Ghz (Modes n,g, and b)" OFF \
						"6" "2.437 Ghz (Modes n,g, and b)" ON \
						"7" "2.442 Ghz (Modes n,g, and b)" OFF \
						"8" "2.447 Ghz (Modes n,g, and b)" OFF \
						"9" "2.452 Ghz (Modes n,g, and b)" OFF \
						"10" "2.457 Ghz (Modes n,g, and b)" OFF \
						"11" "2.462 Ghz (Modes n,g, and b)" OFF \
						"36" "5.180 Ghz (Modes n and a)" OFF \
						"40" "5.200 Ghz (Modes n and a)" OFF \
						"44" "5.220 Ghz (Modes n and a)" OFF \
						"48" "5.240 Ghz (Modes n and a)" OFF \
						3>&1 1>&2 2>&3)
		;;
		g | b)
			AP_CHANNEL=$(whiptail --title "$TITLEBAR" --nocancel --radiolist \
						"Select a channel to operate on.  Valid channels are: 1 through 11 for 2.4 Ghz band." 20 78 12 \
						"1" "2.412 Ghz (Modes n,g, and b)" OFF \
						"2" "2.417 Ghz (Modes n,g, and b)" OFF \
						"3" "2.422 Ghz (Modes n,g, and b)" OFF \
						"4" "2.427 Ghz (Modes n,g, and b)" OFF \
						"5" "2.432 Ghz (Modes n,g, and b)" OFF \
						"6" "2.437 Ghz (Modes n,g, and b)" ON \
						"7" "2.442 Ghz (Modes n,g, and b)" OFF \
						"8" "2.447 Ghz (Modes n,g, and b)" OFF \
						"9" "2.452 Ghz (Modes n,g, and b)" OFF \
						"10" "2.457 Ghz (Modes n,g, and b)" OFF \
						"11" "2.462 Ghz (Modes n,g, and b)" OFF \
						3>&1 1>&2 2>&3)
		;;
		a)
			AP_CHANNEL=$(whiptail --title "$TITLEBAR" --nocancel --radiolist \
						"Select a channel to operate on.  Valid channels are: 36, 40, 44, and 48 for 5 Ghz band." 20 78 12 \
						"36" "5.180 Ghz (Modes n and a)" ON \
						"40" "5.200 Ghz (Modes n and a)" OFF \
						"44" "5.220 Ghz (Modes n and a)" OFF \
						"48" "5.240 Ghz (Modes n and a)" OFF \
						3>&1 1>&2 2>&3)
		;;
	esac
	#error_quit $?
}





function advance_config
{
	TITLEBAR="ADVANCED CONFIGURATION"
	whiptail --title "$TITLEBAR" --msgbox "This option will load the pinball.cfg file in the nano text editor so that you may edit your configuration manually.  All changes made thus far will be discarded.  Before changes are made, the existing configuration file will be backed up as PREVIOUS-pinball.cfg" 8 78
	#error_quit $?
	cp -f ./pinball.cfg ./PREVIOUS-pinball.cfg
	error_quit $?
	nano ./pinball.cfg
	error_quit $?
	source pinball.cfg #Reload the variables with the new settings.
}





function restore_config
{
	whiptail --title "RESTORE CONFIGURATION" --yesno "This will restore the previously saved configuration and reboot.  Are you sure you wish to continue?" 8 78
    exitstatus=$?
	if [ $exitstatus = 0 ]; then
   		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-pinball.cfg ./pinball.cfg
   		error_quit $?
		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-hostapd.conf /etc/hostapd/hostapd.conf
		error_quit $?
		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-interfaces /etc/network/interfaces
		error_quit $?
		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-client.conf /etc/openvpn/client.conf
		error_quit $?
		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-isc-dhcp-server /etc/default/isc-dhcp-server
		error_quit $?
		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-dhcpd.conf /etc/dhcp/dhcpd.conf
		error_quit $?
		cp -f $PREVIOUS_CONFIG_DIR/PREVIOUS-iptables.ipv4.nat /etc/iptables.ipv4.nat
		error_quit $?
		reboot
	fi	
}




function run_updates
{
	whiptail --title "UPDATE" --yesno "You are about to erase old packages and update all other packages to their latest available version.  Afterwards the system will reboot.  Are you sure you wish to continue?" 8 78
    exitstatus=$?
	if [ $exitstatus = 0 ]; then
		apt-get -y autoremove
		error_quit $?
		apt-get -y autoclean
		error_quit $?
		apt-get -y clean
		error_quit $?
		apt-get -y update
		error_quit $?
		apt-get -y upgrade
		error_quit $?
		reboot
	else
		return
	fi
}




function finalize
{
	# Check that there are no blank variables being exported to configuration.
	if \
	[ -z $PREVIOUS_CONFIG_DIR ] || \
	[ -z $OUTPUT_CONFIG ] || \
	[ -z $OVPN_DIR ] || \
	[ -z $WAN_SSID ] || \
	[ -z $WIFI_PASS ] || \
	[ -z $WIFI_SECURE ] || \
	[ -z $MODE ] || \
	[ -z $VPN ] || \
	[ -z $WAN ] || \
	[ -z $AP_IF ] || \
	[ -z $AP_SSID ] || \
	[ -z $AP_MODE ] || \
	[ -z $AP_CHANNEL ] || \
	[ -z $AP_BROADCAST ] || \
	[ -z $AP_KEY ] ; then
		error_msg config
		return
	fi
		
	whiptail --title "FINALIZING CONFIGURATION" --yesno "You are about to export the configuration changes that you have made and reboot the system.  Are you sure you wish to continue?" 8 78
    exitstatus=$?
	if [ $exitstatus = 0 ]; then
   	
		# de-activate network interfaces during configuration update.
		ifdown wlan0
		ifdown wlan1
		ifdown eth0
   	
		# Stop networking daemons
		service tor stop
		service openvpn stop
		service hostapd stop
		service isc-dhcp-server stop
		service networking stop
		
		# Save pinball.cfg
		# Backup pinball.cfg
		cp -f ./pinball.cfg $PREVIOUS_CONFIG_DIR/PREVIOUS-pinball.cfg
		error_quit $?
		
		#Exporting pinball.cfg
		OUTPUT_FILE="pinball.cfg"
		echo "# This file generated by the Pinball Router script" > $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Path to store backup configuration files." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "PREVIOUS_CONFIG_DIR=\"$PREVIOUS_CONFIG_DIR\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Path to where generated configuration files will be saved." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "OUTPUT_CONFIG=\"$OUTPUT_CONFIG\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Path to store OVPN client files" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "OVPN_DIR=\"$OVPN_DIR\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Currently configured SSID." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "WAN_SSID=\"$WAN_SSID\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Wireless key for currently configured SSID." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "WIFI_PASS=\"$WIFI_PASS\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Wireless security protocol.  Valid options are \"WPA\", \"WEP\", or \"OPEN\"." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "WIFI_SECURE=\"$WIFI_SECURE\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Configuration Mode - TOR or VPN" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "MODE=\"$MODE\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Default VPN client configuration" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "VPN=\"$VPN\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Device to use for WAN connection. Valid options are \"wlan0\", \"wlan1\", or \"eth0\"." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "WAN=\"$WAN\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# HOSTAP Configuration" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Interface to broadcast on" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "AP_IF=\"$AP_IF\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Network SSID" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "AP_SSID=\"$AP_SSID\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# 802.11 Standard to use.  Valid options are: a, b, g, or n." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "AP_MODE=\"$AP_MODE\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Wireless channel to operate on." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Channels 1-11 for 802.11b,g, or n using the 2.4 Ghz band." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Channels 36, 40, 44, and 48 for 802.11a or n using the 5 Ghz band." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "AP_CHANNEL=\"$AP_CHANNEL\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# 0 to broadcast the SSID. 1 to not broadcast.  Recommend leaving at 1." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "AP_BROADCAST=\"$AP_BROADCAST\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "AP_KEY=\"$AP_KEY\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Specify a class C subnet for your local LAN.  Example: 192.168.42.0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "IP_SUBNET=\"$IP_SUBNET\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Specify a range of DHCP assignable IP addresses." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "IP_RANGE_FROM=\"$IP_RANGE_FROM\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "IP_RANGE_TO=\"$IP_RANGE_TO\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		
		# copying pinball.cfg into place
		cp -f $OUTPUT_CONFIG/$OUTPUT_FILE ./pinball.cfg
		error_quit $?

		# Backup hostapd.conf
		cp -f /etc/hostapd/hostapd.conf $PREVIOUS_CONFIG_DIR/PREVIOUS-hostapd.conf
		error_quit $?
		
		# Generate hostapd.conf
		OUTPUT_FILE="hostapd.conf"
		echo "# This file generated by the Pinball Router script" > $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "interface=$AP_IF" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "driver=rtl871xdrv" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "ssid=$AP_SSID" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "hw_mode=$AP_MODE" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "channel=$AP_CHANNEL" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "macaddr_acl=0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "auth_algs=1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "ignore_broadcast_ssid=$AP_BROADCAST" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "wpa=2" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "wpa_passphrase=$AP_KEY" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "wpa_key_mgmt=WPA-PSK" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "wpa_pairwise=TKIP" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "rsn_pairwise=CCMP" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		
		# copying hostapd.conf into place
		cp -f $OUTPUT_CONFIG/$OUTPUT_FILE /etc/hostapd/hostapd.conf
		error_quit $?
		
		# Enable TOR or VPN daemons.
		#service tor stop
		#error_quit $?
		#service openvpn stop
		#error_quit $?

		case "$MODE" in
			TOR)
				update-rc.d tor enable
				error_quit $?
				update-rc.d openvpn disable
				error_quit $?
#-----------------------------------------------------------------------
				# Backup TOR configuration file
				cp -f /etc/tor/torrc $PREVIOUS_CONFIG_DIR/PREVIOUS-torrc
				error_quit $?
				
				# Generate torrc
				OUTPUT_FILE="torrc"
				echo "# This file generated by the Pinball Router script" > $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Configuration file for a typical Tor user" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Last updated 22 April 2012 for Tor 0.2.3.14-alpha." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## (may or may not work for much older or much newer versions of Tor.)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Lines that begin with \"## \" try to explain what's going on. Lines" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## that begin with just \"#\" are disabled commands: you can enable them" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## by removing the \"#\" symbol." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## See 'man tor', or https://www.torproject.org/docs/tor-manual.html," >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## for more options you can use in this file." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Tor will look for this file in various places based on your platform:" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## https://www.torproject.org/docs/faq#torrc" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "Log notice file /var/log/tor/notices.log" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "VirtualAddrNetwork 10.192.0.0/10" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "AutomapHostsSuffixes .onion,.exit" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "AutomapHostsOnResolve 1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "TransPort 9040" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "TransListenAddress ${IP_SUBNET%.*}.1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "DNSPort 53" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "DNSListenAddress ${IP_SUBNET%.*}.1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Tor opens a socks proxy on port 9050 by default -- even if you don't" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## configure one below. Set \"SocksPort 0\" if you plan to run Tor only" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## as a relay, and not make any local application connections yourself." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#SocksPort 9050 # Default: Bind to localhost:9050 for local connections." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#SocksPort 192.168.0.1:9100 # Bind to this adddress:port too." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Entry policies to allow/deny SOCKS requests based on IP address." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## First entry that matches wins. If no SocksPolicy is set, we accept" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## all (and only) requests that reach a SocksPort. Untrusted users who" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## can access your SocksPort may be able to learn about the connections" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## you make." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#SocksPolicy accept 192.168.0.0/16" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#SocksPolicy reject *" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Logs go to stdout at level \"notice\" unless redirected by something" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## else, like one of the below lines. You can have as many Log lines as" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## you want." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## We advise using \"notice\" in most cases, since anything more verbose" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## may provide sensitive information to an attacker who obtains the logs." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Send all messages of level 'notice' or higher to /var/log/tor/notices.log" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#Log notice file /var/log/tor/notices.log" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Send every possible message to /var/log/tor/debug.log" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#Log debug file /var/log/tor/debug.log" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Use the system log instead of Tor's logfiles" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#Log notice syslog" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## To send all messages to stderr:" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#Log debug stderr" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Uncomment this to start the process in the background... or use" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## --runasdaemon 1 on the command line. This is ignored on Windows;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## see the FAQ entry if you want Tor to run as an NT service." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#RunAsDaemon 1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## The directory for keeping all the keys/etc. By default, we store" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## things in $HOME/.tor on Unix, and in Application Data\tor on Windows." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#DataDirectory /var/lib/tor" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## The port on which Tor will listen for local connections from Tor" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## controller applications, as documented in control-spec.txt." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ControlPort 9051" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## If you enable the controlport, be sure to enable one of these" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## authentication methods, to prevent attackers from accessing it." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#CookieAuthentication 1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "############### This section is just for location-hidden services ###" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Once you have configured a hidden service, you can look at the" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## contents of the file ".../hidden_service/hostname" for the address" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## to tell people." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## HiddenServicePort x y:z says to redirect requests on port x to the" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## address y:z." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#HiddenServiceDir /var/lib/tor/hidden_service/" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#HiddenServicePort 80 127.0.0.1:80" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#HiddenServiceDir /var/lib/tor/other_hidden_service/" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#HiddenServicePort 80 127.0.0.1:80" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#HiddenServicePort 22 127.0.0.1:22" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "################ This section is just for relays #####################" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## See https://www.torproject.org/docs/tor-doc-relay for details." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Required: what port to advertise for incoming Tor connections." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ORPort 9001" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## If you want to listen on a port other than the one advertised in" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## ORPort (e.g. to advertise 443 but bind to 9090), you can do it as" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## follows.  You'll need to do ipchains or other port forwarding" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## yourself to make this work." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ORPort 443 NoListen" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ORPort 127.0.0.1:9090 NoAdvertise" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## The IP address or full DNS name for incoming connections to your" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## relay. Leave commented out and Tor will guess." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#Address noname.example.com" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## If you have multiple network interfaces, you can specify one for" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## outgoing traffic to use." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "# OutboundBindAddress 10.0.0.5" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## A handle for your relay, so people don't have to refer to it by key." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#Nickname ididnteditheconfig" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Define these to limit how much relayed traffic you will allow. Your" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## own traffic is still unthrottled. Note that RelayBandwidthRate must" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## be at least 20 KB." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Note that units for these config options are bytes per second, not bits" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## per second, and that prefixes are binary prefixes, i.e. 2^10, 2^20, etc." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#RelayBandwidthRate 100 KB  # Throttle traffic to 100KB/s (800Kbps)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#RelayBandwidthBurst 200 KB # But allow bursts up to 200KB/s (1600Kbps)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Use these to restrict the maximum traffic per day, week, or month." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Note that this threshold applies separately to sent and received bytes," >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## not to their sum: setting \"4 GB\" may allow up to 8 GB total before" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## hibernating." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Set a maximum of 4 gigabytes each way per period." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#AccountingMax 4 GB" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Each period starts daily at midnight (AccountingMax is per day)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#AccountingStart day 00:00" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Each period starts on the 3rd of the month at 15:00 (AccountingMax" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## is per month)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#AccountingStart month 3 15:00" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Contact info to be published in the directory, so we can contact you" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## if your relay is misconfigured or something else goes wrong. Google" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## indexes this, so spammers might also collect it." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ContactInfo Random Person <nobody AT example dot com>" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## You might also include your PGP or GPG fingerprint if you have one:" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ContactInfo 0xFFFFFFFF Random Person <nobody AT example dot com>" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Uncomment this to mirror directory information for others. Please do" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## if you have enough bandwidth." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#DirPort 9030 # what port to advertise for directory connections" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## If you want to listen on a port other than the one advertised in" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## DirPort (e.g. to advertise 80 but bind to 9091), you can do it as" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## follows.  below too. You'll need to do ipchains or other port" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## forwarding yourself to make this work." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#DirPort 80 NoListen" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#DirPort 127.0.0.1:9091 NoAdvertise" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Uncomment to return an arbitrary blob of html on your DirPort. Now you" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## can explain what Tor is if anybody wonders why your IP address is" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## contacting them. See contrib/tor-exit-notice.html in Tor's source" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## distribution for a sample." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#DirPortFrontPage /etc/tor/tor-exit-notice.html" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Uncomment this if you run more than one Tor relay, and add the identity" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## key fingerprint of each Tor relay you control, even if they're on" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## different networks. You declare it here so Tor clients can avoid" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## using more than one of your relays in a single circuit. See" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## https://www.torproject.org/docs/faq#MultipleRelays" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## However, you should never include a bridge's fingerprint here, as it would" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## break its concealability and potentionally reveal its IP/TCP address." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#MyFamily \$keyid,\$keyid,..." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## A comma-separated list of exit policies. They're considered first" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## to last, and the first match wins. If you want to _replace_" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## the default exit policy, end this with either a reject *:* or an" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## accept *:*. Otherwise, you're _augmenting_ (prepending to) the" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## default exit policy. Leave commented to just use the default, which is" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## described in the man page or at" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## https://www.torproject.org/documentation.html" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Look at https://www.torproject.org/faq-abuse.html#TypicalAbuses" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## for issues you might encounter if you use the default exit policy." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## If certain IPs and ports are blocked externally, e.g. by your firewall," >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## you should update your exit policy to reflect this -- otherwise Tor" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## users will be told that those destinations are down." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## For security, by default Tor rejects connections to private (local)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## networks, including to your public IP address. See the man page entry" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## for ExitPolicyRejectPrivate if you want to allow \"exit enclaving\"." >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "##" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ExitPolicy accept *:6660-6667,reject *:* # allow irc ports but no more" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ExitPolicy accept *:119 # accept nntp as well as default exit policy" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#ExitPolicy reject *:* # no exits allowed" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## Bridge relays (or \"bridges\") are Tor relays that aren't listed in the" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## main directory. Since there is no complete public list of them, even an" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## ISP that filters connections to all the known Tor relays probably" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## won't be able to block all the bridges. Also, websites won't treat you" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## differently because they won't know you're running Tor. If you can" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## be a real relay, please do; but if not, be a bridge!" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#BridgeRelay 1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## By default, Tor will advertise your bridge to users through various" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## mechanisms like https://bridges.torproject.org/. If you want to run" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## a private bridge, for example because you'll give out your bridge" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "## address manually to your friends, uncomment this line:" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "#PublishServerDescriptor 0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				
				# copying torrc into place
				cp -f $OUTPUT_CONFIG/$OUTPUT_FILE /etc/tor/torrc
				error_quit $?
#-----------------------------------------------------------------------
			;;
			VPN)
				update-rc.d openvpn enable
				error_quit $?
				update-rc.d tor disable
				error_quit $?

				cp -f /etc/openvpn/client.conf $PREVIOUS_CONFIG_DIR/PREVIOUS-client.conf
				error_quit $?
				cp -f $OVPN_DIR/$VPN /etc/openvpn/client.conf
				error_quit $?
				cp -f $OVPN_DIR/${VPN%.*}/* /etc/openvpn/ #Cut the ".ovpn" from the $VPN filename and copy files from the coresponding directory
			;;
			NONE)
				update-rc.d tor disable
				error_quit $?
				update-rc.d openvpn disable
				error_quit $?
			;;
		esac
		
		# Backup previous interfaces config file
		cp -f /etc/network/interfaces $PREVIOUS_CONFIG_DIR/PREVIOUS-interfaces
		error_quit $?
		
		# Generate Interfaces file.
		OUTPUT_FILE="interfaces"
		echo "# This file generated by the Pinball Router script" > $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# This is the contents of the new interfaces" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# file generated by this script." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Look over the settings below for any errors." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# You may make corrections here." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "auto lo" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "iface lo inet dhcp" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		
		case "$WAN" in
			eth0)
				#eth0 section -- Just set to pickup dhcp.
				echo "iface eth0 inet dhcp" >> $OUTPUT_CONFIG/$OUTPUT_FILE
			;;
			wlan0)

				#eth0 section:
				echo "iface eth0 inet static" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "address 10.253.200.2" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				echo "netmask 255.255.255.0" >> $OUTPUT_CONFIG/$OUTPUT_FILE

				#wlan0 section:

				if [ $WIFI_SECURE == "WPA" ]; then
					echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "# Uncomment the portion below if you are using a hidden SSID." >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "auto wlan0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "iface wlan0 inet dhcp" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "#wpa-scan-ssid 1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "#wpa-ap-scan 1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "#wpa-key-mgmt WPA-PSK" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "#wpa-proto RSN WPA" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "#wpa-pairwise CCMP TKIP" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "#wpa-group CCMP TKIP" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "wpa-ssid \"$WAN_SSID\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "wpa-psk \"$WIFI_PASS\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE

				elif [ $WIFI_SECURE == "WEP" ]; then
					echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "auto wlan0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "wireless-essid $WAN_SSID" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "wireless-key $WIFI_PASS" >> $OUTPUT_CONFIG/$OUTPUT_FILE

				else # OPEN Wifi
					echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "auto wlan0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "iface wlan0 inet dhcp" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "wireless-essid $WAN_SSID" >> $OUTPUT_CONFIG/$OUTPUT_FILE
					echo "wireless-mode managed" >> $OUTPUT_CONFIG/$OUTPUT_FILE
				fi

			;;
		esac
		
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "auto wlan1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "iface wlan1 inet static" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "address 10.253.200.1" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "netmask 255.255.255.0" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "up iptables-restore < /etc/iptables.ipv4.nat" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		

		# Copy new interfaces config file into place
		cp -f ./$OUTPUT_CONFIG/$OUTPUT_FILE /etc/network/interfaces
		error_quit $?
	

		# Backup previous dhcpd.conf file
		cp -f /etc/dhcp/dhcpd.conf $PREVIOUS_CONFIG_DIR/PREVIOUS-dhcpd.conf
		error_quit $?
		
		OUTPUT_FILE="dhcpd.conf"
		echo "# This file generated by the Pinball Router script" > $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# The ddns-updates-style parameter controls whether or not the server will" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# attempt to do a DNS update when a lease is confirmed. We default to the" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# behavior of the version 2 packages ('none', since DHCP v2 didn't" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# have support for DDNS.)" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "ddns-update-style none;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "default-lease-time 600;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "max-lease-time 7200;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# If this DHCP server is the official DHCP server for the local" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# network, the authoritative directive should be uncommented." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "authoritative;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Use this to send dhcp log messages to a different log file (you also" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# have to hack syslog.conf to complete the redirection)." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "log-facility local7;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "subnet $IP_SUBNET netmask 255.255.255.0 {" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "range $IP_RANGE_FROM $IP_RANGE_TO;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "option broadcast-address ${IP_SUBNET%.*}.255;" >> $OUTPUT_CONFIG/$OUTPUT_FILE # String manipulation to cut off everything from the last "." i the string.
		echo "option routers ${IP_SUBNET%.*}.1;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "default-lease-time 600;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "max-lease-time 7200;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "option domain-name \"local\";" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "option domain-name-servers 8.8.8.8, 8.8.4.4;" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "}" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		
		# Copy new dhcp configuration into place
		cp -f /$OUTPUT_CONFIG/$OUTPUT_FILE /etc/dhcp/dhcpd.conf
		
		# Backup previous isc-dhcp-server file
		cp -f /etc/default/isc-dhcp-server $PREVIOUS_CONFIG_DIR/PREVIOUS-isc-dhcp-server
		error_quit $?
		
		# Generate new isc-dhcp-server defaults file
		OUTPUT_FILE="isc-dhcp-server"
		echo "# This file generated by the Pinball Router script" > $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Defaults for isc-dhcp-server initscript" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# sourced by /etc/init.d/isc-dhcp-server" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# installed at /etc/default/isc-dhcp-server by the maintainer scripts" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# This is a POSIX shell fragment" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Path to dhcpd's config file (default: /etc/dhcp/dhcpd.conf)." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#DHCPD_CONF=/etc/dhcp/dhcpd.conf" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Path to dhcpd's PID file (default: /var/run/dhcpd.pid)." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#DHCPD_PID=/var/run/dhcpd.pid" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# Additional options to start dhcpd with." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#	Don't use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#OPTIONS=\"\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		echo "#	Separate multiple interfaces with spaces, e.g. "eth0 eth1"." >> $OUTPUT_CONFIG/$OUTPUT_FILE
		
		if [ $WAN == "eth0" ]; then # If WAN is eth0 then only run DHCP server on wlan1 interface
			echo "INTERFACES=\"wlan1\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		else # Otherwise run DHCP server on both eth0 and wlan1 interfaces
			echo "INTERFACES=\"wlan1 eth0\"" >> $OUTPUT_CONFIG/$OUTPUT_FILE
		fi
		
		# Copy new isc-dhcp-server defaults file into place
		cp -f $OUTPUT_CONFIG/$OUTPUT_FILE /etc/default/isc-dhcp-server
		error_quit $?



	
	
	
		# Backup previous iptables file
		cp -f /etc/iptables.ipv4.nat $PREVIOUS_CONFIG_DIR/PREVIOUS-iptables.ipv4.nat
		error_quit $?

		# Generate appropriate iptable rules.
		##### REMEMBER: IPTABLE RULES MUST BE IN THE CORRECT ORDER #####
		# Flush iptables:
		iptables -F #Flush rules
		#iptables -X #Delete chains
		#iptables -Z #Reset counters
		iptables -t nat -F #Flush nat table
		
		# Set default rules
		iptables -P INPUT   DROP
		iptables -P OUTPUT  DROP
		iptables -P FORWARD DROP
		
		# Accept loopback
		iptables -A INPUT  -i lo -j ACCEPT
		iptables -A OUTPUT -o lo -j ACCEPT
	
		if [ $MODE == "TOR" ] && [ $WAN == "eth0" ]; then # LAN is wlan1, WAN is eth0, MODE is TOR
		
			# SSH access on wlan1
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 22 -j REDIRECT --to-ports 22
			# DNS out over TOR
			iptables -t nat -A PREROUTING -i wlan1 -p udp --dport 53 -j REDIRECT --to-ports 53
			# All tcp traffic on wlan1 to 9040 for TOR
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --syn -j REDIRECT --to-ports 9040
			# wlan1 internal, eth0 to internet
			#iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE # Enable nat routing on eth0
			#iptables -A FORWARD -i eth0 -o wlan1 -m state --state RELATED,ESTABLISHED # Accept incoming connections from eth0, if it's related to an existing outgoing connection from wlan1
			#iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT # Let wlan1 make outgoing connections through eth0
			

			
		

		
		elif [ $MODE == "TOR" ] && [ $WAN == "wlan0" ]; then # LAN is wlan1 and eth0, WAN is wlan0, MODE is TOR
		
			iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT # Let wlan1 talk to eth0
			iptables -A FORWARD -i eth0 -o wlan1 -j ACCEPT # Let eth0 talk to wlan1
			# SSH access on wlan1 and eth0
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 22 -j REDIRECT --to-ports 22
			iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-ports 22
			# DNS out over TOR
			iptables -t nat -A PREROUTING -i wlan1 -p udp --dport 53 -j REDIRECT --to-ports 53
			iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 53
			# All tcp traffic on wlan1 to 9040 for TOR
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --syn -j REDIRECT --to-ports 9040
			# All tcp traffic on eth0 to 9040 for TOR
			iptables -t nat -A PREROUTING -i eth0 -p tcp --syn -j REDIRECT --to-ports 9040
			
			# wlan1, eth0 internal, wlan0 to internet
			#iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE # Enable nat routing on wlan0
			#iptables -A FORWARD -i wlan0 -o wlan1 -m state --state RELATED,ESTABLISHED # Accept incoming connections from wlan0, if it's related to an existing outgoing connection from wlan1
			#iptables -A FORWARD -i wlan0 -o eth0 -m state --state RELATED,ESTABLISHED # Accept incoming connections from wlan0, if it's related to an existing outgoing connection from eth0
			#iptables -A FORWARD -i wlan1 -o wlan0 -j ACCEPT # Let wlan1 make outgoing connections through wlan0
			#iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT # Let eth0 make outgoing connections through wlan0



		

		
		elif [ $MODE == "VPN" ] && [ $WAN == "eth0" ]; then # LAN is wlan1, WAN is eth0, MODE is VPN
		
			# SSH access on wlan1 and eth0
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 22 -j REDIRECT --to-ports 22
			#iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-ports 22
			# wlan1 internal, tun0 to internet
			iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE # Enable nat routing on tun0
			iptables -A FORWARD -i tun0 -o wlan1 -m state --state RELATED,ESTABLISHED # Accept incoming connections from tun0, if it's related to an existing outgoing connection from wlan1
			iptables -A FORWARD -i wlan1 -o tun0 -j ACCEPT # Let wlan1 make outgoing connections through tun0

			
			
			
			
			
		
		elif [ $MODE == "VPN" ] && [ $WAN == "wlan0" ]; then # LAN is wlan1 and eth0, WAN is wlan0, MODE is VPN
		
			iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT # Let wlan1 talk to eth0
			iptables -A FORWARD -i eth0 -o wlan1 -j ACCEPT # Let eth0 talk to wlan1
			# SSH access on wlan1 and eth0
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 22 -j REDIRECT --to-ports 22
			iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-ports 22
			# wlan1, eth0 internal, tun0 to internet
			iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE # Enable nat routing on tun0
			iptables -A FORWARD -i tun0 -o wlan1 -m state --state RELATED,ESTABLISHED # Accept incoming connections from tun0, if it's related to an existing outgoing connection from wlan1
			iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED # Accept incoming connections from tun0, if it's related to an existing outgoing connection from eth0
			iptables -A FORWARD -i wlan1 -o tun0 -j ACCEPT # Let wlan1 make outgoing connections through tun0
			iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT # Let eth0 make outgoing connections through tun0


		
		
		
				
		# TODO: Tighten the following up so as to only allow http and https landing pages through.
		elif [ $MODE == "NONE" ] && [ $WAN == "eth0" ]; then # LAN is wlan1, WAN is eth0, MODE is NONE
			
			# SSH access on wlan1
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 22 -j REDIRECT --to-ports 22
			# wlan1 internal, eth0 to internet
			iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE # Enable nat routing on eth0
			#iptables -A FORWARD -i eth0 -o wlan1 -j ACCEPT # Allow everything incoming on eth0 to wlan1
			#iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT # Allow everything incoming on wlan1 to eth0
			iptables -A FORWARD -i eth0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT
			iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT
		




		
		elif [ $MODE == "NONE" ] && [ $WAN == "wlan0" ]; then # LAN is wlan1 and eth0, WAN is wlan0, MODE is NON

			iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT # Let wlan1 talk to eth0
			iptables -A FORWARD -i eth0 -o wlan1 -j ACCEPT # Let eth0 talk to wlan1
			# SSH access on wlan1 and eth0
			iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 22 -j REDIRECT --to-ports 22
			iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-ports 22
			# wlan1 internal, eth0 to internet
			iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE # Enable nat routing on eth0
			#iptables -A FORWARD -i wlan0 -o wlan1 -j ACCEPT # Allow everything incoming on wlan0 to wlan1
			#iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT # Allow everything incoming on wlan0 to eth0
			#iptables -A FORWARD -i wlan1 -o wlan0 -j ACCEPT # Allow everything incoming on wlan1 to wlan0
			#iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT # Allow everything incoming on eth0 to wlan0
			iptables -A FORWARD -i wlan0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
			iptables -A FORWARD -i wlan0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT
			iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT
			iptables -A FORWARD -i wlan1 -o wlan0 -j ACCEPT

		
		fi
		
		# Save iptable to file
		sh -c "iptables-save > $OUTPUT_CONFIG/iptables.ipv4.nat"
		error_quit $?
		cp -f $OUTPUT_CONFIG/iptables.ipv4.nat /etc/iptables.ipv4.nat
		error_quit $?
		
		#whiptail --title "REBOOT" --msgbox "The system will now reboot." 8 78
				
		reboot
	fi

}




function mainmenu
{
	TITLEBAR="Pinball Privacy Router Main Menu"
	choice=$(whiptail --title "$TITLEBAR" --menu "Choose an option" 22 78 16 \
				"INTERNET" "Change Internet Settings" \
				"MODE" "Toggle between TOR and VPN modes" \
				"AP" "Change your pinball AP settings" \
				"ADVANCE" "Advance configuration settings" \
				"RESTORE" "Restore previous configuration" \
				"SETUP" "Re-run the initial configuration script" \
				"UPDATE" "Update software" \
				"DONE" "Enact changes and reboot" \
				"QUIT" "Exit script without making any changes" \
				3>&1 1>&2 2>&3)

	case "$choice" in
		INTERNET)
			#error_msg incomplete
			internet_config
		;;
		MODE)
			#error_msg incomplete
			mode_config
		;;
		AP)
			#error_msg incomplete
			ap_config
		;;
		ADVANCE)
			#error_msg incomplete
			advance_config
		;;
		RESTORE)
			#error_msg incomplete
			restore_config
			#take config from PREVIOUS-CONFIG and put them back
		;;
		SETUP)
			error_msg incomplete
			#first_time
		;;
		UPDATE)
			run_updates
		;;
		DONE)
			#error_msg incomplete
			finalize
		;;
		QUIT)
			exit
		;;
	esac
}

# TODO: add conectivity check?



rootcheck
source pinball.cfg
while :
do
mainmenu
done
