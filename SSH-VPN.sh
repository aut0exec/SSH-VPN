#!/usr/bin/env bash
#    Name: SSH-VPN.sh
#  Author: Aut0exec
#    Date: July 11, 2022
# Version: 1.0
# Purpose: Script sets up an SSH tunnel to allow a remote network to be accessible locally
#
#   Reqs: User running script needs to be EUID 0
#		  sshd_config on remote end needs: PermitTunnel yes
#		  Root needs to be able to login via SSH on remote end
#		  - SSHD defaults to root login with RSA
#		  Root private key needs to be available locally
#			- Password Authentication is a bad idea...
#		  Public key needs to be in /root/.ssh/authorized_keys on remote end
#
# Issues: Only supports IPv4 currently
#		  DONE - Need to add support for ssh-agent
#		  DONE - Need to add support for ssh-add for adding pub keys
#		  DONE - Add functionality to auto add network route for chosen interface/subnet
#		  Add ARGV/Getopts support
#

build_iptables(){

	local action="$1"
	local ipt_act='-D'
	local sys_act=0

	if [ "$action" == 'add' ]; then
		ipt_act='-A'
		sys_act=1
	fi
	ipt_comm="iptables $ipt_act FORWARD -i $TAP_IF -o $REMOTE_NET_IF -j ACCEPT && "
	ipt_comm+="iptables $ipt_act FORWARD -i $REMOTE_NET_IF -o $TAP_IF -j ACCEPT && "
	ipt_comm+="iptables -t nat $ipt_act POSTROUTING -s ${LOCAL_TUN_IP}/32 -o $REMOTE_NET_IF -j MASQUERADE && "
	ipt_comm+="echo $sys_act > /proc/sys/net/ipv4/conf/${TAP_IF}/forwarding && "
	ipt_comm+="echo $sys_act > /proc/sys/net/ipv4/conf/${REMOTE_NET_IF}/forwarding"	

	echo "$ipt_comm"
}

# Expects RAD_IP and RSA_KEY
check_tun_conf() {

	local check=$(run_ssh_comm "grep PermitTunnel /etc/ssh/sshd_config")

	if [[ "${check,,}" =~ (^#|^permittunnel *no) ]]; then
		error_msg "Tunneling disabled on ${1}!\nEnsure 'PermitTunnel yes' is set in sshd_config."
		exit 2
	elif [ -z "$check" ]; then
		error_msg "Unable to read SSHD configuration!"
		read -n2 -p "Attempt to continue anyways [y/n]? " ANS
		ANS=${ANS,,}
		[ ${ANS:0:1} == 'y' ] || exit 1;
		clear
	else
		info_msg "Appears tunneling is available.\n"
	fi

	return 0
}

command_check() {

	for (( i = 0; i < ${#COMMANDS[@]}; i++ ))
	do
		command -v "${COMMANDS[i]}" > /dev/null 2>&1 || { error_msg "$PROGNAME requires the utility ${COMMANDS[i]} but it could not be found! \n\r"; exit 1; }
	done
}

exit_sigs() {

	echo -e "\nExiting..."
	[ -z $TUN_PID ] || ssh_kill_tun
	exit 0
}

error_msg() {

	local red='\e[1;31m'
	local  nc='\e[0m'
	local msg="$1"

	echo -e "${red}ERROR:${nc} $msg"
}

get_priv_key() {

	while [ -z $RSA_KEY ];
	do
		read -p "Please enter path to RSA Private key: " ans
		test_priv_key $ans
		if [ $? -eq 0 ]; then
			RSA_KEY="$ans"
		else
			try_again "$ans doesn't appear to be a SSH private key!"
		fi
	done
}

get_rad_ip() {

	local ans=''

	while [ -z $RAD_IP ];
	do
		read -p "Please enter a valid IPv4 address for the RAD: " ans
		test_ip $ans
		if [ $? -eq 0 ]; then
			RAD_IP="$ans"
		else
			try_again "$ans isn't a valid IPv4 address!"
		fi
	done
}

get_rem_net_if() {

	while [ -z $REMOTE_NET_IF ];
	do
		echo -e "Available remote intefaces: ${REM_INFS[@]} \n"
		read -p "Which interface is the remote network of interest: " ans

		test_rem_inf "$ans"
		if [ $? -eq 0 ]; then
			REMOTE_NET_IF="$ans"
		else
			try_again "$ans isn't a valid interface on the remote system!"
		fi
	done
}

get_remote_ifs() {

	REM_INFS=( $(run_ssh_comm "ls /proc/sys/net/ipv4/conf/") )
	declare -a bad_infs=( 'lo*' 'all*' 'default*' )

	for inf in "${bad_infs[@]}"
	do
		REM_INFS=( ${REM_INFS[@]/$inf/} )
	done
}

info_msg() {

	local green='\e[1;32m'
	local  nc='\e[0m'
	local msg="$1"

	echo -en "${green}INFO:${nc} $msg"
}

remote_routes() {

	local action="$1"
	local ipr_act='del'

	if [ "$action" == 'add' ]; then
		ipr_act='add'
	fi

	local oifs=$IFS
	IFS=$'\n'
	local net_info=( $(run_ssh_comm "ip -4 -o route show dev $REMOTE_NET_IF") )
	net_info=( ${net_info[@]/default*/} )
	IFS="$oifs"

	for ((i=0; i < ${#net_info[@]}; i++))
	do
		cidr="${net_info[$i]%%[a-zA-Z]*}"
		info_msg "${ipr_act}'ing route for remote network: $cidr \n"
		ip route $ipr_act $cidr dev $TAP_IF via $REMOTE_TUN_IP
	done
}

run_ssh_comm() {

	local command="$1"
	ssh -q root@$RAD_IP -i "$RSA_KEY" "$command"
}

ssh_load_key() {

	eval $(ssh-agent -s) 2&> /dev/null
	info_msg "Loading ssh key. Will prompt for key passphrase if needed.\n"
	ssh-add $RSA_KEY
}

ssh_spawn_tun() {

	ssh -q -o Tunnel=ethernet -o ExitOnForwardFailure=yes -f -w 7:7 root@$RAD_IP -i "$RSA_KEY" true
	#~ ssh -q -o ExitOnForwardFailure=yes -f -w 7:7 root@$RAD_IP -i "$RSA_KEY" true
	TUN_PID=$(pgrep -f "${RAD_IP}.*${RSA_KEY}")
	[ ! -z $TUN_PID ] || return 1
}

ssh_kill_tun() {
	local remove_ipt_cmd=$(build_iptables)
	info_msg "Removing remote iptables entries: "
	run_ssh_comm "$remove_ipt_cmd"
	[ $? -eq 0 ] && echo "Done." || echo "ERROR!"
	info_msg "Removing ssh tunnel and agent sessions: "
	kill $TUN_PID && $(ssh-agent -k)
	[ $? -eq 0 ] && echo "Done." || echo "ERROR!"
}

test_ip() {

	local ip="$1"
	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		OIFS=$IFS
		IFS='.'
		ip=($ip)
		IFS=$OIFS
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
		return $?
	fi
	return 1
}

test_priv_key() {

	shopt -s nocasematch

	if [[ $(file -b "$1") =~ 'OpenSSH private key' ]]; then
		return 0
	else
		return 1
	fi

	shopt -u nocasematch
}

test_rem_inf() {

	local user_inf="$1"

	for inf in "${REM_INFS[@]}"
	do
		if [ "$inf" == "$user_inf" ]; then
			return 0
		fi
	done
	return 1
}

try_again() {

	local err_msg="$1"

	error_msg "$err_msg"
	read -n2 -p "Try again [y/n]? " ans
	ans=${ans,,}
	[ ${ans:0:1} == 'y' ] || exit 1;
	clear
}

usage() {

    echo -e "Usage: $PROGNAME "

	exit 99
}

user_privs() {

	if [ $EUID -ne 0 ]; then
		error_msg "$PROGNAME needs to be run as root or with root privileges!"
		exit 1;
	fi
	return 0
}

warn_msg() {

	local green='\e[1;33m'
	local  nc='\e[0m'
	local msg="$1"

	echo -en "${green}WARN:${nc} $msg"
}

##################### Main ########################
clear
stty -echoctl
trap 'exit_sigs' 1 2 3 15 20
umask 0027

PATH='/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin'
PROGNAME=$(basename "$0")
COMMANDS=( ssh ssh-agent ssh-add file pgrep ifconfig ip )
declare -a REM_INFS

# Interface that is connected to remote network of interest
REMOTE_NET_IF=''
TAP_IF='tap7'
RAD_IP=''
RSA_KEY=''

# Use RFC 5735 space to avoid conflicts
# !!!Only mess with this if you know the remote network and what you're doing!!!
LOCAL_TUN_IP='198.18.0.1'
REMOTE_TUN_IP='198.18.0.2'
TUN_NETMASK='255.255.255.252'
TUN_PID=''

user_privs
command_check

if [ ! -z "$RSA_KEY" ]; then
	test_priv_key "$RSA_KEY" || { unset RSA_KEY; error_msg "Invalid Private key!\n" && get_priv_key; }
else
	get_priv_key
fi

ssh_load_key

if [ ! -z "$RAD_IP" ]; then
	test_ip "$RAD_IP" || { unset RAD_IP; error_msg "Invalid IPv4 Address!\n" && get_rad_ip; }
else
	get_rad_ip
fi

info_msg "Checking configuration on remote end.\n"
check_tun_conf $RAD_IP "$RSA_KEY"
get_remote_ifs

if [ ! -z "$REMOTE_NET_IF" ]; then
	test_rem_inf "$REMOTE_NET_IF" || { unset REMOTE_NET_IF; error_msg "Invalid remote interface!\n" && get_rem_net_if; }
else
	get_rem_net_if
fi

ssh_spawn_tun

if [ $? -eq 0 ]; then
	info_msg "Configuring tunnel for IP based communication.\n"

	ifconfig $TAP_IF $LOCAL_TUN_IP netmask $TUN_NETMASK || { error_msg "Failed to assign $TAP_IF address of $LOCAL_TUN_IP."; exit_sigs; }
	rem_ifconfig="ifconfig $TAP_IF $REMOTE_TUN_IP netmask $TUN_NETMASK"


	rem_forward_rules=$(build_iptables "add")
	run_ssh_comm "${rem_ifconfig} && ${rem_forward_rules}" || { error_msg "Issue setting up forwarding on the remote end."; exit_sigs ;}
	remote_routes "add"

	info_msg "Tunnel appears to be available; PID - $TUN_PID.\n\n"
	warn_msg "Make sure to add additional routes locally for remote networks as needed!"
	echo -e "Syntax would be similar to:\n\r\tip route add <REMOTE_NETWORK> dev $TAP_IF via $REMOTE_TUN_IP"
	echo -e "\nPress ctrl+c when done to tear down tunnel."
	read -r -d '' _
else
	error_msg "Issue creating tunnel. Aborting!"
	ssh_kill_tun
	exit 5
fi

# Catch all...
ssh_kill_tun
