#!/usr/bin/env bash

SSH_PORT=62222
OVPN_BASE_PORT=50000


IPv4_REGEXP='((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
# IPv6_REGEXP='(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
IPv6_REGEXP='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}'
declare -r HEX_DIGITS="0123456789abcdef"

# Interface to VPS provider
DEF_IFACE=$(ip r | grep default | grep -o 'dev.*' | cut -f2 -d ' ')
CWD=`pwd`

# Check root
if [[ "$EUID" -ne 0 ]]; then
	echo "ERROR: you need to run script as root!"
	exit 1
fi

# Check tun support
if [[ ! -e /dev/net/tun ]]; then
	echo "ERROR: The TUN device is not available
You need to enable TUN before running script"
	exit 1
fi


set_ipv4 () {
	arr_ipv4=(`ip a s dev $DEF_IFACE | grep -Eo 'inet [^ ]*' | grep -Eo $IPv4_REGEXP`)
	echo
	echo You have the following IPv4 addresses:
	i=0
	for adr in ${arr_ipv4[@]}; do echo "$((i+1)))" ${arr_ipv4[$i]}; i=$((i+1)); done
	i=$((i+1))
	echo "$i)" custom IPv4
	echo
	read -p "Chose IPv4: " opt_num
	if [[ "$opt_num" -eq $i ]]; then set_custom_ipv4
	else ipv4=${arr_ipv4[$((opt_num-1))]}
	fi
}

set_custom_ipv4 () {
	echo
	read -p "IPv4 address: " ipv4_input
	ipv4_input=`echo $ipv4_input | tr -d ' '`
	ipv4=`echo $ipv4_input | grep -Eo $IPv4_REGEXP`
	if [ "$ipv4_input" != "$ipv4" ]; then echo "Wrong IPv4!" 1>&2; exit 1; fi

	# Add custom IPv4 address to interface
	ip a add $ipv4 dev $DEF_IFACE

	# Test IPv4 is OK
	echo -e -n "Checking IP $ipv4, please wait ... "
	sleep 3
	ping -W2 -c2 -I $ipv4 1.1.1.1 &>/dev/null
	if [ $? -ne 0 ]; then
		echo FAIL
		ip a del $ipv4/32 dev $DEF_IFACE
		exit 1
	else
		echo OK
		# Make IPv4 survive reboot
		cp /etc/rc.local /etc/rc.local.bak
		sed -n '1,/^exit 0/p' /etc/rc.local.bak | head -n -1 > /etc/rc.local
		echo "ip a add $ipv4 dev $DEF_IFACE" >> /etc/rc.local
		sed -n '/^exit 0/,$p' /etc/rc.local.bak >> /etc/rc.local
		rm /etc/rc.local.bak
	fi
}

set_ipv6 () {
	arr_ipv6=(`ip a s dev $DEF_IFACE | grep -Eo 'inet6 [^ ]*' | grep -Eo $IPv6_REGEXP | grep -E '^2|^3'`)
	echo
	echo You have the following IPv6 addresses:
	i=0
	for adr in ${arr_ipv6[@]}; do echo "$((i+1)))" ${arr_ipv6[$i]}; i=$((i+1)); done
	i=$((i+1))
	echo "$i)" custom IPv6
	echo 
	read -p "Chose IPv6 (0 to disable): " opt_num
	if [[ "$opt_num" -eq 0 ]]; then ipv6=""
	elif [[ "$opt_num" -eq $i ]]; then set_custom_ipv6
	else ipv6=${arr_ipv6[$((opt_num-1))]}
	fi
}

set_custom_ipv6 () {
	echo
	read -p "IPv6 address: " ipv6_input
	ipv6_input=`echo $ipv6_input | tr -d ' '`
	ipv6=`echo $ipv6_input | grep -Eo $IPv6_REGEXP`
	if [ "$ipv6_input" != "$ipv6" ]; then echo "Wrong IPv6!" 1>&2; exit 1; fi

	# Add custom IPv6 address to interface
	ip a add $ipv6 dev $DEF_IFACE

	# Test IPv6 is OK
	echo -e -n "Checking IP $ipv6, please wait ... "
	sleep 3
	ping6 -W2 -c2 -I $ipv6 2606:4700:4700::1111 &>/dev/null
	if [ $? -ne 0 ]; then
		echo FAIL
		ip a del $ipv6 dev $DEF_IFACE
		exit 1
	else
		echo OK
		# Make IPv6 survive reboot
		cp /etc/rc.local /etc/rc.local.bak
		sed -n '1,/^exit 0/p' /etc/rc.local.bak | head -n -1 > /etc/rc.local
		echo "ip a add $ipv6 dev $DEF_IFACE" >> /etc/rc.local
		sed -n '/^exit 0/,$p' /etc/rc.local.bak >> /etc/rc.local
		rm /etc/rc.local.bak
	fi
}

set_mtu () {
	echo
	echo "Set MTU value (e.g. 1500) or leave blank for default value."
	echo
	read -p "MTU: " -e mtu
	case $mtu in 
	[0-9]*) echo Setting MTU = $mtu
	;;
	"") echo Setting MTU to default value
	;;
	*) echo "Wrong MTU! Setting MTU to default value"
	   mtu=""
	esac
}

set_dns () {
	echo
	echo "Chose DNS option:"
	echo "1) Custom DNS"
	echo "2) Native DNS"
	echo "3) Cloudflare"
	echo
	read -p "DNS [1-3]: " opt_num
	case $opt_num in
	1) set_custom_dns
	;;
	2) set_native_dns
	;;
	3) set_cloudflare_dns
	;;
	*) echo "Wrong choise! Set to Cloudflare DNS!" 1>&2; set_cloudflare_dns;
	esac
}

set_custom_dns () {
	echo
	echo "Input DNS one per line. Blank line terminates input."
	dns=()
	while read line; do
		if [ -z "$line" ]; then break; fi
		line_dns=`echo $line | grep -Eo "$IPv4_REGEXP|$IPv6_REGEXP"`
		if [ "$line_dns" != "$line" ]; then echo "Wrong DNS!"; continue; fi
		dns+=("$line")
	done
	# Check custom DNS
	for d in ${dns[@]}; do
		echo -e -n "Checking DNS $d ... "
		dig +time=2 @$d google.com &>/dev/null
		if [ $? -eq 0 ]; then echo OK; else echo FAIL; fi
	done
}

set_native_dns () {
	# https://github.com/vektort13/openvpn-install
	# Locate the proper resolv.conf
	# Needed for systems running systemd-resolved
	if grep -q "127.0.0.53" "/etc/resolv.conf"; then
	RESOLVCONF='/run/systemd/resolve/resolv.conf'
	else
	RESOLVCONF='/etc/resolv.conf'
	fi
	# Obtain the resolvers from resolv.conf and use them for OpenVPN
	dns=(`grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'`)
}

set_cloudflare_dns () {
	dns=(1.1.1.1 1.0.0.1)
}


install_ovpn () {
	echo
	echo Installing OpenVPN. Please wait ...
	apt update -y && apt upgrade -y
	apt install -y curl openvpn easy-rsa net-tools iputils-ping dnsutils nftables zip python3

	# Download concatenating script
	mkdir -p /etc/openvpn/all_clients
	wget -4 https://raw.githubusercontent.com/ku4in/aux/main/conf2ovpn.py -O /etc/openvpn/all_clients/conf2ovpn.py
	chmod +x /etc/openvpn/all_clients/conf2ovpn.py

	# OpenVPN server setup
	mkdir -p /etc/openvpn/easy-rsa
	cd /etc/openvpn/easy-rsa
	cp -R /usr/share/easy-rsa /etc/openvpn/
	./easyrsa init-pki
	./easyrsa build-ca nopass << EOF
server
EOF
	./easyrsa gen-dh
	openvpn --genkey --secret /etc/openvpn/easy-rsa/pki/ta.key
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa gen-crl
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass << EOF
yes
EOF
	cp ./pki/ca.crt /etc/openvpn/ca.crt
	cp ./pki/dh.pem /etc/openvpn/dh.pem
	cp ./pki/crl.pem /etc/openvpn/crl.pem
	cp ./pki/ta.key /etc/openvpn/ta.key
	cp ./pki/issued/server.crt /etc/openvpn/server.crt
	cp ./pki/private/server.key /etc/openvpn/server.key

	# Issuing client certificate
	cd /etc/openvpn/easy-rsa
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full client nopass << EOF
yes
EOF
	# Enable forwarding
	echo 1 > /proc/sys/net/ipv4/ip_forward
	sed -i '/net.ipv4.ip_forward=1/s/#//' /etc/sysctl.conf
	echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	sed -i '/net.ipv6.conf.all.forwarding=1/s/#//' /etc/sysctl.conf

	# Change ssh port
	sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
	systemctl daemon-reload
	systemctl restart ssh.service

	# Setup firewall rules
	cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state established,related accept
		meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, ind-neighbor-solicit, ind-neighbor-advert, mld2-listener-report } accept
		meta l4proto icmp icmp type { destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem } accept
		tcp dport $SSH_PORT accept
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
table inet ovpn {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
	}
}
EOF
	systemctl enable nftables.service
	systemctl start nftables.service
	/etc/nftables.conf

	# Set flag that script has already been invoked
	touch /etc/openvpn/jg1Ca5Zt0VbGF68E.txt

	echo
	echo "********************************************"
	echo "*     OpenVPN SUCCESSFULLY INSTALLED!      *"
	echo "* Attention! SSH port was changed to $SSH_PORT *"
	echo "********************************************"
}


create_config (){
	echo Creating NEW client config ...
	if [ -z "$(ls -l /etc/openvpn/ | grep 'server.*[.]conf')" ];then conf_num=1
	else
		conf_num=`ls /etc/openvpn/server*.conf | grep -Eo '[0-9]+' | sort -n | tail -1`
		if [[ -z "$conf_num" ]]; then conf_num=1; fi
		conf_num=$((conf_num + 1))
	fi

	set_ipv4
	set_ipv6
	set_dns
	set_mtu

	# make SERVER config
	cd /etc/openvpn
	cat > server$conf_num.conf << EOF
port $((OVPN_BASE_PORT + conf_num))
proto udp
dev tun$conf_num
local $ipv4
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.$((conf_num/256%255)).$((conf_num%256)).0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp$conf_num.txt
push "redirect-gateway def1 bypass-dhcp"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
persist-key
persist-tun
status /var/log/openvpn/openvpn-status$conf_num.log
log /var/log/openvpn/openvpn$conf_num.log
verb 3
explicit-exit-notify 1
sndbuf 0
rcvbuf 0
comp-lzo
EOF

	# Add DNS to server config
	for d in ${dns[@]}; do
		echo "push \"dhcp-option DNS $d\"" >> /etc/openvpn/server$conf_num.conf
	done

	# Add IPv6 to server config
	if [ ! -z "$ipv6" ]; then 
		# Make IPv6 prefix
		byte1=$((conf_num % 16))
		byte2=$((conf_num/16 % 16))
		byte3=$((conf_num/256 % 16))
		byte4=$((conf_num/4096 % 16))
		prefix=fd00:${HEX_DIGITS:$byte4:1}${HEX_DIGITS:$byte3:1}${HEX_DIGITS:$byte2:1}${HEX_DIGITS:$byte1:1}
		echo server-ipv6 $prefix::/64 >> /etc/openvpn/server$conf_num.conf
		echo tun-ipv6 >> /etc/openvpn/server$conf_num.conf
		echo push tun-ipv6 >> /etc/openvpn/server$conf_num.conf
		echo ifconfig-ipv6 $prefix::1 :: >> /etc/openvpn/server$conf_num.conf
		echo "push \"route-ipv6 2000::/3\"" >> /etc/openvpn/server$conf_num.conf
	fi

	# Make client config
	mkdir -p /etc/openvpn/all_clients/client$conf_num
	cp /etc/openvpn/easy-rsa/pki/ta.key /etc/openvpn/all_clients/client$conf_num
	cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/all_clients/client$conf_num
	cp /etc/openvpn/easy-rsa/pki/issued/client.crt /etc/openvpn/all_clients/client$conf_num
	cp /etc/openvpn/easy-rsa/pki/private/client.key /etc/openvpn/all_clients/client$conf_num

	cd /etc/openvpn/all_clients/client$conf_num

	# Select custom client config name
	read -p "Client config file name (without extention): " -e -i "client$conf_num" custom_conf_name

	# make client config
cat > ${custom_conf_name}.conf << EOF
client
dev tun
proto udp
remote $ipv4 $((OVPN_BASE_PORT+conf_num))
# remote $ipv6
resolv-retry infinite
keepalive 10 120
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
key-direction 1
tls-auth ta.key 1
cipher AES-256-CBC
verb 3
sndbuf 0
rcvbuf 0
comp-lzo
EOF
	# Add MTU to server and client configs
	if [[ ! -z "$mtu" ]]; then
	cat >> /etc/openvpn/server$conf_num.conf << EOF
fragment $mtu
mssfix 0
EOF
	cat >> /etc/openvpn/all_clients/client$conf_num/${custom_conf_name}.conf << EOF
fragment $mtu
mssfix 0
EOF
	fi

	# concatenate client config files into .ovpn
	cd /etc/openvpn/all_clients/client${conf_num}
	cp ../conf2ovpn.py .
	./conf2ovpn.py
	rm -f conf2ovpn.py ca.crt client.crt client.key ta.key ${custom_conf_name}.conf

	# Save client config to custom under custom name
	mkdir -p $CWD/clients
	cp /etc/openvpn/all_clients/client$conf_num/${custom_conf_name}.ovpn $CWD/clients/

	# Setup firewall
	# Open OpenVPN port
	nft add rule inet filter input udp dport $((OVPN_BASE_PORT+conf_num)) accept

	# Add srcnat rules to firewall
	nft add rule inet ovpn postrouting iifname tun$conf_num oif $DEF_IFACE snat ip to $ipv4
	if [ ! -z "$ipv6" ]; then
	nft add rule inet ovpn postrouting iifname tun$conf_num oif $DEF_IFACE snat ip6 to $ipv6
	fi
	echo '#!/usr/sbin/nft -f' > /etc/nftables.conf
	echo 'flush ruleset' >> /etc/nftables.conf
	nft -s list ruleset >> /etc/nftables.conf
	# Reload firewall
	chmod +x /etc/nftables.conf
	/etc/nftables.conf 

	# Start OpenVPN server and enable it on boot
	systemctl enable openvpn@server$conf_num &>/dev/null
	systemctl start openvpn@server$conf_num
}


show_all_configs () {
	arr_conf_num=(`for name in  /etc/openvpn/all_clients/client*/; do echo $name | grep -Eo '[0-9]+'; done`)
	echo
	echo "---All configs---"
	for conf_num in  ${arr_conf_num[@]}; do echo -e -n "$conf_num) "; ls /etc/openvpn/all_clients/client$conf_num/ | sed 's/\(.*\)[.]ovpn/\1/'; done
}

del_config () {
	show_all_configs
	echo
	read -p "Chose config to delete: " conf_num
	systemctl disable openvpn@server$conf_num &>/dev/null
	systemctl stop openvpn@server$conf_num
	> /etc/openvpn/server$conf_num.conf
	rm -rf /etc/openvpn/all_clients/client$conf_num
	sed -i "/udp dport $((OVPN_BASE_PORT+conf_num))/d" /etc/nftables.conf
	sed -i "/tun$conf_num/d" /etc/nftables.conf
	# Reload firewall
	/etc/nftables.conf 
}



#############
# MAIN LOOP #
#############

# Check if OpenVPN allready installed
if [[ ! -f /etc/openvpn/jg1Ca5Zt0VbGF68E.txt ]]; then
	install_ovpn
else
	echo
	echo OpenVPN is allready installed
fi

# Show menu
# echo "####################################"
while :; do
echo 
echo Chose what you want:
echo "1) Create NEW config"
echo "2) Show ALL configs"
echo "3) DELETE config"
echo "4) EXIT"
echo 

read -p "Your chois [1-4]: " option
case $option in
	1)
	create_config
	;;
	2)
	show_all_configs
	echo
	read -p "Press ENTER to continue " dummy
	;;
	3)
	del_config
	;;
	*)
	break
	;;
esac
if [ "$option" -eq 1 -o "$option" -eq 3 ]; then
echo 
echo "**********************"
echo "* SUCCESSFULLY DONE! *"
echo "**********************"
fi

done

echo
echo "GOODBYE!"
echo
