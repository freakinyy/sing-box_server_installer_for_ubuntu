#!/bin/bash

TMP_DIR="/tmp"

Add_To_New_Line(){
	if [ "$(tail -n1 $1 | wc -l)" == "0"  ];then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

Check_And_Add_Line(){
	if [ -z "$(cat "$1" | grep "$2")" ];then
		Add_To_New_Line "$1" "$2"
	fi
}

get_my_ip(){
	local my_ip=$(ifconfig | grep "inet" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed -n 1p)
	echo $my_ip
}

Update_Upgrade_Packages(){
	echo "#############################################"
	echo "Update Packages..."
	apt update
	apt upgrade -y
	apt dist-upgrade -y
	apt autoremove -y
	apt autoclean -y
	echo "Update Packages Done."
	if [ -f /var/run/reboot-required ];then 
		echo "Will Reboot in 5s!!!"
		sleep 5
		reboot
	fi
	echo "Install Packages Done."
	echo "#############################################"
}

Install_Bin(){
	wget https://github.com/freakinyy/sing-box_server_installer_for_ubuntu/raw/main/sing-box_bin_installer.sh%40amd64 -O sing-box_bin_installer.sh
	mv sing-box_bin_installer.sh /usr/bin
	chmod +x /usr/bin/sing-box_bin_installer.sh
	sing-box_bin_installer.sh install
}

Uninstall_Bin(){
	sing-box_installer.sh uninstall
	rm -f /usr/bin/sing-box_bin_installer.sh
}

Install_Rng_tools(){
	echo "#############################################"
	echo "Install Rng-tools..."
	apt install --no-install-recommends virt-what -y
	echo "Your Virtualization type is $(virt-what)"
	if [ "$(virt-what)" != "kvm" -a "$(virt-what)" != "hyperv" ];then
		echo "Rng-tools can not be used."
		echo "#############################################"
		return 1
	fi
	apt install rng-tools -y
	Check_And_Add_Line "/etc/default/rng-tools" "HRNGDEVICE=/dev/urandom"
	service rng-tools stop
	service rng-tools start
	echo "Install Rng-tools Done."
	echo "#############################################"
}

Install_BBR(){
	echo "#############################################"
	echo "Install TCP_BBR..."
	if [ -n "$(lsmod | grep bbr)" ];then
		echo "TCP_BBR already installed."
		echo "#############################################"
		return 1
	fi
	local kernel_version=$(uname -r | grep -oE '[0-9]\.[0-9]' | sed -n 1p)
	local can_use_BBR="0"
	if [ "echo $kernel_version | cut -d"." -f1" > "4" ];then
		can_use_BBR="1"
	elif [ "echo $kernel_version | cut -d"." -f1" == "4" ];then
		if [ "echo $kernel_version | cut -d"." -f2" >= "9" ];then
			can_use_BBR="1"
		fi
	fi
	if [ "$can_use_BBR" == "1" ];then
		echo "Your Kernel Version $(uname -r) >= 4.9"
	else
		echo "Your Kernel Version $(uname -r) < 4.9"
		echo "TCP_BBR can not be used."
		echo "#############################################"
		return 1
	fi
	apt install --no-install-recommends virt-what -y
	echo "Your Virtualization type is $(virt-what)"
	if [ "$(virt-what)" != "kvm"  && "$(virt-what)" != "hyperv" ];then
		echo "TCP_BBR can not be used."
		echo "#############################################"
		return 1
	fi
	echo "TCP_BBR can be used."
	echo "Start to Install TCP_BBR..."
	modprobe tcp_bbr
	Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
	Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
	Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
	sysctl -p
	if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ];then
		echo "TCP_BBR Install Success."
	else
		echo "Fail to Install TCP_BBR."
	fi
	echo "#############################################"
}

Optimize_Parameters(){
	echo "#############################################"
	echo "Optimize Parameters..."
	Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 51200"
	Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 51200"
	Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
	Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_all = 1"
	Check_And_Add_Line "/etc/sysctl.conf" "fs.file-max = 51200"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_max_backlog = 250000"
	Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn = 4096"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_syncookies = 1"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse = 1"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_recycle = 0"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout = 30"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time = 1200"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_local_port_range = 10000 65000"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 8192"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets = 5000"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fastopen = 3"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mem = 25600 51200 102400"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rmem = 4096 87380 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_wmem = 4096 65536 67108864"
	Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing = 1"
	echo "Optimize Parameters Done."
	echo "#############################################"
}

Create_Json(){
	echo "#############################################"
	echo "Create json path and file..."
	if [ -d /etc/sing-box_server/ ];then
		json_files=$(ls /etc/sing-box_server/ | grep ".json$" )
		if [ -n "$json_files" ];then
			echo "Json path and file already exit, abort."
			echo "#############################################"
			return 1
		else
			rm -rf /etc/sing-box_server/
		fi
	fi
	mkdir -p /etc/sing-box_server/
	local key_pair=$(sing-box generate reality-keypair)
	local private_key=$(echo $key_pair | cut -d " " -f2)
	local public_key=$(echo $key_pair | cut -d " " -f4)
	apt install openssl -y
	local short_id=$(openssl rand -hex 8)
	local uuid=$(sing-box generate uuid)
	touch /etc/sing-box_server/vless_reality.json
	cat >> /etc/sing-box_server/vless_reality.json <<EOF
{
	"log": {
		"disabled": true,
		"level": "warn",
		"output": "",
		"timestamp": true
	},
	"inbounds": [
		{
			"type": "vless",
			"tag": "in-vless",
			"listen": "::",
			"listen_port": 443,
			"tcp_fast_open": true,
			"users": [
				{
					"uuid": "$uuid",
					"flow": "xtls-rprx-vision"
				}
			],
			"tls": {
				"enabled": true,
				"server_name": "www.microsoft.com",
				"reality": {
					"enabled": true,
					"handshake": {
						"server": "www.microsoft.com",
						"server_port": 443
					},
					"private_key": "$private_key",
					"short_id": [
						"$short_id"
					]
				}
			}
		}
	],
	"outbounds": [
		{
			"type": "direct",
			"tag": "out-direct"
		}
	]
}
EOF
	echo "Create json path and file Done."
	echo "#############################################"
	Show_Client_Outbound $public_key $short_id $uuid
}

Show_Client_Outbound(){
	echo "#############################################"
	echo "Your client outbound should be:"
	local public_key=$1
	local short_id=$2
	local uuid=$3
	local $server=$(get_my_ip)
	echo << EOF
{
	"type": "vless",
	"tag": "out-vless",
	"server": "$server",
	"server_port": 443,
	"uuid": "$uuid",
	"flow": "xtls-rprx-vision",
	"tls": {
		"enabled": true,
		"disable_sni": false,
		"server_name": "www.microsoft.com",
		"insecure": false,
		"utls": {
			"enabled": true,
			"fingerprint": "chrome"
		},
		"reality": {
			"enabled": true,
			"public_key": "$public_key",
			"short_id": "$short_id"
		}
	},
	"packet_encoding": "xudp"
}
EOF
	echo "#############################################"
}

Remove_Json(){
	echo "#############################################"
	echo "Remove json path and file..."
	rm -rf /etc/sing-box_server/
	echo "Remove json path and file Done."
	echo "#############################################"
}

Create_Service(){
	echo "#############################################"
	echo "Create Service..."
	if [ -f /etc/init.d/sing-box_server ];then
		service sing-box_server stop
		update-rc.d -f sing-box_server remove
		rm -f /etc/init.d/sing-box_server
	fi
	wget https://github.com/freakinyy/sing-box_server_installer_for_ubuntu/raw/main/sing-box_server.service%40ubuntu -O sing-box_server.service@ubuntu
	mv sing-box_server.service@ubuntu /etc/init.d/sing-box_server
	chmod +x /etc/init.d/sing-box_server
	update-rc.d -f sing-box_server defaults 95
	echo "Create Service Done."
	echo "#############################################"
}

Remove_Service(){
	echo "#############################################"
	echo "Remove Service..."
	service sing-box_server stop
	update-rc.d -f sing-box_server remove
	rm -f /etc/init.d/sing-box_server
	echo "Remove Service Done."
	echo "#############################################"
}

Add_to_Crontab(){
	echo "#############################################"
	echo "Add updates-and-upgrades to crontab, you should modify these items and their schedules at your own favor..."
	rm -f $TMP_DIR/crontab.bak
	touch $TMP_DIR/crontab.bak
	crontab -l >> $TMP_DIR/crontab.bak
	
	local start_line_num=$(grep -n "#sing-box_server modifies start" $TMP_DIR/crontab.bak | cut -d":" -f1)
	local end_line_num=$(grep -n "#sing-box_server modifies end" $TMP_DIR/crontab.bak | cut -d":" -f1)
	if [ -n "$start_line_num" ] || [ -n "$end_line_num" ];then
		echo "It seems that crontab has already modified by this scprit, abort."
		echo "Please Check Crontab!!!"
		echo "#############################################"
		return 1
	fi
	
	cat >> $TMP_DIR/crontab.bak <<EOF
#sing-box_server modifies start
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
20 04 * * * apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean
40 04 * * * [ -f /var/run/reboot-required ] && reboot
50 04 * * * sing-box_bin_installer.sh update
#sing-box_server modifies end
EOF
	crontab $TMP_DIR/crontab.bak
	echo "Add updates-and-upgrades to crontab Done."
	echo "#############################################"
}

Remove_from_Crontab(){
	echo "#############################################"
	echo "Remove updates-and-upgrades from crontab..."
	rm -f $TMP_DIR/crontab.bak
	touch $TMP_DIR/crontab.bak
	crontab -l >> $TMP_DIR/crontab.bak
	local start_line_num=$(grep -n "#sing-box_server modifies start" $TMP_DIR/crontab.bak | cut -d":" -f1)
	local end_line_num=$(grep -n "#sing-box_server modifies end" $TMP_DIR/crontab.bak | cut -d":" -f1)
	[ -n "$start_line_num" ] && [ -n "$end_line_num" ] && sed -i ''"$start_line_num"','"$end_line_num"'d' $TMP_DIR/crontab.bak
	crontab $TMP_DIR/crontab.bak
	echo "Remove updates-and-upgrades from crontab Done."
	echo "#############################################"
}

Do_Install(){
	echo "#########################################################################"
	echo "Start Install sing-box_server..."
	service sing-box_server stop
	Update_Upgrade_Packages
	Install_Bin
	Install_Rng_tools
	Install_BBR
	Optimize_Parameters
	Create_Json
	Create_Service
	Add_to_Crontab
	service sing-box_server start
	Show_Client_Outbound
	echo "All Install Done!"
	echo "#########################################################################"
}

Do_Uninstall(){
	echo "#########################################################################"
	echo "Start Uninstall sing-box_server..."
	service sing-box_server stop
	Remove_from_Crontab
	Remove_Service
	Remove_Json
	Uninstall_Bin
	echo "All Uninstall Done!"
	echo "#########################################################################"
}

Do_Re_InstallService(){
	echo "#########################################################################"
	echo "Start Re-Install sing-box_server Service..."
	service sing-box_server stop
	Remove_Service
	Create_Service
	service sing-box_server start
	echo "Re-Install Service Done!"
	echo "#########################################################################"
}

case "$1" in
install)			Do_Install
					;;
uninstall)			Do_Uninstall
					;;
optimizeparameters)	Optimize_Parameters
					;;
reinstallservice)	Do_Re_InstallService
					;;
*)					echo "Usage: install|uninstall|optimizeparameters|reinstallservice"
					exit 2
					;;
esac
exit 0
