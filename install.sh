#!/usr/bin/env bash

set -eu

sourceDir=$(dirname $0)
repoVer=feature/debian10
sourceVer=$(basename $repoVer)
sourceTar=https://github.com/axelrtgs/debian-router/tarball/${repoVer}

error_exit() {
  printf "\nFATAL ERROR: $1\n"
  printf "installer exiting!\nYour system is likely in a broken state.\nPlease report this issue.\n"
  exit 1
}

export DEBIAN_FRONTEND="noninteractive"

dirList=" \
	/opt/router/files \
	/opt/router/install \
	/home/router/action \
	/home/router/config \
"

echo
echo "##########################################################"
echo "Checking permissions"
echo "##########################################################"
echo

echo -n "Verifying user ... "
if [ ${USER} != 'root' ]; then
	error_exit "Not running as root, exiting."
else
	echo "ok"
fi

echo
echo "##########################################################"
echo "Disabling SSH password authentication"
echo "##########################################################"
echo

while true; do
  read -p "Disable SSH password authentication (y/n)? " yn
  case $yn in
    [Yy]* )
      echo

      if grep -qE '^PasswordAuthentication no$' /etc/ssh/sshd_config; then
        echo "PasswordAuthentication already disabled ... skipping"
      else
        echo -n "checking if key present in authorized_keys file ... "
        grep -qE '^ssh-rsa' /home/router/.ssh/authorized_keys && echo ok || error_exit "Please copy ssh key using 'ssh-copy-id -i ~/.ssh/id_rsa.pub router@<ROUTER IP>'"

        echo -n "Disabling PasswordAuthentication ... "

        sed -i -E 's/^#?PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config

        grep -qE '^PasswordAuthentication no$' /etc/ssh/sshd_config && echo "ok" || error_exit "FAILED"

        systemctl restart sshd
      fi
      break;;
    [Nn]* )
      echo Skipping ...
      break;;
  esac
done

echo
echo "##########################################################"
echo "Creating directories"
echo "##########################################################"
echo

for listItem in $dirList; do
	echo -n "creating directory ${listItem} ... "
	[ ! -d "${listItem}" ] && mkdir -p ${listItem}
	[ -d "${listItem}" ] && echo "ok" || error_exit "FAILED"
done

echo
echo "##########################################################"
echo "Eanbling extra repos and updating"
echo "##########################################################"
echo

# remove cdrom source to only get packages from internet
sed -i '/^deb cdrom/d' /etc/apt/sources.list

echo 'deb http://deb.debian.org/debian buster-backports main contrib non-free' > /etc/apt/sources.list.d/buster-backports.list

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 379CE192D401AB61
echo "deb https://ookla.bintray.com/debian $(lsb_release -sc) main" >  /etc/apt/sources.list.d/speedtest.list

apt update
apt upgrade -y

echo
echo "##########################################################"
echo "Installing base and utility packages"
echo "##########################################################"
echo

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 379CE192D401AB61
echo "deb https://ookla.bintray.com/debian $(lsb_release -sc) main" >  /etc/apt/sources.list.d/speedtest.list

apt install -y vlan bridge-utils net-tools ppp ipset traceroute nmap conntrack git \
	ndisc6 whois dnsutils mtr iperf3 curl resolvconf sudo apt-transport-https \
	tcpdump ethtool irqbalance lshw vim firmware-bnx2x speedtest tuned unzip

# Detect hypervisor
if grep -q hypervisor /proc/cpuinfo; then

	echo
	echo "##########################################################"
	echo "Hypervisor detected"
	echo "##########################################################"
	echo

	while true; do
		read -p "Install open-vm-tools (y/n)? " yn
		case $yn in
			[Yy]* )
				echo
				apt install -y open-vm-tools
				break;;
			[Nn]* )
				echo Skipping ...
				break;;
		esac
	done
fi

echo
echo "##########################################################"
echo "Installing cockpit"
echo "##########################################################"
echo

cockpitInstalled=no

while true; do
  read -p "Install cockpit (y/n)? " yn
  case $yn in
    [Yy]* )
      echo
      apt install -y cockpit

      cockpitInstalled=yes
      echo -n "Generating macOS Catalina compatible certificate"
      hostname="router.internal.axelrtgs.com"
      subject="/C=US/ST=State/L=City/O=Organization/CN=${hostname}"
      filename=/etc/cockpit/ws-certs.d/0-self-signed
      openssl req \
          -newkey rsa:2048  -nodes  -keyout ${filename}.key \
          -new -x509 -sha256 -days 365 -out ${filename}.cert \
          -subj "${subject}" \
          -addext "subjectAltName = DNS:${hostname}" \
          -addext "extendedKeyUsage = serverAuth" > /dev/null
      cat /etc/cockpit/ws-certs.d/0-self-signed.key >> /etc/cockpit/ws-certs.d/0-self-signed.cert
      rm /etc/cockpit/ws-certs.d/0-self-signed.key
      systemctl restart cockpit
      break;;
    [Nn]* )
      echo Skipping ...
      break;;
  esac
done

echo
echo "##########################################################"
echo "Enabling 2FA"
echo "##########################################################"
echo

while true; do
  read -p "Enable 2FA (y/n)? " yn
  case $yn in
    [Yy]* )
      echo
      apt install -y libpam-google-authenticator

      echo "Generating 2FA for router user"
      if [ -f /home/router/.google_authenticator ]; then
        echo "2FA already configured ... skipping"
      else
        sudo -u router google-authenticator
      fi

      echo "Configuring sudo for 2FA"
      if grep -qE '^auth required pam_google_authenticator.so$' /etc/pam.d/sudo; then
        echo "Sudo 2FA already enabled ... skipping"
      else
        echo "
# google authenticator for two-factor
auth required pam_google_authenticator.so" >> /etc/pam.d/sudo
      fi

      echo "Configuring SSH for 2FA"
      if grep -qE '^ChallengeResponseAuthentication yes$' /etc/ssh/sshd_config; then
        echo "ChallengeResponseAuthentication already enabled ... skipping"
      else
        echo -n "Enabling ChallengeResponseAuthentication ... "

        sed -i 's/^ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config

        grep -qE '^ChallengeResponseAuthentication yes$' /etc/ssh/sshd_config && echo "ok" || error_exit "FAILED"

        systemctl restart sshd
      fi

      if grep -qE '^auth required pam_google_authenticator.so$' /etc/pam.d/sshd; then
        echo "SSH 2FA already enabled ... skipping"
      else
        echo "
# google authenticator for two-factor
auth required pam_google_authenticator.so" >> /etc/pam.d/sshd

        systemctl restart sshd
      fi

      if [ $cockpitInstalled = 'yes' ]; then
        echo "Configuring Cockpit for 2FA"

        if grep -qE '^auth required pam_google_authenticator.so$' /etc/pam.d/cockpit; then
          echo "Cockpit 2FA already enabled ... skipping"
        else
          echo "
# google authenticator for two-factor
auth required pam_google_authenticator.so" >> /etc/pam.d/cockpit

        systemctl restart cockpit
        fi
      fi
      break;;
    [Nn]* )
      echo Skipping ...
      break;;
  esac
done

echo
echo "##########################################################"
echo "Installing services"
echo "##########################################################"
echo

apt install -y unbound dnsmasq inadyn wide-dhcpv6-client igmpproxy wireguard

systemctl stop dnsmasq
systemctl stop  unbound

# TODO: wireguard configs -> https://www.cyberciti.biz/faq/debian-10-set-up-wireguard-vpn-server/

echo
echo "##########################################################"
echo "Installing mdns-repeater"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/mdns-repeater-1.9.zip" ] && useLocalPath="/opt/router/install/mdns-repeater-1.9.zip"
[ -f "${sourceDir}/mdns-repeater-1.9.zip" ] && useLocalPath="${sourceDir}/mdns-repeater-1.9.zip"

# Detect if local version exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Local copy of found, use local copy (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
					cp $useLocalPath /opt/router/install
				fi
				break;;
			[Nn]* )
				useLocalCopy=no
				break;;
		esac
	done
	echo
fi

[ "$useLocalCopy"  = 'no' ] && wget -q -O /opt/router/install/mdns-repeater.tar.gz https://github.com/kennylevinsen/mdns-repeater/archive/1.11.tar.gz
rm -rf /opt/router/install/mdns-repeater/
mkdir -p /opt/router/install/mdns-repeater/
tar -xzvf /opt/router/install/mdns-repeater.tar.gz -C /opt/router/install/mdns-repeater --strip-components=1
pushd /opt/router/install/mdns-repeater > /dev/null
echo -n "Building mdns-repeater ... "
make &> /dev/null && echo "ok" || error_exit "FAILED"
popd > /dev/null

echo -n "Copying mdns-repeater ... "
cp /opt/router/install/mdns-repeater/mdns-repeater /usr/bin/ && echo "ok" || error_exit "FAILED"

echo -n "Setting permissions mdns-repeater ... "
chmod +x /usr/bin/mdns-repeater && echo "ok" || error_exit "FAILED"

echo
echo "##########################################################"
echo "Fetching install files"
echo "##########################################################"
echo

# Copy install to /opt/router/install/
if [ $sourceDir != "/opt/router/install" ]; then
	echo -n "copying $0 /opt/router/install/ ... "
	cp $0 /opt/router/install/ && echo "ok" || error_exit "FAILED"
fi

useLocalSource=no

# Detect if local archive exists
if [ -f "${sourceDir}/${sourceVer}.tar.gz" ]; then
	while true; do
		read -p "Local archive detected, use local archive (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalSource=yes
				break;;
			[Nn]* )
				useLocalSource=no
				break;;
		esac
	done
	echo
fi

# Download or use local copy of archive
if [ $useLocalSource = 'yes' ]; then
		echo -n "copying ${sourceDir}/${sourceVer}.tar.gz -> /opt/router/install/${sourceVer}.tar.gz ... "
		cp ${sourceDir}/${sourceVer}.tar.gz /opt/router/install/
		[ -f "/opt/router/install/${sourceVer}.tar.gz" ] && echo "ok" || error_exit "FAILED"
else
		echo -n "fetching /opt/router/install/${sourceVer}.tar.gz ... "
		wget -q ${sourceTar} -O /opt/router/install/${sourceVer}.tar.gz
		[ -f "/opt/router/install/${sourceVer}.tar.gz" ] && echo "ok" || error_exit "FAILED"
fi

echo
echo "##########################################################"
echo "Extracting archive to /opt/router"
echo "##########################################################"
echo

# Get file list from archive
fileList=$(tar -tvf /opt/router/install/${sourceVer}.tar.gz | awk '{print $6}' | grep -oE '^.*/files/.*' | sed "s/^.*\/files\///g" | grep -vE '/$')

# Extract archive
rm -rf /opt/router/files/*
tar -C /opt/router/files/ -xvf /opt/router/install/${sourceVer}.tar.gz --strip-components=2 | sed -E "s/^[^\/]*\///g" | sed "s/^files\///g" | grep -vE '/$'

echo
echo "##########################################################"
echo "backup of original files that will be overwritten"
echo "##########################################################"
echo

if [ ! -d "/opt/router/files.bak/" ]; then
	for listItem in $fileList; do
		if [ -f "/${listItem}" ]; then
			echo -n "backing up /${listItem} ... "
			[ ! -d "/opt/router/files.bak/$(dirname $listItem)" ] && mkdir -p "/opt/router/files.bak/$(dirname $listItem)"
			cp /${listItem} /opt/router/files.bak/$(dirname $listItem)
			[ -f "/opt/router/files.bak/${listItem}" ] && echo "ok" || error_exit "FAILED"
		fi
	done
else
	echo Backup of original files exists ... skipping
fi

echo
echo "##########################################################"
echo "copying files"
echo "##########################################################"
echo

for listItem in $fileList; do
	echo -n "copying /opt/router/files/${listItem} -> /${listItem} ... "
	[ ! -d "/$(dirname $listItem)" ] && mkdir -p /$(dirname $listItem)
	cp /opt/router/files/${listItem} /${listItem}
	[ -f "/${listItem}" ] && echo "ok" || error_exit "FAILED"
done

echo
echo "######################################"
echo "creating symlinks"
echo "######################################"
echo

# config cron symlinks
echo -n "creating /home/router/config/cron_jobs ... "
ln -sf /etc/cron.d/cronjobs /home/router/config/cron_jobs && echo "ok" || error_exit "FAILED"

# config dhcp symlinks
echo -n "creating /home/router/config/dhcp_base ... "
ln -sf /opt/router/dnsmasq/dnsmasq.conf.router /home/router/config/dhcp_base && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/dhcp_hosts ... "
ln -sf /opt/router/dnsmasq/dnsmasq.hosts /home/router/config/dhcp_hosts && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/dhcp_v6-pd_config ... "
ln -sf /etc/wide-dhcpv6/dhcp6c.conf /home/router/config/dhcp_v6-pd_config && echo "ok" || error_exit "FAILED"

# config dns symlinks
echo -n "creating /home/router/config/unbound ... "
ln -sf /etc/unbound/unbound.conf.d /home/router/config/unbound && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/adblock ... "
ln -sf /opt/router/adblock /home/router/config/adblock && echo "ok" || error_exit "FAILED"

# config ddns symlinks
echo -n "creating /home/router/config/ddns_he_tunnel ... "
ln -sf /opt/router/scripts/ddns/ddns-ipv4-he-tunnel /home/router/config/ddns_he_tunnel && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/ddns_inadyn ... "
ln -sf /etc/inadyn.conf /home/router/config/ddns_inadyn && echo "ok" || error_exit "FAILED"

# config firewall symlinks
echo -n "creating /home/router/config/firewall_dns_redirect_v4.set ... "
ln -sf /opt/router/nftables/dns_redirect_v4.set /home/router/config/firewall_dns_redirect_v4.set && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/firewall_dns_redirect_v6.set ... "
ln -sf /opt/router/nftables/dns_redirect_v6.set /home/router/config/firewall_dns_redirect_v6.set && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/firewall_forwarding_v4.set ... "
ln -sf /opt/router/nftables/port_forwarding_v4.set /home/router/config/firewall_forwarding_v4.set && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/firewall_forwarding_v6.set ... "
ln -sf /opt/router/nftables/port_forwarding_v6.set /home/router/config/firewall_forwarding_v6.set && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/firewall_rules_v4 ... "
ln -sf /opt/router/nftables/iptables.rules /home/router/config/firewall_rules_v4 && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/firewall_rules_v6 ... "
ln -sf /opt/router/nftables/ip6tables.rules /home/router/config/firewall_rules_v6 && echo "ok" || error_exit "FAILED"

# config igmpproxy symlinks
echo -n "creating /home/router/config/igmpproxy_config ... "
ln -sf /etc/igmpproxy.conf /home/router/config/igmpproxy_config && echo "ok" || error_exit "FAILED"

# config network symlinks
echo -n "creating /home/router/config/network_interfaces ... "
ln -sf /etc/network/interfaces.router /home/router/config/network_interfaces && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/network_persistent_rules ... "
ln -sf /etc/udev/rules.d/70-persistent-net.rules /home/router/config/network_persistent_rules && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/network_pppoe ... "
ln -sf /etc/ppp/peers/pppoe.conf /home/router/config/network_pppoe && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/config/network_wan_up ... "
ln -sf /opt/router/scripts/system/wan-up /home/router/config/network_wan_up && echo "ok" || error_exit "FAILED"

# actions symlinks
echo -n "creating /home/router/action/activate.sh ... "
ln -sf /opt/router/scripts/system/activate /home/router/action/activate.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/adblock.sh ... "
ln -sf /opt/router/scripts/services/adblock /home/router/action/adblock.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/backup.sh ... "
ln -sf /opt/router/scripts/system/backup /home/router/action/backup.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/filelist.sh ... "
ln -sf /opt/router/scripts/system/filelist /home/router/action/filelist.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/forwarding-rules.sh ... "
ln -sf /opt/router/scripts/system/forwarding-rules /home/router/action/forwarding-rules.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/restore.sh ... "
ln -sf /opt/router/scripts/system/restore /home/router/action/restore.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/ssh-lock.sh ... "
ln -sf /opt/router/scripts/system/ssh-lock /home/router/action/ssh-lock.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/ssh-reset.sh ... "
ln -sf /opt/router/scripts/system/ssh-reset /home/router/action/ssh-reset.sh && echo "ok" || error_exit "FAILED"
echo -n "creating /home/router/action/ssh-unlock.sh ... "
ln -sf /opt/router/scripts/system/ssh-unlock /home/router/action/ssh-unlock.sh && echo "ok" || error_exit "FAILED"

echo
echo "##########################################################"
echo "Restore backup of locally modified files"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/${sourceVer}-local.tar.gz" ] && useLocalPath="/opt/router/install/${sourceVer}-local.tar.gz"
[ -f "${sourceDir}/${sourceVer}-local.tar.gz" ] && useLocalPath="${sourceDir}/${sourceVer}-local.tar.gz"

# Detect if archive.local exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Backup of locally modified files detected, use backup (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				break;;
			[Nn]* )
				useLocalCopy=no
				echo
				echo skipping ...
				break;;
		esac
	done
else
	echo "${sourceVer}-local.tar.gz not found ... skipping restore"
fi

# Extract local backup
if [ $useLocalCopy = 'yes' ]; then
	if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
		echo
		echo -n "copying $useLocalPath -> /opt/router/install/${sourceVer}-local.tar.gz ... "
		cp $useLocalPath /opt/router/install && echo "ok" || error_exit "FAILED"
	fi

	echo "Extracting files ..."
	echo
	tar -C / -xvf /opt/router/install/${sourceVer}-local.tar.gz
fi

echo
echo "##########################################################"
echo "Restore backup of extra files"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/${sourceVer}-extras.tar.gz" ] && useLocalPath="/opt/router/install/${sourceVer}-extras.tar.gz"
[ -f "${sourceDir}/${sourceVer}-extras.tar.gz" ] && useLocalPath="${sourceDir}/${sourceVer}-extras.tar.gz"

# Detect if archive.extras exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Backup of extra files detected, use backup (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				break;;
			[Nn]* )
				useLocalCopy=no
				echo
				echo skipping ...
				break;;
		esac
	done
else
	echo "${sourceVer}-extras.tar.gz not found ... skipping restore"
fi

# Extract extra files backup
if [ $useLocalCopy = 'yes' ]; then
	if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
		echo
		echo -n "copying $useLocalPath -> /opt/router/install/${sourceVer}-extras.tar.gz ... "
		cp $useLocalPath /opt/router/install && echo "ok" || error_exit "FAILED"
	fi

	echo "Extracting files ..."
	echo
	tar -C / -xvf /opt/router/install/${sourceVer}-extras.tar.gz
fi

echo
echo "######################################"
echo "Reloading daemon configs"
echo "######################################"
echo

echo -n "disabling autostart of wide-dhcpv6-client ... "
update-rc.d wide-dhcpv6-client disable && echo "ok" || error_exit "FAILED"
echo -n "reloading daemon configs ... "
systemctl daemon-reload && echo "ok" || error_exit "FAILED"

echo
echo "######################################"
echo "Enabling systemd services"
echo "######################################"
echo

echo -n "mdns-repeater ... "
systemctl enable mdns-repeater && echo "ok" || error_exit "FAILED"

echo
echo "##########################################################"
echo "setting permissions"
echo "##########################################################"
echo

echo -n "chmod 755 /etc/ppp/ip-down.local ... "
chmod 755 /etc/ppp/ip-down.local && echo "ok" || error_exit "FAILED"
echo -n "chmod 755 /etc/ppp/ip-up.local ... "
chmod 755 /etc/ppp/ip-up.local && echo "ok" || error_exit "FAILED"
echo -n "chmod 755 -R /opt/router/install/*.sh ... "
chmod 755 -R /opt/router/install/*.sh && echo "ok" || error_exit "FAILED"
echo -n "chmod 755 -R /opt/router/scripts ... "
chmod 755 -R /opt/router/scripts && echo "ok" || error_exit "FAILED"

# Test if is activated following restore
if [ -s /opt/router/install/.activated ]; then
	echo
	echo "######################################"
	echo "Router activated following restore"
	echo "######################################"
	echo

	echo "remapping ~/router/config/network_interfaces -> /etc/network/interfaces"
	ln -sf /etc/network/interfaces ~/router/config/network_interfaces

	echo "remapping ~/router/config/dhcp_base -> /opt/router/dnsmasq/dnsmasq.conf"
	ln -sf /opt/router/dnsmasq/dnsmasq.conf ~/router/config/dhcp_base

	echo
	echo "The router will be fully active the next time you boot."
	echo "Make sure the original router is shutdown before booting."
	echo
else
	echo
	echo "######################################"
	echo "Finished base install"
	echo "######################################"
	echo
	echo "Please edit the files linked in the ~/router/config directory then run the"
	echo "activate script."
	echo
	echo "~/router/action/activate.sh"
	echo
	echo "The activate script will replace the temporary network and dhcp settings with"
	echo "your configured settings"
	echo
	echo "After running the activate script, the router WILL SHUT DOWN"
	echo
	echo "The router will be fully active the next time you boot."
	echo "Make sure the original router is shutdown before booting."
	echo
fi
