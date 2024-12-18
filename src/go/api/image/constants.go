package image

const POSTBUILD_VWIFI_PACKAGES = `
apt update
apt install -y build-essential git hostapd iw libnl-3-dev libnl-genl-3-dev wpasupplicant
git clone https://github.com/Raizo62/vwifi.git -b v6.3 /root/vwifi
cd /root/vwifi
make gitversion
make update
make
make tools
make install
rm -rf /root/vwifi

cat > /etc/systemd/system/vwifi-client.service <<EOF
[Unit]
Description=vwifi-client
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=2
ExecStart=/usr/local/bin/vwifi-client

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vwifi-hostapd@.service <<EOF
[Unit]
Description=hostapd service for vwifi (%I)
After=network.target
BindsTo=sys-subsystem-net-devices-%i.device

[Service]
Type=forking
PIDFile=/run/hostapd.%i.pid
Restart=on-failure
RestartSec=2
EnvironmentFile=-/etc/default/hostapd
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.%i.pid $DAEMON_OPTS /etc/hostapd/%i.conf

[Install]
WantedBy=multi-user.target sys-subsystem-net-devices-%i.device
EOF

cat > /etc/systemd/system/vwifi-wpa_supplicant@.service <<EOF
[Unit]
Description=wpa_supplicant service for vwifi (%I)
Requires=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device
Before=network.target
Wants=network.target

# NetworkManager users will probably want the dbus version instead.

[Service]
Type=simple
ExecStart=/usr/sbin/wpa_supplicant -c /etc/wpa_supplicant/wpa_supplicant-%i.conf -i %i

[Install]
WantedBy=multi-user.target
EOF
`

const POSTBUILD_APT_CLEANUP = `
apt clean || apt-get clean || echo "unable to clean apt cache"
`

const POSTBUILD_NO_ROOT_PASSWD = `
sed -i 's/nullok_secure/nullok/' /etc/pam.d/common-auth
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
passwd -d root
`

const POSTBUILD_PHENIX_HOSTNAME = `
echo "phenix" > /etc/hostname
sed -i 's/127.0.1.1 .*/127.0.1.1 phenix/' /etc/hosts
cat > /etc/motd <<EOF

██████╗ ██╗  ██╗███████╗███╗  ██╗██╗██╗  ██╗
██╔══██╗██║  ██║██╔════╝████╗ ██║██║╚██╗██╔╝
██████╔╝███████║█████╗  ██╔██╗██║██║ ╚███╔╝
██╔═══╝ ██╔══██║██╔══╝  ██║╚████║██║ ██╔██╗
██║     ██║  ██║███████╗██║ ╚███║██║██╔╝╚██╗
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚══╝╚═╝╚═╝  ╚═╝

EOF
echo "\nBuilt with phenix image on $(date)\n\n" >> /etc/motd
`

const POSTBUILD_PHENIX_BASE = `
cat > /etc/systemd/system/miniccc.service <<EOF
[Unit]
Description=miniccc
[Service]
ExecStart=/opt/minimega/bin/miniccc -v=false -serial /dev/virtio-ports/cc -logfile /var/log/miniccc.log
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/phenix.service <<EOF
[Unit]
Description=phenix startup service
After=network.target systemd-hostnamed.service
[Service]
Environment=LD_LIBRARY_PATH=/usr/local/lib
ExecStart=/usr/local/bin/phenix-start.sh
RemainAfterExit=true
StandardOutput=journal
Type=oneshot
[Install]
WantedBy=multi-user.target
EOF
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -s /etc/systemd/system/miniccc.service /etc/systemd/system/multi-user.target.wants/miniccc.service
ln -s /etc/systemd/system/phenix.service /etc/systemd/system/multi-user.target.wants/phenix.service
mkdir -p /usr/local/bin
cat > /usr/local/bin/phenix-start.sh <<EOF
#!/bin/bash
for file in /etc/phenix/startup/*; do
	echo \$file
	bash \$file
done
EOF
chmod +x /usr/local/bin/phenix-start.sh
mkdir -p /etc/phenix/startup
`

const POSTBUILD_GUI = `
update-alternatives --set x-terminal-emulator /usr/bin/xfce4-terminal.wrapper
echo "#!/bin/bash\nstartx" > /root/.profile
`

const POSTBUILD_PROTONUKE = `
cat > /etc/systemd/system/protonuke.service <<EOF
[Unit]
Description=protonuke
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=/etc/default/protonuke
ExecStart=/opt/minimega/bin/protonuke \$PROTONUKE_ARGS
[Install]
WantedBy=multi-user.target
EOF
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -s /etc/systemd/system/protonuke.service /etc/systemd/system/multi-user.target.wants/protonuke.service
`

const POSTBUILD_ENABLE_DHCP = `
echo "#!/bin/bash\ndhclient" > /etc/init.d/dhcp.sh
chmod +x /etc/init.d/dhcp.sh
update-rc.d dhcp.sh defaults 100
`

var PACKAGES_DEFAULT = []string{
	"initramfs-tools",
	"net-tools",
	"isc-dhcp-client",
	"openssh-server",
	"init",
	"iputils-ping",
	"vim",
	"less",
	"netbase",
	"curl",
	"ifupdown",
	"dbus",
}

var PACKAGES_KALI = []string{
	"linux-image-amd64",
	"linux-headers-amd64",
	"default-jre",
	"kali-linux-core",
	"kali-tools-top10",
	"python3-cffi-backend",
}

var PACKAGES_UBUNTU = []string{
	"linux-image-generic",
	"linux-headers-generic",
}

var PACKAGES_MINGUI = []string{
	"xorg",
	"xinit",
	"dbus-x11",
	"xserver-xorg",
	"xserver-xorg-input-all",
	"xserver-xorg-video-qxl",
	"xserver-xorg-video-vesa",
	"xfce4",
	"xfce4-terminal",
}

var PACKAGES_MINGUI_KALI = []string{
	"xorg",
	"xfce4-terminal",
	"kali-desktop-xfce",
}

var PACKAGES_COMPONENTS = []string{
	"main",
	"restricted",
	"universe",
	"multiverse",
}

var PACKAGES_COMPONENTS_KALI = []string{
	"main",
	"contrib",
	"non-free",
}
