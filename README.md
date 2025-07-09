# Alien4you
Pentesting framework, 135 Modules



requirements:

system: Kali Linux.

Wireless Adapter in Monitor Mode
Must support packet injection and monitor mode.
Use commands like airmon-ng start wlan0 to enable monitor mode.
Verify with iwconfig or iw dev.

Kernel modules:
nl80211 wireless driver support.

System Permissions:
Run as root or with sudo for raw socket and interface control.




sudo pip3 install requests python-nmap dnspython geoip2 scapy beautifulsoup4 git-dumper

sudo apt update && sudo apt install -y aircrack-ng airbase-ng aireplay-ng airodump-ng antiword btmon curl delv dnsmasq gatttool git hashcat hcitool hcxdumptool hostapd iw iwconfig iwlist nmcli openssl php python3 reaver searchsploit socat sqlite3 sudo tcpdump traceroute wash whois pdfinfo dnsutils libssl-dev libnl-dev build-essential pkg-config

sudo systemctl start bluetooth
sudo systemctl enable bluetooth

sudo airmon-ng check kill
sudo airmon-ng start wlan0

Ensure Kernel supports injection:
sudo modprobe -r <driver>
sudo modprobe <driver> # e.g. iwlwifi, ath9k, etc.

Check interfaces:
iwconfig

Bluetooth Interface Up:
sudo hciconfig hci0 up


# hostapd-wpe installation
git clone https://github.com/OpenSecurityResearch/hostapd-wpe.git
wget http://hostap.epitest.fi/releases/hostapd-2.6.tar.gz
tar -zxf hostapd-2.6.tar.gz
cd hostapd-2.6
patch -p1 < ../hostapd-wpe/hostapd-wpe.patch
cd hostapd
make
sudo cp hostapd-wpe /usr/local/bin/
cd ../..
cd hostapd-wpe/certs
./bootstrap
# Run hostapd-wpe from anywhere:
# sudo hostapd-wpe hostapd-wpe.conf

# hcxdumptool installation
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool
make -j $(nproc)
sudo make install PREFIX=/usr/local

