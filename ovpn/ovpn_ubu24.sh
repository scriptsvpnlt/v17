#!/bin/bash

clear
echo -e "\e[32m Install OpenVpn \e[0m"
apt update
apt install openvpn -y

export DEBIAN_FRONTEND=noninteractive
# Deteksi Versi OS
os_id=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep -w VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')

MYIP=$(wget -qO- ipinfo.io/ip)
domain=$(cat /root/domain)
MYIP2="s/xxxxxxxxx/$domain/g"

function ovpn_install() {
    echo "Menghapus direktori lama dan membuat ulang direktori OpenVPN..."
    rm -rf /etc/openvpn
    mkdir -p /etc/openvpn

    # Unduh file konfigurasi
    wget -O /etc/openvpn/vpn.zip "https://raw.githubusercontent.com/scriptsvpnlt/v17/main/ovpn/vpn.zip" >/dev/null 2>&1
    unzip -d /etc/openvpn/ /etc/openvpn/vpn.zip
    rm -f /etc/openvpn/vpn.zip
    chown -R root:root /etc/openvpn/server/easy-rsa/
}

function config_easy() {
    echo "Mengkonfigurasi layanan OpenVPN..."
    mkdir -p /usr/lib/openvpn/
    if [[ -f /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so ]]; then
        cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
    fi

    # Aktifkan layanan OpenVPN
    systemctl enable --now openvpn-server@server-tcp
    systemctl enable --now openvpn-server@server-udp
}

function enable_ip_forwarding() {
    echo "Mengaktifkan IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
    sysctl -p
}

function generate_client_configs() {
    echo "Membuat file konfigurasi client..."
    for proto in tcp udp ws-ssl ssl; do
        cat > /etc/openvpn/${proto}.ovpn <<-END
client
dev tun
proto ${proto}
remote xxxxxxxxx 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
        sed -i $MYIP2 /etc/openvpn/${proto}.ovpn
        echo '<ca>' >> /etc/openvpn/${proto}.ovpn
        cat /etc/openvpn/server/ca.crt >> /etc/openvpn/${proto}.ovpn
        echo '</ca>' >> /etc/openvpn/${proto}.ovpn
        cp /etc/openvpn/${proto}.ovpn /var/www/html/${proto}.ovpn
    done
}

function finalize_setup() {
    echo "Menyelesaikan konfigurasi OpenVPN..."
    cd /var/www/html/
    zip Kyt-Project.zip tcp.ovpn udp.ovpn ssl.ovpn ws-ssl.ovpn >/dev/null 2>&1
    sed -i "s|IP-ADDRESSS|$(curl -sS ifconfig.me)|g" /var/www/html/index.html

    systemctl restart openvpn-server@server-tcp
    systemctl restart openvpn-server@server-udp
    systemctl enable openvpn
}

function install_openvpn() {
    echo "Memulai instalasi OpenVPN..."
    ovpn_install
    config_easy
    enable_ip_forwarding
    generate_client_configs
    finalize_setup
}

install_openvpn
