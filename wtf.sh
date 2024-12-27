#!/bin/bash

clear

# ==========================================
# Variabel Global
# ==========================================
GRN="\e[92;1m"
RED="\033[1;31m"
CY="\033[36;1m"
BLUE="\033[36m"
Softex="\033[0m"
OK="${GRN}[NICE]${Softex}"
ERROR="${RED}[EROR]${Softex}"
MyIP_Vps=$(curl -sS ipv4.icanhazip.com)
DATE=$(date +'%Y-%m-%d')

# github Repository
GIT_USER="scriptsvpnlt"
GIT_REPO="v17"
GIT_BRANCH="main"
REPO="https://raw.githubusercontent.com/${GIT_USER}/${GIT_REPO}/${GIT_BRANCH}/"

# ==========================================
# Fungsi Utama
# ==========================================
PRINT_DONE() {
    echo -e "${OK} ${BLUE}$1${Softex}"
}

PRINT_FAILURE() {
    echo -e "${ERROR} ${RED}$1${Softex}"
}

PRINTF_INSTALL() {
    echo -e "${GRN}===========================================${Softex}"
    echo -e "${CY}# $1 ${Softex}"
    echo -e "${GRN}===========================================${Softex}"
    sleep 1
}

CHECKING_ROOT_USER() {
    if [[ $EUID -ne 0 ]]; then
        PRINT_FAILURE "Script must be run as root. Exiting..."
        exit 1
    fi
}

VALIDITY_IPVPS() {
    if [[ -z "$MyIP_Vps" ]]; then
        PRINT_FAILURE "Unable to detect your IP address. Exiting..."
        exit 1
    fi
    PRINT_DONE "IP Detected: $MyIP_Vps"
}

# setup directories
SETUP_DIRECTORIES() {
    mkdir -p /etc/xray /var/log/xray /var/lib/LT
    curl -s ifconfig.me > /etc/xray/ipvps
    chown www-data:www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
}

ADDED_DOMAINS() {
clear
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[1;32m    Please Select a Domain bellow type.     \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[1;32m  1). \e[97;1m Domain Pribadi \e[0m"
echo -e "   \e[1;32m  2). \e[97;1m Domain Random  \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e ""
read -p "   Just Input a number [1-2]:   " host
echo ""
if [[ $host == "1" ]]; then
clear
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e "   \e[97;1m             INPUT YOUR DOMAIN              \e[0m"
echo -e "   \e[97;1m ===========================================\e[0m"
echo -e ""
read -p "   input your domain :   " host1
echo "IP=" >> /var/lib/LT/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
fi
}

FETCH_USER_INFO() {
    PRINTF_INSTALL "Fetching user information"
    username=$(curl -s https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep $MyIP_Vps | awk '{print $2}')
    expx=$(curl -s https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep $MyIP_Vps | awk '{print $3}')
    if [[ -z "$username" || -z "$expx" ]]; then
        PRINT_FAILURE "User information not found for IP: $MyIP_Vps"
        exit 1
    fi
    echo "$username" > /usr/bin/user
    echo "$expx" > /usr/bin/e
    PRINT_DONE "User: $username, Expiry: $expx"
}

CALCULATE_RAM_USAGE() {
    PRINTF_INSTALL "Calculating RAM usage"
    local mem_used=0 mem_total=0
    while IFS=":" read -r key value; do
        case $key in
            "MemTotal") mem_total="${value/kB}"; mem_used="${value/kB}" ;;
            "MemFree" | "Buffers" | "Cached" | "SReclaimable")
                mem_used=$((mem_used - ${value/kB}))
                ;;
        esac
    done < /proc/meminfo
    Ram_Usage=$((mem_used / 1024))
    Ram_Total=$((mem_total / 1024))
    PRINT_DONE "RAM Usage: ${Ram_Usage}MB/${Ram_Total}MB"
}

# ==========================================
# Main Script
# ==========================================
main() {
    clear
    echo -e "${CY}=========================================${Softex}"
    echo -e "\033[41;97;1m          LUNATIC TUNNELING SETUP         \033[0m"
    echo -e "${CY}=========================================${Softex}"
    echo ""

    CHECKING_ROOT_USER
    VALIDITY_IPVPS
    SETUP_DIRECTORIES
    ADDED_DOMAINS
    FETCH_USER_INFO
    CALCULATE_RAM_USAGE

    PRINT_DONE "Setup completed successfully"
}

main "$@"

function INSTALL_HAPROXY() {
    # Mengatur timezone
    PRINTF_INSTALL "Mengatur Timezone"
    timedatectl set-timezone Asia/Jakarta
    PRINT_DONE "Timezone diatur ke Asia/Jakarta"

    # Mengatur auto-save iptables
    PRINTF_INSTALL "Mengatur iptables-persistent"
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Mengecek dan mengatur dependensi berdasarkan OS
    OS=$(grep -w ID /etc/os-release | head -n1 | awk -F= '{print $2}' | sed 's/"//g')
    PRETTY_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | awk -F= '{print $2}' | sed 's/"//g')
    
    if [[ $OS == "ubuntu" ]]; then
        PRINTF_INSTALL "Meng install haproxy untuk OS (${PRETTY_NAME})"
        apt update -y
        apt-get install --no-install-recommends -y software-properties-common
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get install -y haproxy=2.0.\*
        PRINT_DONE "Haproxy berhasil di Install di ubuntu"

    elif [[ $OS == "debian" ]]; then
        PRINTF_INSTALL "Mengatur dependensi untuk Debian (${PRETTY_NAME})"
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net $(lsb_release -cs)-backports-1.8 main" > /etc/apt/sources.list.d/haproxy.list
        apt-get update
        apt-get install -y haproxy=1.8.\*
        PRINT_DONE "Haproxy berhasil di install di debian"
    else
        PRINT_FAILURE "Operating System (${PRETTY_NAME}) not compatible."
        exit 1
    fi
}

function INSTALL_NGINX() {
    # Pendeteksian OS
    OS=$(grep -w ID /etc/os-release | head -n1 | awk -F= '{print $2}' | sed 's/"//g')
    PRETTY_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | awk -F= '{print $2}' | sed 's/"//g')

    PRINTF_INSTALL "Instalasi Nginx untuk ${PRETTY_NAME}"

    # Instalasi berdasarkan OS
    if [[ $OS == "ubuntu" || $OS == "debian" ]]; then
        apt update -y
        apt install -y nginx
        if [[ $? -eq 0 ]]; then
            PRINT_SUCCES "Nginx berhasil diinstal pada ${PRETTY_NAME}"
        else
            PRINT_FAILURE "Gagal menginstal Nginx pada ${PRETTY_NAME}"
            exit 1
        fi
    else
        PRINT_FAILURE "Sistem operasi ${PRETTY_NAME} tidak didukung"
        exit 1
    fi
}

function INSTALL_TOOLS() {
    clear
    PRINTF_INSTALL "Menginstal Paket yang Dibutuhkan"

    # Update dan upgrade sistem
    apt update -y && apt upgrade -y && apt dist-upgrade -y

    # Instal paket dasar
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet sudo ntpdate \
        speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev \
        libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
        libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr \
        libxml-parser-perl build-essential gcc g++ python3-pip htop lsof tar wget curl ruby \
        zip unzip p7zip-full libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables \
        iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg \
        gnupg2 lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https \
        gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa

    # Konfigurasi firewall dan jaringan
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get remove --purge -y exim4 ufw firewalld
    sudo apt-get clean all && sudo apt-get autoremove -y

    # Sinkronisasi waktu
    systemctl enable chrony && systemctl restart chrony
    ntpdate pool.ntp.org

    # Verifikasi konfigurasi waktu
    chronyc sourcestats -v
    chronyc tracking -v

    PRINT_SUCCES "Paket yang Dibutuhkan Telah Berhasil Diinstal"
}

function SEND_NOTIF() {
    # Mendapatkan informasi dari server
    USRSC=$(wget -qO- https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$MyIP_Vps" | awk '{print $2}')
    EXPSC=$(wget -qO- https://raw.githubusercontent.com/scriptsvpnlt/vps_access/main/ip | grep "$MyIP_Vps" | awk '{print $3}')
    TIMEZONE=$(date '+%H:%M:%S')

    # Memastikan variabel domain tidak kosong
    if [[ -z "$domain" ]]; then
        domain="Tidak Diketahui"
    fi

    # Memastikan IP terdeteksi
    if [[ -z "$MyIP_Vps" ]]; then
        MyIP_Vps="Tidak Diketahui"
    fi

    # Membuat pesan notifikasi
    TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>IP VPS : </code><code>$MyIP_Vps</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>"

    # Menambahkan tombol inline
    INLINE_KEYBOARD='{"inline_keyboard":[[{"text":"⭐ᴏʀᴅᴇʀ⭐","url":"https://t.me/sanzVPN"},{"text":"⭐ɪɴꜱᴛᴀʟʟ⭐","url":"https://wa.me/6282240074362"}]]}'

    # Mengirim notifikasi ke Telegram
    curl -s --max-time "$TIMES" \
        -d "chat_id=$CHATID" \
        -d "disable_web_page_preview=1" \
        -d "text=$TEXT" \
        -d "parse_mode=html" \
        -d "reply_markup=$INLINE_KEYBOARD" \
        "$URL" >/dev/null

    # Memastikan curl berhasil
    if [[ $? -eq 0 ]]; then
        echo -e "${GRN}Notifikasi berhasil dikirim.${Softex}"
    else
        echo -e "${RED}Gagal mengirim notifikasi.${Softex}"
    fi
}

function INSTALL_SSLCERT() {
    clear
    PRINTF_INSTALL "Memasang SSL pada Domain"

    # Membersihkan file SSL sebelumnya
    rm -f /etc/xray/xray.key
    rm -f /etc/xray/xray.crt

    # Mendapatkan nama domain
    domain=$(cat /root/domain 2>/dev/null)

    # Validasi domain
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Error: Domain tidak ditemukan. Pastikan Anda sudah mengatur domain sebelumnya.${Softex}"
        exit 1
    fi

    # Menghentikan server yang menggunakan port 80
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    if [[ -n "$STOPWEBSERVER" ]]; then
        systemctl stop "$STOPWEBSERVER"
    fi
    systemctl stop nginx

    # Membersihkan dan menyiapkan direktori untuk ACME
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Mengunduh dan mengatur ACME
    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Memperbarui ACME dan menetapkan server Let's Encrypt
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Menerbitkan sertifikat SSL
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    if [[ $? -ne 0 ]]; then
        echo -e "${RED} Gagal menerbitkan sertifikat SSL.${Softex}"
        exit 1
    fi

    # Memasang sertifikat SSL
    /root/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key \
        --ecc
    if [[ $? -ne 0 ]]; then
        echo -e "${RED} Gagal memasang sertifikat SSL.${Softex}"
        exit 1
    fi

    # Mengatur izin file SSL
    chmod 600 /etc/xray/xray.key
    chmod 644 /etc/xray/xray.crt

    PRINT_SUCCES "Sertifikat SSL berhasil dipasang untuk domain $domain"
}

function INSTALL_FOLDER() {
  # Hapus file database lama jika ada
  rm -rf /etc/lunatic/{vmess/.vmess.db,vless/.vless.db,trojan/.trojan.db,shadowsocks/.shadowsocks.db,ssh/.ssh.db,bot/.bot.db}

  # Buat direktori utama
  mkdir -p /etc/lunatic \
           /etc/limit \
           /usr/bin/xray \
           /var/log/xray \
           /var/www/html \
           /usr/sbin/local \
           /usr/local/sbin

  # Buat direktori khusus layanan
  for service in vmess vless trojan shadowsocks ssh; do
    mkdir -p /etc/lunatic/$service/{ip,detail,usage}
  done

  # Direktori tambahan untuk bot dan fitur lainnya
  mkdir -p /etc/lunatic/bot/{telegram,notif}
  mkdir -p /etc/lunatic/noobzvpns/detail

  # Set izin untuk direktori log
  chmod -R 755 /var/log/xray

  # Buat file penting
  touch /etc/xray/v2ray \
        /var/log/xray/{access.log,error.log} \
        /etc/lunatic/{vmess/.vmess.db,vless/.vless.db,trojan/.trojan.db,ssh/.ssh.db,bot/.bot.db} \
        /etc/lunatic/bot/notif/{key,id}

  # Isi file database dengan template awal
  for db in vmess vless trojan ssh; do
    if [[ ! -f /etc/lunatic/$db/.${db}.db ]]; then
      echo "& plughin Account" > /etc/lunatic/$db/.${db}.db
    fi
  done

    PRINT_SUCCES "Folder dan file Xray berhasil perbarui"
}

function INSTALL_XRAY() {
    clear
    PRINTF_INSTALL "Memasang Xray Core Versi Terbaru"

    # Direktori untuk domain socket
    domainSock_dir="/run/xray"
    if [ ! -d $domainSock_dir ]; then
        mkdir $domainSock_dir
        chown www-data:www-data $domainSock_dir
    fi

    # Mendapatkan versi terbaru Xray dari GitHub
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"

    # Memasang Xray menggunakan skrip resmi
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

    # Mendownload konfigurasi awal
    wget -O /etc/xray/config.json "${REPO}cfg_conf_js/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

    # Membaca domain dan IP VPS
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)

    PRINT_SUCCES "Xray Core Versi $latest_version berhasil dipasang"

    clear

    # Menambahkan informasi lokasi dan ISP ke konfigurasi
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp

    PRINTF_INSTALL "Mengonfigurasi Paket Pendukung"

    # Mendownload file konfigurasi tambahan
    wget -O /etc/haproxy/haproxy.cfg "${REPO}cfg_conf_js/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}cfg_conf_js/xray.conf" >/dev/null 2>&1

    # Mengganti placeholder domain dalam file konfigurasi
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

    # Mengonfigurasi Nginx
    curl ${REPO}cfg_conf_js/nginx.conf > /etc/nginx/nginx.conf

    # Membuat file SSL untuk HAProxy
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1

    # Memberikan izin eksekusi pada service
    chmod +x /etc/systemd/system/runn.service

    # Menghapus konfigurasi lama jika ada
    rm -rf /etc/systemd/system/xray.service.d

    # Membuat konfigurasi service systemd untuk Xray
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # Menampilkan pesan sukses
    PRINT_SUCCES "Konfigurasi Paket dan Service Xray berhasil diterapkan"
}

function INSTALL_PASSWORD() {
    clear
    PRINTF_INSTALL "Memasang dan Mengonfigurasi SSH"

    # Mengunduh file konfigurasi password SSH
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    # Konfigurasi keyboard default
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
ebconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    # Membuat layanan rc-local jika tidak ada
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
END

    # Membuat file rc.local jika tidak ada
    cat > /etc/rc.local <<-END
#!/bin/bash
exit 0
END

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service

    # Menonaktifkan IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # Mengatur zona waktu ke Asia/Jakarta
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Menonaktifkan penerimaan variabel lingkungan di konfigurasi SSH
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

    # Menampilkan pesan sukses
    PRINT_SUCCES "SSH berhasil dikonfigurasi dan siap digunakan"
}

function INSTALL_BADVPN() {
    clear
    PRINTF_INSTALL "Memasang Service Limit Quota"

    # Unduh skrip limit.sh dan jalankan
    wget -q https://raw.githubusercontent.com/LunaticTunnel/ZZxxLTxxZZ/master/files/limit.sh -O limit.sh
    chmod +x limit.sh
    ./limit.sh

    # Unduh dan konfigurasikan skrip limit-ip
    wget -q -O /usr/bin/limit-ip "${REPO}files/limit-ip"
    chmod +x /usr/bin/limit-ip
    sed -i 's/\r//' /usr/bin/limit-ip

    # Konfigurasi layanan VMIP
    cat >/etc/systemd/system/vmip.service <<EOF
[Unit]
Description=Service VMIP
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Aktifkan dan mulai layanan VMIP
    systemctl daemon-reload
    systemctl enable vmip
    systemctl restart vmip

    # Konfigurasi layanan VLIP
    cat >/etc/systemd/system/vlip.service <<EOF
[Unit]
Description=Service VLIP
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Aktifkan dan mulai layanan VLIP
    systemctl daemon-reload
    systemctl enable vlip
    systemctl restart vlip

    # Konfigurasi layanan TRIP
    cat >/etc/systemd/system/trip.service <<EOF
[Unit]
Description=Service TRIP
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Aktifkan dan mulai layanan TRIP
    systemctl daemon-reload
    systemctl enable trip
    systemctl restart trip

    # Unduh binary UDP Mini dan konfigurasinya
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini

    # Konfigurasi layanan UDP Mini 1
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    systemctl disable udp-mini-1
    systemctl stop udp-mini-1
    systemctl enable udp-mini-1
    systemctl start udp-mini-1

    # Konfigurasi layanan UDP Mini 2
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    systemctl disable udp-mini-2
    systemctl stop udp-mini-2
    systemctl enable udp-mini-2
    systemctl start udp-mini-2

    # Konfigurasi layanan UDP Mini 3
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
    systemctl disable udp-mini-3
    systemctl stop udp-mini-3
    systemctl enable udp-mini-3
    systemctl start udp-mini-3

    # Tampilkan pesan sukses
    PRINT_SUCCES "Layanan Quota Service telah berhasil dipasang"
}

function INSTALL_SSHD() {
    clear
    PRINTF_INSTALL "Memasang SSHD"

    # Unduh konfigurasi SSHD dari repository
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1

    # Atur izin file konfigurasi
    chmod 700 /etc/ssh/sshd_config

    # Restart layanan SSHD
    systemctl restart ssh
    systemctl enable ssh

    # Tampilkan status layanan SSHD
    ssh_status=$(systemctl is-active ssh)
    if [[ $ssh_status == "active" ]]; then
        PRINT_SUCCES "SSHD berhasil dipasang dan berjalan"
    else
        PRINT_FAILURE "Gagal memulai SSHD. Periksa konfigurasi."
    fi
}

function INSTALL_DROPBEAR() {
    clear
    PRINTF_INSTALL "Menginstall Dropbear"

    # Install paket Dropbear
    apt-get install dropbear -y > /dev/null 2>&1

    # Unduh file konfigurasi Dropbear
    wget -q -O /etc/default/dropbear "${REPO}cfg_conf_js/dropbear.conf"

    # Atur izin file konfigurasi
    chmod 600 /etc/default/dropbear

    # Restart layanan Dropbear
    systemctl restart dropbear
    systemctl enable dropbear

    # Periksa status layanan Dropbear
    dropbear_status=$(systemctl is-active dropbear)
    if [[ $dropbear_status == "active" ]]; then
        PRINT_SUCCES "Dropbear berhasil dipasang dan berjalan"
    else
        PRINT_FAILURE "Gagal memulai Dropbear. Periksa konfigurasi."
    fi
}

function INSTALL_VNSTAT() {
    clear
    PRINTF_INSTALL "Menginstall Vnstat"

    # Instalasi paket dasar untuk Vnstat
    apt-get update -y > /dev/null 2>&1
    apt-get install -y vnstat libsqlite3-dev wget build-essential > /dev/null 2>&1

    # Restart layanan Vnstat untuk memastikan tersedia
    systemctl restart vnstat || /etc/init.d/vnstat restart
    systemctl enable vnstat || echo "Service vnstat enabled (init.d)"

    # Unduh dan instal Vnstat versi terbaru dari sumber
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc > /dev/null 2>&1
    make > /dev/null 2>&1
    make install > /dev/null 2>&1
    cd

    # Konfigurasi Vnstat
    NET=$(ip route | grep default | awk '{print $5}')
    vnstat -u -i $NET
    sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R

    # Pastikan layanan berjalan
    systemctl restart vnstat || /etc/init.d/vnstat restart
    vnstat_status=$(systemctl is-active vnstat || /etc/init.d/vnstat status)

    # Hapus file instalasi sementara
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6

    # Verifikasi dan tampilkan status
    if [[ $vnstat_status == "active" || $vnstat_status == *"running"* ]]; then
        PRINT_SUCCES "Vnstat berhasil diinstal dan berjalan pada antarmuka $NET"
    else
        PRINT_FAILURE "Gagal memulai layanan Vnstat. Periksa log untuk informasi lebih lanjut."
    fi
}

function INSTALL_OPENVPN() {
    clear
    PRINTF_INSTALL "Menginstall OpenVPN"

    # Deteksi versi OS
    OS=$(lsb_release -si)
    VERSION=$(lsb_release -sr | cut -d. -f1)

    # Perbarui sistem dan instal dependensi dasar
    apt-get update -y > /dev/null 2>&1
    apt-get install -y wget curl apt-transport-https gnupg > /dev/null 2>&1

    # Menambahkan repository OpenVPN sesuai OS dan versi
    if [[ "$OS" == "Ubuntu" && "$VERSION" -ge 22 ]] || [[ "$OS" == "Debian" && "$VERSION" -ge 11 ]]; then
        wget -qO - https://packages.openvpn.net/packages-repo.gpg | gpg --dearmor -o /usr/share/keyrings/openvpn.gpg
        echo "deb [signed-by=/usr/share/keyrings/openvpn.gpg] https://packages.openvpn.net/openvpn3/debian $(lsb_release -cs) main" \
            > /etc/apt/sources.list.d/openvpn3.list
        apt-get update -y > /dev/null 2>&1
        apt-get install -y openvpn3 > /dev/null 2>&1
    else
        apt-get install -y openvpn > /dev/null 2>&1
    fi

    # Konfigurasi OpenVPN
    wget -q -O /etc/openvpn/server.conf "${REPO}files/server.conf"
    mkdir -p /etc/openvpn/easy-rsa
    wget -q -O /etc/openvpn/easy-rsa/easyrsa "${REPO}files/easyrsa"
    chmod +x /etc/openvpn/easy-rsa/easyrsa

    # Memulai layanan OpenVPN
    if [[ "$OS" == "Ubuntu" && "$VERSION" -ge 22 ]] || [[ "$OS" == "Debian" && "$VERSION" -ge 11 ]]; then
        systemctl enable openvpn3-service
        systemctl start openvpn3-service
        systemctl status openvpn3-service
    else
        systemctl enable openvpn
        systemctl start openvpn
        systemctl status openvpn
    fi

    # Tampilkan status dan pesan sukses
    PRINT_SUCCES "OpenVPN berhasil diinstal dan dikonfigurasi."
}

function INSTALL_RCLONE() {
    clear
    PRINTF_INSTALL "Memasang Backup Server"

    # Menentukan distribusi dan versi
    OS=$(lsb_release -si)
    VERSION=$(lsb_release -sr | cut -d. -f1)

    # Install rclone
    apt-get update -y > /dev/null 2>&1
    apt-get install rclone -y > /dev/null 2>&1

    # Konfigurasi rclone
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}cfg_conf_js/rclone.conf"
    
    # Install Wondershaper
    cd /bin
    git clone https://github.com/LunaticTunnel/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper

    # Install tools untuk email
    apt-get install msmtp-mta ca-certificates bsd-mailx -y > /dev/null 2>&1
    
    # Konfigurasi msmtp
    cat <<EOF > /etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF
    chown -R www-data:www-data /etc/msmtprc

    # Menjalankan script ipserver
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver

    # Pesan keberhasilan
    PRINT_SUCCES "Backup Server telah terpasang."
}

function INSTALL_SWAPP() {
    clear
    PRINTF_INSTALL "Memasang Swap 1 G"

    # Mendapatkan versi terbaru dari gotop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v$gotop_latest_linux_amd64.deb"

    # Install gotop sesuai dengan distribusi (Ubuntu 20/Debian 10 vs Ubuntu 22/Debian 11)
    OS=$(lsb_release -si)
    VERSION=$(lsb_release -sr | cut -d. -f1)
    
    # Mengunduh dan menginstal gotop
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    if [ "$OS" == "Ubuntu" ] && [ "$VERSION" -ge 22 ]; then
        # Di Ubuntu 22 atau lebih baru, kita perlu menggunakan `apt` untuk menginstal dependensi
        apt-get update -y
        apt-get install -y libncurses6
    fi
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Membuat dan mengaktifkan swap
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1

    # Menambahkan swap ke fstab
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # Mengatur waktu dan sinkronisasi
    if ! command -v chronyd &>/dev/null; then
        # Jika chrony tidak ada, kita bisa install
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            apt-get install -y chrony
        fi
    fi
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # Menginstall BBR
    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh

    PRINT_SUCCES "Swap 1 G"
}

function INSTALL_FAIL2BAN(){
    clear
    PRINTF_INSTALL "Menginstall Fail2ban"

    # Memeriksa apakah ada versi sebelumnya yang diinstal
    if [ -d '/usr/local/ddos' ]; then
        echo; echo; echo "Please un-install the previous version first"
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    # Memeriksa apakah Fail2ban sudah terinstal, jika belum, maka diinstal
    if ! dpkg -l | grep -q fail2ban; then
        if [ -f /etc/lsb-release ]; then
            . /etc/lsb-release
            if [[ "$DISTRIB_ID" == "Ubuntu" ]] || [[ "$DISTRIB_ID" == "Debian" ]]; then
                apt-get update -y
                apt-get install -y fail2ban > /dev/null 2>&1
            fi
        fi
    fi

    # Menambahkan banner ke konfigurasi SSH dan Dropbear
    echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear

    # Mengunduh dan menyetel banner
    wget -O /etc/banner.txt "${REPO}banner/issue.net" > /dev/null 2>&1

    # Restart Fail2ban untuk memastikan konfigurasi diterapkan
    systemctl restart fail2ban

    PRINT_SUCCES "Fail2ban"
}

function INSTALL_EPROWS(){
    clear
    PRINTF_INSTALL "Menginstall ePro WebSocket Proxy"
    
    # Unduh dan pasang ws, tun.conf, dan ws.service
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}cfg_conf_js/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1

    # Berikan izin akses yang tepat untuk file yang diunduh
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    chmod +x /etc/systemd/system/ws.service
    
    # Matikan dan nonaktifkan service ws jika aktif sebelumnya
    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws
    
    # Unduh file konfigurasi geosite dan geoip untuk xray
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    
    # Unduh dan pasang ftvpn
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn
    
    # Setup iptables untuk blocking traffic terkait BitTorrent
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    
    # Menyimpan dan memuat kembali aturan iptables
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload
    
    # Bersihkan cache dan hapus paket yang tidak digunakan
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    PRINT_SUCCES "ePro WebSocket Proxy"
}

function INSTALL_ENVIRONT(){
    clear
    PRINTF_INSTALL "Memasang Menu Packet"
    wget ${REPO}feature/LUNATIX_sh
    unzip LUNATIX_sh
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf LUNATIX
    rm -rf LUNATIX_sh

    wget ${REPO}feature/LUNATIX_py
    unzip LUNATIX_py
    chmod +x menu/*
    mv menu/* /usr/bin
    rm -rf LUNATIX
    rm -rf LUNATIX_sh
    
    # Menulis file .profile untuk root
    cat >/root/.profile <<EOF
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    # Menulis konfigurasi cron untuk xp_all
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    # Menulis konfigurasi cron untuk logclean
    cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

    # Memberikan izin akses pada file .profile
    chmod 644 /root/.profile

    # Menulis konfigurasi cron untuk daily_reboot
    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

    # Menulis konfigurasi cron untuk membersihkan log nginx dan xray
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

    # Restart cron untuk menerapkan perubahan
    service cron restart

    # Menulis file /home/daily_reboot
    cat >/home/daily_reboot <<-END
5
END

    # Menulis konfigurasi systemd untuk rc-local
    cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    # Menambahkan /bin/false dan /usr/sbin/nologin ke /etc/shells untuk membatasi akses
    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells

    # Menulis file rc.local
    cat >/etc/rc.local <<EOF
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
    chmod +x /etc/rc.local

    # Mengecek pengaturan auto-reboot
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

    # Menampilkan pesan sukses
    PRINT_SUCCES "Menu Packet"
}

function RESTART_SERVICE(){
    clear
    PRINTF_INSTALL "Restarting All Packet"
    
    # Restart berbagai layanan menggunakan init.d dan systemctl
    /etc/init.d/nginx restart
    /etc/init.d/openvpn restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/fail2ban restart
    /etc/init.d/vnstat restart
    systemctl restart haproxy
    /etc/init.d/cron restart
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
        
    # Reload daemon systemd dan start layanan netfilter-persistent
    systemctl daemon-reload
    systemctl start netfilter-persistent
    
    # Enable layanan agar berjalan otomatis saat boot
        
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban
    
    # Bersihkan history terminal untuk menghindari kebocoran data
    history -c
    echo "unset HISTFILE" >> /etc/profile
    
    # Menghapus file konfigurasi yang mungkin sensitif
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    
    PRINT_SUCCES "All Packet"
}

function instal(){
    clear
    INSTALL_HAPROXY
    INSTALL_NGINX
    INSTALL_TOOLS
    INSTALL_FOLDER
    INSTALL_SSLCERT
    INSTALL_XRAY
    INSTALL_PASSWORD
    INSTALL_BADVPN    
    INSTALL_SSHD
    INSTALL_DROPBEAR
    INSTALL_VNSTAT
    INSTALL_OPENVPN
    INSTALL_RCLONE
    INSTALL_SWAPP
    INSTALL_FAIL2BAN
    INSTALL_EPROWS
    INSTALL_ENVIRONT
    RESTART_SERVICE    
    SEND_NOTIF
}

# Menjalankan fungsi instalasi
instal

# Menghapus file yang tidak diperlukan
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
rm -rf /root/LUNATIX_sh
rm -rf /root/LUNATIX_py
rm -rf /root/snap
rm -rf /root/udp-custom
rm -rf /root/udp
rm -rf /root/install.log

# Menampilkan waktu yang dibutuhkan untuk instalasi
secs_to_human "$(($(date +%s) - ${start}))"

# Mengatur hostname server
sudo hostnamectl set-hostname $username

# bersihkan terminal
clear

# Menampilkan pesan sukses
echo -e "\e[31;1m ============================= \e[0m"
echo -e "\e[36;1m        Install Sukses         \e[0m"
echo -e "\e[31;1m ============================= \e[0m"
# Memberi perintah untuk reboot
echo ""
read -p "$( echo -e "\e[97;1m type \e[96;1m'ENTER'\e[97;1m to reboot \e[0m") "
reboot
