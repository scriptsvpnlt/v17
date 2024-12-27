# Daftar paket yang akan diinstal
PACKAGES=(
ubuntu-pro-client-l10n ubuntu-pro-client ubuntu-release-upgrader-core ubuntu-server ubuntu-standard snap docker docker.io podman-docker
udev udisks2 update-manager-core util-linux uuid-runtime vim-common vim-runtime vim-tiny vim xkb-data xxd xz-utils zlib1g zstd
apparmor apport-core-dump-handler apport base-files bind9-dnsutils bind9-host bind9-libs bsdextrautils bsdutils make make-guile
busybox-initramfs busybox-static cloud-init cloud-initramfs-copymods cloud-initramfs-dyn-netconf cryptsetup-bin cryptsetup-initramfs cryptsetup curl dbus-bin
dbus-daemon dbus-session-bus-common dbus-system-bus-common dbus-user-session dbus distro-info-data dmeventd dmidecode  dmsetup dpkg dracut-install
e2fsprogs-l10n  e2fsprogs eject fdisk fwupd gcc-14-base gir1.2-glib-2.0 gir1.2-packagekitglib-1.0 initramfs-tools-bin initramfs-tools-core initramfs-tools krb5-locales landscape-common libacl1
libapparmor1 libarchive13t64 libaudit-common libaudit1 libblkid1 libbz2-1.0 libc-bin libc-dev-bin libc-devtools libc6-dev libc6 libcom-err2 libcryptsetup12 libcurl3t64-gnutls libcurl4t64 libdbus-1-3 libdeflate0 libdevmapper-event1.02.1
libdevmapper1.02.1 libexpat1 libext2fs2t64 libfdisk1 libfwupd2 libgcc-s1 libglib2.0-0t64 libglib2.0-bin libglib2.0-data libgnutls30t64 libgssapi-krb5-2 libgstreamer1.0-0 libheif-plugin-aomdec libheif-plugin-aomenc
libheif-plugin-libde265 libheif1 libhogweed6t64 libicu74 libk5crypto3 libkrb5-3 libkrb5support0 libldap-common libldap2 liblvm2cmd2.03 liblz4-1 liblzma5 libmodule-scandeps-perl libmount1 libnetplan1 libnettle8t64 libnss-systemd libopeniscsiusr
libp11-kit0 libpackagekit-glib2-18 libpam-systemd libproc2-0 libpython3-stdlib libpython3.12-minimal libpython3.12-stdlib libpython3.12t64 libsasl2-2 libsasl2-modules-db libsasl2-modules libseccomp2 libsmartcols1 libss2 libssl3t64 libstdc++6 libsystemd-shared libsystemd0
libtiff6 libudev1 libudisks2-0 libuuid1 libzstd1 linux-headers-generic linux-headers-virtual linux-image-virtual linux-libc-dev linux-tools-common linux-virtual locales login logsave lvm2 lxd-agent-loader motd-news-config mount mtr-tiny nano needrestart
netplan-generator netplan.io open-iscsi open-vm-tools openssh-client openssh-server openssh-sftp-server openssl overlayroot packagekit-tools packagekit passwd procps python-apt-common python3-apport python3-apt python3-distupgrade python3-minimal python3-netplan jq
python3-problem-report python3-setuptools python3-software-properties python3-twisted python3-update-manager python3-urllib3 ubuntu-server ubuntu-standard udev udisks2 update-manager-core util-linux uuid-runtime vim-common vim-runtime vim-tiny vim xkb-data xxd xz-utils zlib1g zstd
python3.12-minimal python3.12 python3 snapd software-properties-common sosreport ssh-import-id systemd-dev systemd-hwe-hwdb systemd-resolved systemd-sysv systemd-timesyncd systemd thin-provisioning-tools tmux ubuntu-minimal ubuntu-pro-client-l10n ubuntu-pro-client ubuntu-release-upgrader-core build-essential libssl-dev
)

# Instalasi paket berdasarkan OS
    sudo apt update -y
    sudo apt upgrade -y
    sudo apt install -y "${PACKAGES[@]}"
