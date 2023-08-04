#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

# set font color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# variables
shell_version="0.1.0"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/xray_web/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

# default values
default_UUID="9413922d-5e4e-44a6-9d0a-43eb2f7eab8c"
default_PRIVATEKEY="KG51ri3PjT00wO3UsSirbnArZ4O3kQ7TF-JoJ6uoZ2A"

# print ok/error message
function print_ok() {
    echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
    echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

# check root
function is_root() {
    if [[ 0 -ne $EUID ]]; then
        print_error "This script must be run as root!"
        exit 1
    else
        print_ok "Current user is root. Start installation."
    fi
}
# [[ 0 -ne $EUID ]] && echo -e "${ERROR} This script must be run as root!" && exit 1

# check system
function system_check() {
    source '/etc/os-release'
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        print_ok "Current OS: CentOS ${VERSION_ID} ${VERSION}"
        INS="yum install -y"
        ${INS} wget
        wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/siikii/xray_install/${github_branch}/basic/nginx.repo
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        print_ok "Current OS: Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
        INS="apt install -y"
        # remove nginx repo to be safe
        rm -f /etc/apt/sources.list.d/nginx.list
        # preprocess nginx installation
        $INS curl gnupg2 ca-certificates lsb-release ubuntu-keyring
        curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor |
            tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" |
            tee /etc/apt/sources.list.d/nginx.list
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" |
            tee /etc/apt/preferences.d/99nginx
        apt update
    else
        print_error "Current OS: ${ID} ${VERSION_ID} is not supported!"
        exit 1
    fi
}

# status check
judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 succeeded."
        sleep 1
    else
        print_error "$1 failed."
        exit 1
    fi
}

# check version of this script
function update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/siikii/xray_install/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
        print_ok "Found new version of the script, update? [Y/N]?"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            wget -N --no-check-certificate https://raw.githubusercontent.com/siikii/xray_install/${github_branch}/install.sh
            print_ok "Update completed."
            print_ok "Use bash $0 to run this script."
            exit 0
            ;;
        *) ;;
        esac
    else
        print_ok "No new version found."
        print_ok "Use bash $0 to run this script."
    fi
}

# check current mode
function shell_mode_check() {
    if [ -f ${xray_conf_dir}/config.json ]; then
        if [ "$(grep -c "wsSettings" ${xray_conf_dir}/config.json)" -ge 1 ]; then
            shell_mode="ws"
        else
            shell_mode="tcp"
        fi
    else
        shell_mode="None"
    fi
}

# install dependency
function dependency_install() {
    ${INS} lsof tar
    judge "install lsof tar"

    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
        ${INS} crontabs
    else
        ${INS} cron
    fi
    judge "install crontab"

    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab autostart setting"

    ${INS} unzip
    judge "install unzip"

    ${INS} curl
    judge "install curl"

    # upgrade systemd
    ${INS} systemd
    judge "install/upgrade systemd"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
    else
        ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
    fi

    ${INS} jq

    if ! command -v jq; then
        wget -P /usr/bin https://raw.githubusercontent.com/siikii/xray_install/${github_branch}/binary/jq && chmod +x /usr/bin/jq
        judge "install jq"
    fi

    # ensure xray default install path exists
    mkdir /usr/local/bin >/dev/null 2>&1
}

function basic_optimization() {
    # maximum number of open files
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # RedHat-based linux disbale SELinux
    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
}

function domain_check() {
    echo "If you don't have a domain name, local ip address will be used."
    read -rp "Do you want to use domain name? (y/n)" answer
    case $answer in
    [yY][eE][sS] | [yY])
        echo "If you have not pointed your domain to this server, please do so before continuing."
        read -rp "Please input your domain name (eg: www.example.com):" domain
        domain_ip = $(curl -sm8 ipget.net/?ip="$domain")
        local_ipv4 = "$(curl -4 ip.sb)"

        if [[ ${domain_ip} == "${local_ipv4}" ]]; then
            print_ok "The IP from DNS resolution matches the local IP."
            sleep 2
        else
            print_error "Please insure that correct A / AAAA record has beeb added, or you will not be able to use Xray normally."
            print_error "Doamin IP from DNS not match local IP, continue to install anyway? (y/n)" && read -r install
            case $install in
            [yY][eE][sS] | [yY])
                print_ok "continue to install"
                sleep 2
                ;;
            *)
                print_error "abort installation"
                exit 2
                ;;
            esac
        fi
        ;;
    *)
        domain="$(local_ipv4)"
        print_ok "Local IP address will be used."
        ;;
    esac
}

function port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        print_ok "$1 port is available."
        sleep 1
    else
        print_error "$1 port is not available. $1 port is occupied by the following program."
        lsof -i:"$1"
        print_error "wait 5s to kill the process occupying $1 port"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        print_ok "kill succeeded."
        sleep 1
    fi
}

function xray_tmp_config_file_check_and_use() {
    if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
        mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
    else
        print_error "xray configure file modification not successful!"
    fi
}

function modify_UUID() {
    read -rp "Do you want to use the default UUID? (Y/N): " answer
    answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]') # convert to lowercase
    if [[ $answer == "y" ]]; then
        UUID="$default_UUID"
    else
        UUID=$(cat /proc/sys/kernel/random/uuid)
    fi
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
    xray_tmp_config_file_check_and_use
    judge "modify UUID"
}

function modify_privateKey() {
    echo "Please use default private key if you haven't installed xray."
    echo "private key and public key pair can only be generated after installing xray."
    read -rp "Do you want to use the default PRIVATEKEY? (Y/N): " answer
    answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]') # convert to lowercase
    if [[ $answer == "y" ]]; then
        PRIVATEKEY="$default_PRIVATEKEY"
    else
        PRIVATEKEY=$(head -c 32 /dev/random | base64 -w 0 | tr '+/' '-_' | tr -d '=' | xargs xray x25519 -i)
        echo "private key and public key pair can only be generated after installing xray."
        echo -e "$yellow private key (PrivateKey) = ${cyan}${private_key}${none}"
    fi
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","realitySettings","privateKey"];"'${PRIVATEKEY}'")' >${xray_conf_dir}/config_tmp.json
    xray_tmp_config_file_check_and_use
    judge "modify privateKey"
}

function modify_port() {
    read -rp "Please input port number (default: 443): " PORT
    [ -z "$PORT" ] && PORT="443"
    if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
        print_error "Please input value between 0-65535"
        exit 1
    fi
    port_exist_check $PORT
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"port"];'${PORT}')' >${xray_conf_dir}/config_tmp.json
    xray_tmp_config_file_check_and_use
    judge "modify Xray port"
}

function modify_dest() {
    read -rp "Please input destination address (default: www.microsoft.com): " dest
    [ -z "$dest" ] && dest="www.microsoft.com"
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","realitySettings","dest"];"'${dest}'")' >${xray_conf_dir}/config_tmp.json
    xray_tmp_config_file_check_and_use
    judge "modify dest"
}

function modify_severnames() {
    read -rp "Please input server names (default: www.microsoft.com): " servernames
    [ -z "$servernames" ] && servernames="www.microsoft.com"
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","realitySettings","serverNames",0];"'${servernames}'")' >${xray_conf_dir}/config_tmp.json
    xray_tmp_config_file_check_and_use
    judge "modify serverNames"
}

function xray_install() {
    print_ok "Install Xray"
    curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
    judge "install xray"
}

function configure_xray() {
    cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/siikii/xray_install/${github_branch}/config/vless_xtls-utls-reality.json
    modify_UUID
    modify_port
    modify_dest
    modify_severnames
    modify_privateKey
}

function restart_xray() {
    systemctl restart xray
    judge "Xray restart"
}

function restart_nginx() {
    systemctl restart nginx
    judge "nginx restart"
}

function vless_xtls-utls-reality_information() {
    UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
    PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
    FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
    DECRYPTION=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.decryption | tr -d '"')
    SECURITY=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].streamSettings.security | tr -d '"')
    DEST=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].streamSettings.realitySettings.dest | tr -d '"')
    SERVERNAMES=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].streamSettings.realitySettings.serverNames[0] | tr -d '"')
    PRIVATEKEY=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].streamSettings.realitySettings.privateKey | tr -d '"')
    PUBLICKEY=$(echo "$PRIVATEKEY" | xargs xray x25519 -i | tr -d '\n' | awk '{print $6}')

    echo -e "${Red} Xray Configuration Info ${Font}"
    # echo -e "${Red} 地址（address）:${Font}  $DOMAIN"
    echo -e "${Red} Port:${Font} $PORT"
    echo -e "${Red} UUID:${Font} $UUID"
    echo -e "${Red} Flow:${Font} $FLOW"
    echo -e "${Red} Decyption:${Font} $DECRYPTION"
    echo -e "${Red} Network:${Font} tcp"
    echo -e "${Red} Security:${Font} $SECURITY"
    echo -e "${Red} Dest:${Font} $DEST"
    echo -e "${Red} ServerNames:${Font} $SERVERNAMES"
    echo -e "${Red} PrivateKey:${Font} $PRIVATEKEY"
    echo -e "${Red} PublicKey:${Font} $PUBLICKEY"
    print_ok "Xray vless+xtls+utls+reality configuration info print completed."
}

# function vless_xtls-utls-reality_link() {

# }

function basic_information() {
    print_ok "VLESS+uTLS+Reality install succeded."
    vless_xtls-utls-reality_information
    # vless_xtls-utls-reality_link
}

# install xray
function install_xray() {
    is_root
    system_check
    dependency_install
    basic_optimization
    domain_check
    # port_exist_check 80
    xray_install
    configure_xray
    # nginx_install
    # configure_nginx
    # configure_web
    # generate_certificate
    # ssl_judge_and_install
    restart_xray
    basic_information
}

# uninstall Xray
function xray_uninstall() {
    curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
    rm -rf $website_dir
    print_ok "If you have nginx installed, uninstall it to release port 443 [Y/N]?"
    read -r uninstall_nginx
    case $uninstall_nginx in
    [yY][eE][sS] | [yY])
        if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
            yum remove nginx -y
        else
            apt purge nginx -y
        fi
        ;;
    *) ;;
    esac
    print_ok "Uninstall acme.sh [Y/N]?"
    read -r uninstall_acme
    case $uninstall_acme in
    [yY][eE][sS] | [yY])
        "$HOME"/.acme.sh/acme.sh --uninstall
        rm -rf /root/.acme.sh
        rm -rf /ssl/
        ;;
    *) ;;
    esac
    print_ok "Uninstall completed."
    exit 0
}

# menu
menu() {
    update_sh

    echo -e "Current installed mode: ${shell_mode}"
    if [[ ${shell_mode} == "ws" ]]; then
        echo -e "Looks like you have installed Xray (TLS + Nginx + WebSocket), please uninstall it first."
        print_ok "Uninstall Xray (TLS + Nginx + WebSocket)? [Y/N]"
        read -r uninstall_confirm
        case $uninstall_confirm in
        [yY][eE][sS] | [yY])
            xray_uninstall
            ;;
        *) ;;
        esac
    fi

    echo -e "\tXray VLESS-uTLS-Reality 安装管理脚本 ${Red}[${shell_version}]${Font}"
    echo -e "\t---authored by siikii---"
    echo -e "\thttps://github.com/siikii/xray_install\n"
    echo -e "—————————————— 安装向导 ——————————————"""
    echo -e "${Green}0.${Font}  升级 脚本"
    echo -e "${Green}1.${Font}  安装 Xray (VLESS + uTLS + Reality)"
    echo -e "—————————————— 配置变更 ——————————————"
    echo -e "${Green}11.${Font} 变更 UUID"
    echo -e "${Green}13.${Font} 变更 连接端口"
    echo -e "—————————————— 查看信息 ——————————————"
    echo -e "${Green}21.${Font} 查看 实时访问日志"
    echo -e "${Green}22.${Font} 查看 实时错误日志"
    echo -e "${Green}23.${Font} 查看 Xray 配置链接"
    echo -e "—————————————— 其他选项 ——————————————"
    echo -e "${Green}33.${Font} 卸载 Xray"
    echo -e "${Green}34.${Font} 更新 Xray-core"
    echo -e "${Green}35.${Font} 安装 Xray-core 测试版 (Pre)"
    echo -e "${Green}40.${Font} 退出"
    read -rp "请输入数字：" menu_num
    case $menu_num in
    0)
        update_sh
        ;;
    1)
        install_xray
        ;;
    11)
        read -rp "请输入 UUID:" UUID
        modify_UUID
        restart_all
        ;;
    13)
        modify_port
        restart_all
        ;;
    21)
        tail -f $xray_access_log
        ;;
    22)
        tail -f $xray_error_log
        ;;
    23)
        if [[ -f $xray_conf_dir/config.json ]]; then
            basic_information
        fi
        ;;
    33)
        source '/etc/os-release'
        xray_uninstall
        ;;
    34)
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
        restart_all
        ;;
    35)
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
        restart_all
        ;;
    40)
        exit 0
        ;;
    *)
        print_error "Please enter the correct number: "
        ;;
    esac
}
menu "$@"
