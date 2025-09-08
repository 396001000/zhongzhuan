#!/bin/bash

# 超级中转脚本 - WireGuard多落地机管理工具
# 版本: 1.2.0
# 作者: 超级中转团队
# 支持系统: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch, Manjaro, openSUSE, Alpine, Gentoo, Void

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 全局变量
SCRIPT_DIR="/etc/chaojizhongzhuan"
CONFIG_FILE="$SCRIPT_DIR/config.json"
SERVERS_FILE="$SCRIPT_DIR/servers.json"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 检测系统类型
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        OS_ID=$ID
        OS_ID_LIKE=$ID_LIKE
    elif [[ -f /etc/redhat-release ]]; then
        OS=$(cat /etc/redhat-release | cut -d' ' -f1)
        VER=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+' | head -1)
        OS_ID="rhel"
    elif [[ -f /etc/debian_version ]]; then
        OS="Debian"
        VER=$(cat /etc/debian_version)
        OS_ID="debian"
    else
        log_error "无法检测操作系统类型"
        exit 1
    fi
    
    log_info "检测到系统: $OS $VER"
    log_info "系统标识: $OS_ID"
}

# 创建脚本目录
create_directories() {
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "/etc/wireguard/keys"
}

# 检测可用端口
find_available_port() {
    local start_port=$1
    local port=$start_port
    
    while [ $port -le 65535 ]; do
        if ! ss -tulpn | grep ":$port " >/dev/null 2>&1; then
            echo $port
            return
        fi
        ((port++))
    done
    
    echo $((RANDOM % 10000 + 10000))
}

# 安装依赖
install_dependencies() {
    log_step "安装系统依赖..."
    
    # Debian/Ubuntu系列
    if [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]] || [[ "$OS_ID_LIKE" =~ "debian" ]]; then
        apt update -y
        
        # 分步安装以避免依赖冲突
        apt install -y curl wget net-tools jq
        
        # 安装WireGuard
        apt install -y wireguard wireguard-tools
        
        # 处理iptables-persistent和ufw的冲突
        setup_iptables_persistence
        
        # 确保ufw可用
        if ! command -v ufw &> /dev/null; then
            apt install -y ufw 2>/dev/null || log_warn "ufw安装失败，将使用iptables"
        fi
        
    # RHEL/CentOS/Fedora系列
    elif [[ "$OS_ID" == "centos" ]] || [[ "$OS_ID" == "rhel" ]] || [[ "$OS_ID" == "fedora" ]] || [[ "$OS_ID_LIKE" =~ "rhel" ]] || [[ "$OS_ID_LIKE" =~ "fedora" ]]; then
        
        if [[ "$OS_ID" == "fedora" ]]; then
            # Fedora使用dnf
            dnf update -y
            dnf install -y wireguard-tools iptables curl wget net-tools jq
        else
            # RHEL/CentOS使用yum
            if command -v dnf &> /dev/null; then
                dnf update -y
                dnf install -y epel-release
                dnf install -y wireguard-tools iptables curl wget net-tools jq
            else
                yum update -y
                yum install -y epel-release
                yum install -y wireguard-tools iptables curl wget net-tools jq
            fi
        fi
        
        # RHEL系列通常使用firewalld
        if command -v firewalld &> /dev/null; then
            systemctl enable firewalld 2>/dev/null || true
            systemctl start firewalld 2>/dev/null || true
        fi
        
    # Arch Linux系列
    elif [[ "$OS_ID" == "arch" ]] || [[ "$OS_ID" == "manjaro" ]] || [[ "$OS_ID_LIKE" =~ "arch" ]]; then
        pacman -Syu --noconfirm
        pacman -S --noconfirm wireguard-tools iptables curl wget net-tools jq
        
    # openSUSE系列
    elif [[ "$OS_ID" == "opensuse-leap" ]] || [[ "$OS_ID" == "opensuse-tumbleweed" ]] || [[ "$OS_ID" == "sles" ]]; then
        zypper refresh
        zypper install -y wireguard-tools iptables curl wget net-tools jq
        
    # Alpine Linux
    elif [[ "$OS_ID" == "alpine" ]]; then
        apk update
        apk add wireguard-tools iptables curl wget net-tools jq
        
    # Gentoo
    elif [[ "$OS_ID" == "gentoo" ]]; then
        emerge --sync
        emerge -av net-vpn/wireguard-tools net-firewall/iptables net-misc/curl net-misc/wget sys-apps/net-tools app-misc/jq
        
    # Void Linux
    elif [[ "$OS_ID" == "void" ]]; then
        xbps-install -Syu
        xbps-install -y wireguard-tools iptables curl wget net-tools jq
        
    else
        log_error "不支持的操作系统: $OS ($OS_ID)"
        log_error "支持的系统: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch Linux, Manjaro, openSUSE, Alpine, Gentoo, Void Linux"
        exit 1
    fi
    
    log_info "依赖安装完成"
}

# 设置iptables持久化
setup_iptables_persistence() {
    if ! dpkg -l | grep -q iptables-persistent; then
        # 如果没有安装iptables-persistent，尝试安装
        apt install -y iptables-persistent 2>/dev/null || {
            log_warn "iptables-persistent安装失败，使用替代方案"
            create_iptables_scripts
        }
    fi
}

# 创建iptables管理脚本
create_iptables_scripts() {
    # 创建iptables规则保存机制
    mkdir -p /etc/iptables
    
    # 创建规则保存脚本
    cat > /usr/local/bin/save-iptables << 'EOF'
#!/bin/bash
# 保存当前iptables规则
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
EOF
    chmod +x /usr/local/bin/save-iptables
    
    # 创建规则恢复脚本
    cat > /usr/local/bin/restore-iptables << 'EOF'
#!/bin/bash
# 恢复iptables规则
if [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4 2>/dev/null || true
fi
if [ -f /etc/iptables/rules.v6 ]; then
    ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null || true
fi
EOF
    chmod +x /usr/local/bin/restore-iptables
    
    # 创建systemd服务
    cat > /etc/systemd/system/iptables-restore.service << 'EOF'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/restore-iptables

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable iptables-restore.service 2>/dev/null || true
}

# 配置防火墙
configure_firewall() {
    local port=$1
    log_step "配置防火墙规则..."
    
    # 优先级：firewalld > ufw > iptables
    if command -v firewall-cmd &> /dev/null && systemctl is-active firewalld >/dev/null 2>&1; then
        # 使用firewalld (RHEL/CentOS/Fedora)
        firewall-cmd --permanent --add-port=${port}/udp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_info "Firewalld防火墙规则已添加"
        
    elif command -v ufw &> /dev/null && ufw status >/dev/null 2>&1; then
        # 使用UFW (Ubuntu/Debian)
        ufw allow $port/udp comment "WireGuard" 2>/dev/null || true
        log_info "UFW防火墙规则已添加"
        
    else
        # 使用iptables作为备选
        iptables -I INPUT -p udp --dport $port -j ACCEPT 2>/dev/null || true
        log_info "iptables防火墙规则已添加"
        
        # 保存iptables规则
        if command -v save-iptables &> /dev/null; then
            save-iptables
        elif command -v iptables-save &> /dev/null; then
            # 尝试其他保存方式
            if [[ "$OS_ID" == "arch" ]] || [[ "$OS_ID" == "manjaro" ]]; then
                iptables-save > /etc/iptables/iptables.rules 2>/dev/null || true
            elif [[ "$OS_ID" == "alpine" ]]; then
                /etc/init.d/iptables save 2>/dev/null || true
            fi
        fi
    fi
}

# 系统优化
optimize_system() {
    log_step "优化系统网络参数..."
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.backup 2>/dev/null || true
    
    # 网络优化参数
    cat >> /etc/sysctl.conf << EOF

# 超级中转脚本网络优化参数
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# TCP优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr

# 网络缓冲区优化
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1

# 连接优化
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30

# UDP优化
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF

    sysctl -p >/dev/null 2>&1
    log_info "系统优化完成"
}

# 获取网络接口
get_network_interface() {
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$INTERFACE" ]]; then
        INTERFACE="eth0"
        log_warn "无法自动检测网络接口，使用默认值: $INTERFACE"
    else
        log_info "检测到网络接口: $INTERFACE"
    fi
}

# 获取服务器公网IP
get_server_ip() {
    SERVER_IP=$(curl -s --connect-timeout 5 ipv4.icanhazip.com || curl -s --connect-timeout 5 ifconfig.me || echo "")
    if [[ -z "$SERVER_IP" ]]; then
        read -p "无法自动获取服务器IP，请手动输入: " SERVER_IP
    fi
}

# 配置落地机
setup_landing_server() {
    log_step "配置WireGuard落地机..."
    
    # 检测端口
    local port=$(find_available_port 51820)
    echo ""
    read -p "WireGuard监听端口 [$port]: " custom_port
    port=${custom_port:-$port}
    
    # 生成密钥
    cd /etc/wireguard/keys
    wg genkey | tee server.key | wg pubkey > server.pub
    wg genkey | tee client.key | wg pubkey > client.pub
    chmod 600 *.key
    
    local server_private=$(cat server.key)
    local server_public=$(cat server.pub)
    local client_private=$(cat client.key)
    local client_public=$(cat client.pub)
    
    # 创建WireGuard配置
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $server_private
Address = 10.0.0.1/24
ListenPort = $port
PostUp = iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $INTERFACE -j MASQUERADE
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -A INPUT -p udp --dport $port -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport $port -j ACCEPT

[Peer]
PublicKey = $client_public
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
EOF

    # 配置防火墙
    configure_firewall $port
    
    # 修复配置文件权限
    chmod 600 /etc/wireguard/wg0.conf
    
    # 启动服务
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # 保存配置
    cat > "$CONFIG_FILE" << EOF
{
    "type": "landing_server",
    "port": $port,
    "server_private": "$server_private",
    "server_public": "$server_public",
    "client_private": "$client_private",
    "client_public": "$client_public",
    "server_ip": "$SERVER_IP"
}
EOF
    
    # 显示连接密钥
    local connection_key="wg://$server_public@$SERVER_IP:$port/$client_private"
    
    echo ""
    echo "==============================================="
    echo -e "${GREEN}落地机配置完成！${NC}"
    echo "==============================================="
    echo ""
    echo -e "${YELLOW}连接密钥（请保存给中转机使用）:${NC}"
    echo -e "${CYAN}$connection_key${NC}"
    echo ""
    echo -e "${YELLOW}服务状态:${NC}"
    systemctl status wg-quick@wg0 --no-pager -l
    echo ""
}

# 解析连接密钥
parse_connection_key() {
    local key="$1"
    
    # 检查格式 wg://pubkey@ip:port/privkey
    if [[ ! "$key" =~ ^wg://([^@]+)@([^:]+):([0-9]+)/(.+)$ ]]; then
        log_error "无效的连接密钥格式"
        return 1
    fi
    
    SERVER_PUBLIC_KEY="${BASH_REMATCH[1]}"
    SERVER_IP="${BASH_REMATCH[2]}"
    SERVER_PORT="${BASH_REMATCH[3]}"
    CLIENT_PRIVATE_KEY="${BASH_REMATCH[4]}"
    
    return 0
}

# 添加落地机
add_landing_server() {
    # 检查WireGuard是否安装
    if ! command -v wg-quick &> /dev/null; then
        log_step "检测到WireGuard未安装，正在安装..."
        install_dependencies
        optimize_system
    fi
    
    echo ""
    read -p "请输入落地机名称: " server_name
    if [[ -z "$server_name" ]]; then
        log_error "落地机名称不能为空"
        return 1
    fi
    
    read -p "请输入落地机连接密钥: " connection_key
    if [[ -z "$connection_key" ]]; then
        log_error "连接密钥不能为空"
        return 1
    fi
    
    # 解析密钥
    if ! parse_connection_key "$connection_key"; then
        return 1
    fi
    
    # 检查是否已存在
    if [[ -f "$SERVERS_FILE" ]] && jq -e ".servers[] | select(.name==\"$server_name\")" "$SERVERS_FILE" >/dev/null 2>&1; then
        log_error "落地机名称已存在: $server_name"
        return 1
    fi
    
    # 生成配置
    local interface_name="wg-$(echo "$server_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"
    local subnet=$(($(get_next_subnet)))
    
    # 创建WireGuard配置文件
    cat > "/etc/wireguard/${interface_name}.conf" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24
# 保留本地SSH连接，避免断开管理连接
Table = off

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF
    
    # 修复配置文件权限
    chmod 600 "/etc/wireguard/${interface_name}.conf"
    
    # 保存当前SSH连接信息
    local ssh_client_ip=$(echo $SSH_CLIENT | awk '{print $1}' 2>/dev/null || echo "unknown")
    local ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -1 || echo "22")
    
    log_warn "重要提醒：正在启动WireGuard，请确保以下连接方式可用："
    log_warn "1. 服务商控制台/VNC连接"
    log_warn "2. SSH当前连接保持: $ssh_client_ip:$ssh_port"
    
    # 启动WireGuard接口（使用安全模式）
    log_step "启动WireGuard接口: $interface_name"
    if ! wg-quick up "$interface_name" 2>/dev/null; then
        log_error "WireGuard接口启动失败，请检查配置"
        log_error "可能的原因：1) 端口被占用 2) 网络配置冲突 3) 权限问题"
        rm -f "/etc/wireguard/${interface_name}.conf"
        return 1
    fi
    
    # 测试连接
    log_step "测试WireGuard连接..."
    sleep 3
    if ! wg show "$interface_name" >/dev/null 2>&1; then
        log_error "WireGuard接口状态异常"
        wg-quick down "$interface_name" 2>/dev/null || true
        rm -f "/etc/wireguard/${interface_name}.conf"
        return 1
    fi
    
    systemctl enable "wg-quick@$interface_name" 2>/dev/null || true
    log_info "WireGuard接口启动成功: $interface_name"
    
    # 保存到服务器列表
    local server_data=$(cat << EOF
{
    "name": "$server_name",
    "interface": "$interface_name",
    "endpoint": "$SERVER_IP:$SERVER_PORT",
    "public_key": "$SERVER_PUBLIC_KEY",
    "private_key": "$CLIENT_PRIVATE_KEY",
    "subnet": $subnet,
    "added_time": "$(date)"
}
EOF
)
    
    if [[ ! -f "$SERVERS_FILE" ]]; then
        echo '{"servers": []}' > "$SERVERS_FILE"
    fi
    
    jq ".servers += [$server_data]" "$SERVERS_FILE" > "${SERVERS_FILE}.tmp" && mv "${SERVERS_FILE}.tmp" "$SERVERS_FILE"
    
    # 测试连接
    log_step "测试连接到落地机..."
    if ping -c 3 -W 5 "10.0.0.1" >/dev/null 2>&1; then
        log_info "✅ $server_name 连接成功"
    else
        log_warn "⚠️  $server_name 连接测试失败，请检查配置"
    fi
    
    echo ""
    log_info "落地机 $server_name 添加完成"
}

# 获取下一个可用子网
get_next_subnet() {
    local max_subnet=1
    if [[ -f "$SERVERS_FILE" ]]; then
        local subnets=$(jq -r '.servers[].subnet' "$SERVERS_FILE" 2>/dev/null || echo "")
        for subnet in $subnets; do
            if [[ $subnet -gt $max_subnet ]]; then
                max_subnet=$subnet
            fi
        done
    fi
    echo $((max_subnet + 1))
}

# 查看落地机列表
list_landing_servers() {
    echo ""
    echo "==============================================="
    echo -e "${BLUE}落地机列表${NC}"
    echo "==============================================="
    
    if [[ ! -f "$SERVERS_FILE" ]] || [[ $(jq '.servers | length' "$SERVERS_FILE" 2>/dev/null || echo 0) -eq 0 ]]; then
        echo "暂无落地机"
        return
    fi
    
    local i=1
    jq -r '.servers[] | "\(.name)|\(.endpoint)|\(.interface)"' "$SERVERS_FILE" | while IFS='|' read -r name endpoint interface; do
        local status="离线"
        local color="$RED"
        local detail=""
        
        # 直接检查WireGuard接口状态（更准确）
        if wg show "$interface" >/dev/null 2>&1; then
            # 检查WireGuard握手状态
            local handshake_info=$(wg show "$interface" latest-handshakes 2>/dev/null | head -1)
            if [[ -n "$handshake_info" ]]; then
                local handshake_time=$(echo "$handshake_info" | awk '{print $2}')
                local current_time=$(date +%s)
                local time_diff=$((current_time - handshake_time))
                
                if [[ $time_diff -lt 300 ]]; then  # 5分钟内有握手
                    status="在线"
                    color="$GREEN"
                    if [[ $time_diff -lt 60 ]]; then
                        detail="(刚刚活跃)"
                    else
                        detail="(${time_diff}秒前活跃)"
                    fi
                else
                    status="连接中"
                    color="$YELLOW"
                    detail="(${time_diff}秒前握手)"
                fi
            else
                status="启动中"
                color="$YELLOW"
                detail="(等待握手)"
            fi
        fi
        
        echo -e "$i. ${CYAN}$name${NC} (${color}$status${NC}) $detail"
        echo "   端点: $endpoint"
        echo "   接口: $interface"
        echo ""
        ((i++))
    done
}

# 删除落地机
remove_landing_server() {
    list_landing_servers
    
    if [[ ! -f "$SERVERS_FILE" ]] || [[ $(jq '.servers | length' "$SERVERS_FILE" 2>/dev/null || echo 0) -eq 0 ]]; then
        return
    fi
    
    echo ""
    read -p "请输入要删除的落地机名称: " server_name
    if [[ -z "$server_name" ]]; then
        log_error "落地机名称不能为空"
        return 1
    fi
    
    # 查找服务器
    local server_info=$(jq -r ".servers[] | select(.name==\"$server_name\") | \"\(.interface)\"" "$SERVERS_FILE" 2>/dev/null)
    if [[ -z "$server_info" ]]; then
        log_error "未找到落地机: $server_name"
        return 1
    fi
    
    local interface="$server_info"
    
    # 确认删除
    echo ""
    read -p "确认删除落地机 '$server_name' ? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "取消删除"
        return
    fi
    
    # 停止并删除WireGuard接口
    systemctl stop "wg-quick@$interface" 2>/dev/null || true
    systemctl disable "wg-quick@$interface" 2>/dev/null || true
    rm -f "/etc/wireguard/${interface}.conf"
    
    # 从配置文件中删除
    jq ".servers = [.servers[] | select(.name != \"$server_name\")]" "$SERVERS_FILE" > "${SERVERS_FILE}.tmp" && mv "${SERVERS_FILE}.tmp" "$SERVERS_FILE"
    
    log_info "落地机 $server_name 已删除"
}

# 生成3x-ui出站配置
generate_3xui_config() {
    echo ""
    log_step "生成3x-ui出站配置..."
    
    if [[ ! -f "$SERVERS_FILE" ]] || [[ $(jq '.servers | length' "$SERVERS_FILE" 2>/dev/null || echo 0) -eq 0 ]]; then
        log_error "暂无落地机，请先添加落地机"
        return 1
    fi
    
    local config_file="/tmp/3xui_outbounds_$(date +%Y%m%d_%H%M%S).json"
    
    # 生成配置
    cat > "$config_file" << 'EOF'
{
  "outbounds": [
EOF
    
    local first=true
    jq -r '.servers[] | "\(.name)|\(.private_key)|\(.public_key)|\(.endpoint)|\(.subnet)"' "$SERVERS_FILE" | while IFS='|' read -r name private_key public_key endpoint subnet; do
        if [[ "$first" == "false" ]]; then
            echo "    }," >> "$config_file"
        fi
        first=false
        
        local tag="wg-$(echo "$name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"
        
        cat >> "$config_file" << EOF
    {
      "tag": "$tag",
      "protocol": "wireguard",
      "settings": {
        "secretKey": "$private_key",
        "address": ["10.0.0.2/24"],
        "peers": [
          {
            "publicKey": "$public_key",
            "allowedIPs": ["0.0.0.0/0"],
            "endpoint": "$endpoint"
          }
        ]
      }
EOF
    done
    
    cat >> "$config_file" << 'EOF'
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ]
}
EOF
    
    echo ""
    echo "==============================================="
    echo -e "${GREEN}3x-ui出站配置已生成${NC}"
    echo "==============================================="
    echo ""
    echo -e "${YELLOW}配置文件位置:${NC} $config_file"
    echo ""
    echo -e "${YELLOW}使用方法:${NC}"
    echo "1. 复制以下配置内容"
    echo "2. 登录3x-ui管理面板"
    echo "3. 出站设置 → 批量添加"
    echo "4. 粘贴配置内容并保存"
    echo "5. 重启3x-ui服务"
    echo ""
    echo -e "${CYAN}配置内容:${NC}"
    echo "----------------------------------------"
    cat "$config_file"
    echo "----------------------------------------"
    echo ""
    echo -e "${YELLOW}提示:${NC} 客户端请设置为'规则模式'或'绕过大陆'以实现智能分流"
}

# 查看连接状态
show_connection_status() {
    echo ""
    echo "==============================================="
    echo -e "${BLUE}连接状态${NC}"
    echo "==============================================="
    
    # 检查当前类型
    if [[ -f "$CONFIG_FILE" ]]; then
        local server_type=$(jq -r '.type' "$CONFIG_FILE" 2>/dev/null || echo "unknown")
        
        if [[ "$server_type" == "landing_server" ]]; then
            echo -e "${CYAN}当前模式:${NC} 落地机"
            echo ""
            echo -e "${YELLOW}WireGuard状态:${NC}"
            systemctl status wg-quick@wg0 --no-pager -l
            echo ""
            echo -e "${YELLOW}连接统计:${NC}"
            wg show wg0 2>/dev/null || echo "WireGuard未运行"
        else
            echo -e "${CYAN}当前模式:${NC} 中转机"
            echo ""
            echo -e "${YELLOW}WireGuard接口状态:${NC}"
            
            if [[ -f "$SERVERS_FILE" ]]; then
                jq -r '.servers[].interface' "$SERVERS_FILE" | while read -r interface; do
                    echo "接口: $interface"
                    if systemctl is-active "wg-quick@$interface" >/dev/null 2>&1; then
                        echo -e "状态: ${GREEN}运行中${NC}"
                        wg show "$interface" 2>/dev/null | head -5
                    else
                        echo -e "状态: ${RED}已停止${NC}"
                    fi
                    echo ""
                done
            fi
        fi
    else
        echo "未检测到配置文件"
    fi
}

# 重启服务
restart_services() {
    log_step "重启WireGuard服务..."
    
    if [[ -f "$CONFIG_FILE" ]]; then
        local server_type=$(jq -r '.type' "$CONFIG_FILE" 2>/dev/null || echo "unknown")
        
        if [[ "$server_type" == "landing_server" ]]; then
            systemctl restart wg-quick@wg0
            log_info "落地机WireGuard服务已重启"
        else
            if [[ -f "$SERVERS_FILE" ]]; then
                jq -r '.servers[].interface' "$SERVERS_FILE" | while read -r interface; do
                    systemctl restart "wg-quick@$interface"
                    log_info "接口 $interface 已重启"
                done
            fi
        fi
    else
        log_warn "未检测到配置，尝试重启所有WireGuard接口"
        systemctl restart wg-quick@* 2>/dev/null || true
    fi
}

# 卸载脚本
uninstall_script() {
    echo ""
    read -p "确认卸载超级中转脚本及所有配置? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "取消卸载"
        return
    fi
    
    log_step "停止所有WireGuard服务..."
    systemctl stop wg-quick@* 2>/dev/null || true
    systemctl disable wg-quick@* 2>/dev/null || true
    
    log_step "删除配置文件..."
    rm -rf /etc/wireguard/wg*.conf
    rm -rf "$SCRIPT_DIR"
    rm -f /usr/local/bin/chaojizhongzhuan
    
    log_step "清理系统配置..."
    # 恢复sysctl配置
    if [[ -f /etc/sysctl.conf.backup ]]; then
        mv /etc/sysctl.conf.backup /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
    
    log_info "卸载完成"
}

# 更新脚本
update_script() {
    echo ""
    echo "==============================================="
    echo -e "${BLUE}脚本更新工具${NC}"
    echo "==============================================="
    echo ""
    
    log_step "检查脚本更新..."
    
    # 定义更新源
    local github_url="https://raw.githubusercontent.com/396001000/zhongzhuan/main/chaojizhongzhuan.sh"
    local gitee_url="https://gitee.com/dlaasd/zhongzhuan/raw/main/chaojizhongzhuan.sh"
    local version_url="https://raw.githubusercontent.com/396001000/zhongzhuan/main/version.json"
    local current_version="1.2.0"
    
    # 检查网络连接和版本信息
    log_step "获取最新版本信息..."
    local latest_version=""
    local update_info=""
    
    if curl -s --connect-timeout 10 "$version_url" >/dev/null 2>&1; then
        latest_version=$(curl -s --connect-timeout 10 "$version_url" | jq -r '.version' 2>/dev/null || echo "")
        update_info=$(curl -s --connect-timeout 10 "$version_url" | jq -r '.changelog[]' 2>/dev/null || echo "")
    fi
    
    echo ""
    echo -e "${CYAN}当前版本:${NC} $current_version"
    if [[ -n "$latest_version" ]]; then
        echo -e "${CYAN}最新版本:${NC} $latest_version"
        echo ""
        
        if [[ "$current_version" == "$latest_version" ]]; then
            echo -e "${GREEN}✅ 您已经是最新版本！${NC}"
            echo ""
            return
        else
            echo -e "${YELLOW}📦 发现新版本更新：${NC}"
            if [[ -n "$update_info" ]]; then
                echo "$update_info" | while read -r line; do
                    echo "  • $line"
                done
            fi
            echo ""
        fi
    else
        log_warn "无法获取版本信息，将尝试更新到最新版本"
        echo ""
    fi
    
    # 选择更新源
    echo -e "${YELLOW}请选择更新源：${NC}"
    echo "1. GitHub源（国外推荐）"
    echo "2. Gitee源（国内推荐）"
    echo "3. 取消更新"
    echo ""
    read -p "请选择 [1-3]: " source_choice
    
    local download_url=""
    case $source_choice in
        1)
            download_url="$github_url"
            echo "使用GitHub源更新..."
            ;;
        2)
            download_url="$gitee_url"
            echo "使用Gitee源更新..."
            ;;
        3)
            echo "取消更新"
            return
            ;;
        *)
            log_error "无效选择"
            return
            ;;
    esac
    
    # 备份当前脚本
    log_step "备份当前脚本..."
    local backup_file="/etc/chaojizhongzhuan/chaojizhongzhuan.sh.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$SCRIPT_DIR/chaojizhongzhuan.sh" "$backup_file" 2>/dev/null || {
        log_warn "备份失败，但继续更新..."
    }
    
    # 下载新版本
    log_step "下载最新版本..."
    local temp_file="/tmp/chaojizhongzhuan_update.sh"
    
    if curl -fsSL --connect-timeout 30 "$download_url" -o "$temp_file"; then
        log_info "下载成功"
    else
        log_error "下载失败，请检查网络连接"
        return 1
    fi
    
    # 验证下载的文件
    if [[ ! -s "$temp_file" ]]; then
        log_error "下载的文件为空"
        rm -f "$temp_file"
        return 1
    fi
    
    # 检查脚本语法
    if ! bash -n "$temp_file" 2>/dev/null; then
        log_error "下载的脚本语法错误"
        rm -f "$temp_file"
        return 1
    fi
    
    # 替换脚本文件
    log_step "安装新版本..."
    if cp "$temp_file" "$SCRIPT_DIR/chaojizhongzhuan.sh"; then
        chmod +x "$SCRIPT_DIR/chaojizhongzhuan.sh"
        rm -f "$temp_file"
        log_info "更新成功！"
        
        # 更新快捷命令
        cat > /usr/local/bin/chaojizhongzhuan << 'EOF'
#!/bin/bash
bash /etc/chaojizhongzhuan/chaojizhongzhuan.sh "$@"
EOF
        chmod +x /usr/local/bin/chaojizhongzhuan
        
        echo ""
        echo "==============================================="
        echo -e "${GREEN}🎉 更新完成！${NC}"
        echo "==============================================="
        echo ""
        echo -e "${YELLOW}更新内容：${NC}"
        if [[ -n "$update_info" ]]; then
            echo "$update_info" | while read -r line; do
                echo "  ✅ $line"
            done
        else
            echo "  ✅ 脚本已更新到最新版本"
        fi
        echo ""
        echo -e "${YELLOW}备份文件：${NC} $backup_file"
        echo -e "${YELLOW}使用方法：${NC} 直接运行 chaojizhongzhuan 即可使用新版本"
        echo ""
        
        # 询问是否立即重启脚本
        read -p "是否立即重启脚本查看新功能？[Y/n]: " restart_choice
        if [[ "$restart_choice" != "n" && "$restart_choice" != "N" ]]; then
            echo ""
            echo "正在重启脚本..."
            sleep 2
            exec bash "$SCRIPT_DIR/chaojizhongzhuan.sh"
        fi
        
    else
        log_error "安装失败"
        rm -f "$temp_file"
        return 1
    fi
}

# 落地机菜单
show_landing_menu() {
    while true; do
        clear
        echo -e "${PURPLE}"
        echo "╔══════════════════════════════════════╗"
        echo "║            落地机管理                ║"
        echo "╠══════════════════════════════════════╣"
        echo "║  1. 一键配置落地机                   ║"
        echo "║  2. 查看连接密钥                     ║"
        echo "║  3. 查看连接状态                     ║"
        echo "║  4. 一键优化系统                     ║"
        echo "║  5. 重启WireGuard                    ║"
        echo "║  6. 返回主菜单                       ║"
        echo "╚══════════════════════════════════════╝"
        echo -e "${NC}"
        
        read -p "请选择操作 [1-6]: " choice
        
        case $choice in
            1)
                install_dependencies
                get_network_interface
                get_server_ip
                optimize_system
                setup_landing_server
                read -p "按回车键继续..."
                ;;
            2)
                if [[ -f "$CONFIG_FILE" ]]; then
                    local server_public=$(jq -r '.server_public' "$CONFIG_FILE")
                    local server_ip=$(jq -r '.server_ip' "$CONFIG_FILE")
                    local port=$(jq -r '.port' "$CONFIG_FILE")
                    local client_private=$(jq -r '.client_private' "$CONFIG_FILE")
                    echo ""
                    echo -e "${YELLOW}连接密钥:${NC}"
                    echo -e "${CYAN}wg://$server_public@$server_ip:$port/$client_private${NC}"
                else
                    log_error "未找到配置文件，请先配置落地机"
                fi
                read -p "按回车键继续..."
                ;;
            3)
                show_connection_status
                read -p "按回车键继续..."
                ;;
            4)
                optimize_system
                read -p "按回车键继续..."
                ;;
            5)
                restart_services
                read -p "按回车键继续..."
                ;;
            6)
                return
                ;;
            *)
                log_error "无效选择，请重新输入"
                sleep 1
                ;;
        esac
    done
}

# 中转机菜单
show_relay_menu() {
    while true; do
        clear
        echo -e "${PURPLE}"
        echo "╔══════════════════════════════════════╗"
        echo "║            中转机管理                ║"
        echo "╠══════════════════════════════════════╣"
        echo "║  1. 添加落地机                       ║"
        echo "║  2. 查看落地机列表                   ║"
        echo "║  3. 删除落地机                       ║"
        echo "║  4. 生成3x-ui出站配置                ║"
        echo "║  5. 查看连接状态                     ║"
        echo "║  6. 一键优化系统                     ║"
        echo "║  7. 重启WireGuard                    ║"
        echo "║  9. 初始化中转机环境                 ║"
        echo "║  8. 返回主菜单                       ║"
        echo "╚══════════════════════════════════════╝"
        echo -e "${NC}"
        
        # 检查WireGuard安装状态
        if ! command -v wg-quick &> /dev/null; then
            echo -e "${YELLOW}⚠️  检测到WireGuard未安装，添加落地机时将自动安装${NC}"
            echo ""
        fi
        
        read -p "请选择操作 [1-9]: " choice
        
        case $choice in
            1)
                # 确保WireGuard已安装
                if ! command -v wg-quick &> /dev/null; then
                    log_step "检测到WireGuard未安装，正在安装..."
                    install_dependencies
                    optimize_system
                fi
                add_landing_server
                read -p "按回车键继续..."
                ;;
            2)
                list_landing_servers
                read -p "按回车键继续..."
                ;;
            3)
                remove_landing_server
                read -p "按回车键继续..."
                ;;
            4)
                generate_3xui_config
                read -p "按回车键继续..."
                ;;
            5)
                show_connection_status
                read -p "按回车键继续..."
                ;;
            6)
                optimize_system
                read -p "按回车键继续..."
                ;;
            7)
                restart_services
                read -p "按回车键继续..."
                ;;
            8)
                return
                ;;
            9)
                log_step "初始化中转机环境..."
                install_dependencies
                optimize_system
                log_info "中转机环境初始化完成"
                read -p "按回车键继续..."
                ;;
            *)
                log_error "无效选择，请重新输入"
                sleep 1
                ;;
        esac
    done
}

# 主菜单
show_main_menu() {
    while true; do
        clear
        echo -e "${BLUE}"
        echo "╔══════════════════════════════════════╗"
        echo "║          超级中转脚本 V1.2.0          ║"
        echo "║        WireGuard多落地机管理工具       ║"
        echo "╠══════════════════════════════════════╣"
        echo "║  1. 配置落地机 (WireGuard服务端)      ║"
        echo "║  2. 配置中转机 (WireGuard客户端)      ║"
        echo "║  3. 管理服务                         ║"
        echo "║  4. 紧急恢复网络                     ║"
        echo "║  5. 卸载脚本                         ║"
        echo "║  6. 更新脚本                         ║"
        echo "║  0. 退出脚本                         ║"
        echo "╚══════════════════════════════════════╝"
        echo -e "${NC}"
        
        # 显示当前状态
        if [[ -f "$CONFIG_FILE" ]]; then
            local server_type=$(jq -r '.type' "$CONFIG_FILE" 2>/dev/null || echo "unknown")
            if [[ "$server_type" == "landing_server" ]]; then
                echo -e "${GREEN}当前模式: 落地机${NC}"
            else
                echo -e "${GREEN}当前模式: 中转机${NC}"
            fi
        fi
        
        read -p "请选择操作 [0-6]: " choice
        
        case $choice in
            1)
                show_landing_menu
                ;;
            2)
                show_relay_menu
                ;;
            3)
                if [[ -f "$CONFIG_FILE" ]]; then
                    local server_type=$(jq -r '.type' "$CONFIG_FILE" 2>/dev/null || echo "unknown")
                    if [[ "$server_type" == "landing_server" ]]; then
                        show_landing_menu
                    else
                        show_relay_menu
                    fi
                else
                    log_error "未检测到配置，请先选择配置落地机或中转机"
                    sleep 2
                fi
                ;;
            4)
                emergency_network_recovery
                ;;
            5)
                uninstall_script
                exit 0
                ;;
            6)
                update_script
                read -p "按回车键继续..."
                ;;
            0)
                echo "感谢使用超级中转脚本！"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                sleep 1
                ;;
        esac
    done
}

# 紧急恢复网络
emergency_network_recovery() {
    echo ""
    echo "==============================================="
    echo -e "${RED}紧急网络恢复工具${NC}"
    echo "==============================================="
    echo ""
    echo -e "${YELLOW}此功能将执行以下操作：${NC}"
    echo "1. 停止所有WireGuard服务"
    echo "2. 删除WireGuard配置文件"
    echo "3. 清理网络路由表"
    echo "4. 重置防火墙规则"
    echo "5. 重启网络服务"
    echo ""
    echo -e "${RED}警告：此操作将删除所有WireGuard配置！${NC}"
    echo ""
    read -p "确认执行紧急恢复？(输入 YES 确认): " confirm
    
    if [[ "$confirm" != "YES" ]]; then
        echo "操作已取消"
        return
    fi
    
    log_step "执行紧急网络恢复..."
    
    # 1. 停止所有WireGuard服务
    log_step "停止WireGuard服务..."
    systemctl stop wg-quick@* 2>/dev/null || true
    systemctl disable wg-quick@* 2>/dev/null || true
    
    # 2. 删除WireGuard配置
    log_step "删除WireGuard配置..."
    rm -f /etc/wireguard/wg*.conf 2>/dev/null || true
    
    # 3. 清理网络路由
    log_step "清理网络路由..."
    # 删除WireGuard接口
    for interface in $(ip link show | grep wg- | awk -F: '{print $2}' | tr -d ' '); do
        ip link delete "$interface" 2>/dev/null || true
    done
    
    # 4. 重置防火墙规则
    log_step "重置防火墙规则..."
    if command -v firewall-cmd &> /dev/null && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --reload 2>/dev/null || true
    elif command -v ufw &> /dev/null; then
        ufw --force reset 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    else
        # 清理iptables规则（保留基本SSH规则）
        iptables -F 2>/dev/null || true
        iptables -X 2>/dev/null || true
        iptables -t nat -F 2>/dev/null || true
        iptables -t nat -X 2>/dev/null || true
        
        # 重新添加基本规则
        iptables -P INPUT ACCEPT 2>/dev/null || true
        iptables -P FORWARD ACCEPT 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
        
        # 保存规则
        if command -v save-iptables &> /dev/null; then
            save-iptables
        fi
    fi
    
    # 5. 重启网络服务
    log_step "重启网络服务..."
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        systemctl restart NetworkManager 2>/dev/null || true
    elif systemctl is-active networking >/dev/null 2>&1; then
        systemctl restart networking 2>/dev/null || true
    fi
    
    # 6. 清理脚本配置
    log_step "清理脚本配置..."
    rm -f "$CONFIG_FILE" 2>/dev/null || true
    rm -f "$SERVERS_FILE" 2>/dev/null || true
    
    echo ""
    echo "==============================================="
    echo -e "${GREEN}紧急恢复完成！${NC}"
    echo "==============================================="
    echo ""
    echo -e "${YELLOW}恢复结果：${NC}"
    echo "✅ WireGuard服务已停止"
    echo "✅ 配置文件已清理"
    echo "✅ 网络路由已重置"
    echo "✅ 防火墙规则已重置"
    echo "✅ 网络服务已重启"
    echo ""
    echo -e "${YELLOW}建议操作：${NC}"
    echo "1. 测试SSH连接是否正常"
    echo "2. 检查服务器网络连接"
    echo "3. 如需重新配置WireGuard，请重新运行脚本"
    echo ""
    read -p "按回车键继续..."
}

# 创建管理命令
create_management_command() {
    cat > /usr/local/bin/chaojizhongzhuan << 'EOF'
#!/bin/bash
bash /etc/chaojizhongzhuan/chaojizhongzhuan.sh "$@"
EOF
    chmod +x /usr/local/bin/chaojizhongzhuan
}

# 主函数
main() {
    check_root
    detect_system
    create_directories
    
    # 复制脚本到系统目录
    cp "$0" "$SCRIPT_DIR/chaojizhongzhuan.sh" 2>/dev/null || true
    create_management_command
    
    show_main_menu
}

# 执行主函数
main "$@"
