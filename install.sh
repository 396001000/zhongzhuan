#!/bin/bash

# 超级中转脚本在线安装器
# 使用方法: curl -fsSL https://raw.githubusercontent.com/用户名/仓库名/main/install.sh | bash

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置参数
SCRIPT_URL="https://raw.githubusercontent.com/396001000/zhongzhuan/main/chaojizhongzhuan.sh"
SCRIPT_NAME="chaojizhongzhuan.sh"
INSTALL_DIR="/etc/chaojizhongzhuan"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
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
        log_error "请使用root权限运行此安装脚本"
        echo "请使用: sudo bash <(curl -fsSL https://raw.githubusercontent.com/396001000/zhongzhuan/main/install.sh)"
        exit 1
    fi
}

# 检测系统
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        log_info "检测到系统: $OS"
    else
        log_error "无法检测操作系统类型"
        exit 1
    fi
}

# 安装基础依赖
install_basic_deps() {
    log_step "安装基础依赖..."
    
    if [[ $OS =~ "Ubuntu" ]] || [[ $OS =~ "Debian" ]]; then
        apt update -y >/dev/null 2>&1
        apt install -y curl wget jq >/dev/null 2>&1
    elif [[ $OS =~ "CentOS" ]] || [[ $OS =~ "Red Hat" ]]; then
        yum update -y >/dev/null 2>&1
        yum install -y curl wget jq >/dev/null 2>&1
    fi
    
    log_info "基础依赖安装完成"
}

# 下载脚本
download_script() {
    log_step "下载超级中转脚本..."
    
    # 创建目录
    mkdir -p "$INSTALL_DIR"
    
    # 下载主脚本
    if curl -fsSL "$SCRIPT_URL" -o "$INSTALL_DIR/$SCRIPT_NAME"; then
        chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
        log_info "脚本下载成功"
    else
        log_error "脚本下载失败，请检查网络连接"
        exit 1
    fi
}

# 创建快捷命令
create_shortcut() {
    log_step "创建快捷命令..."
    
    cat > /usr/local/bin/chaojizhongzhuan << EOF
#!/bin/bash
bash $INSTALL_DIR/$SCRIPT_NAME "\$@"
EOF
    
    chmod +x /usr/local/bin/chaojizhongzhuan
    log_info "快捷命令创建成功"
}

# 显示安装完成信息
show_completion() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════╗"
    echo "║        超级中转脚本安装完成！          ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${YELLOW}使用方法:${NC}"
    echo "  chaojizhongzhuan    # 启动脚本"
    echo ""
    echo -e "${YELLOW}功能特点:${NC}"
    echo "  ✅ WireGuard多落地机管理"
    echo "  ✅ 一键配置落地机和中转机"
    echo "  ✅ 自动生成3x-ui出站配置"
    echo "  ✅ 系统网络优化"
    echo "  ✅ 可视化管理界面"
    echo ""
    echo -e "${BLUE}现在就开始使用吧！${NC}"
    echo ""
}

# 主函数
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════╗"
    echo "║      超级中转脚本在线安装器            ║"
    echo "║    WireGuard多落地机管理工具          ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    check_root
    detect_system
    install_basic_deps
    download_script
    create_shortcut
    show_completion
    
    # 询问是否立即运行
    read -p "是否立即运行脚本? (Y/n): " run_now
    if [[ "$run_now" != "n" && "$run_now" != "N" ]]; then
        bash "$INSTALL_DIR/$SCRIPT_NAME"
    fi
}

main "$@"
