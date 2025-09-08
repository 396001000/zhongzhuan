# 🚀 超级中转脚本 - WireGuard多落地机管理工具

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/396001000/zhongzhuan/releases)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](README.md)

一个强大的WireGuard多落地机管理工具，支持一键配置落地机和中转机，自动生成3x-ui出站配置，让您轻松搭建高性能的代理网络。

## ✨ 主要特性

- 🎯 **一键部署**：自动化配置WireGuard服务端和客户端
- 🌐 **多落地机支持**：轻松管理多个落地服务器
- ⚡ **高性能**：基于WireGuard内核级处理，延时低至8ms
- 🔧 **3x-ui集成**：自动生成完整的出站配置代码
- 🛡️ **系统优化**：内置BBR拥塞控制和网络参数优化
- 📊 **可视化管理**：友好的交互式菜单界面
- 🔄 **智能分流**：支持国内直连，国外代理
- 📱 **小白友好**：无需复杂配置，跟着提示操作即可

## 🎬 快速开始

### 📍 镜像源选择

| 镜像源 | 适用地区 | 速度 | 稳定性 |
|--------|----------|------|--------|
| **GitHub** | 海外用户 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Gitee** | 中国大陆 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

### 一键安装

```bash
# 方法1：GitHub源（国外推荐）
curl -fsSL https://raw.githubusercontent.com/396001000/zhongzhuan/main/install.sh | bash

# 方法2：Gitee源（国内推荐）
curl -fsSL https://gitee.com/dlaasd/zhongzhuan/raw/master/install.sh | bash

# 方法3：使用wget（GitHub）
wget -qO- https://raw.githubusercontent.com/396001000/zhongzhuan/main/install.sh | bash

# 方法4：使用wget（Gitee）
wget -qO- https://gitee.com/dlaasd/zhongzhuan/raw/master/install.sh | bash
```

### 启动脚本

```bash
chaojizhongzhuan
```

## 📋 系统要求

### 支持的操作系统

| 系统类型 | 支持版本 | 包管理器 | 防火墙 | 测试状态 |
|----------|----------|----------|--------|----------|
| **Ubuntu** | 18.04+ | apt | ufw/iptables | ✅ 完全支持 |
| **Debian** | 10+ | apt | ufw/iptables | ✅ 完全支持 |
| **CentOS** | 7/8 | yum/dnf | firewalld/iptables | ✅ 完全支持 |
| **RHEL** | 8/9 | yum/dnf | firewalld/iptables | ✅ 完全支持 |
| **Fedora** | 35+ | dnf | firewalld/iptables | ✅ 完全支持 |
| **Arch Linux** | Rolling | pacman | iptables | ✅ 完全支持 |
| **Manjaro** | 21+ | pacman | iptables | ✅ 完全支持 |
| **openSUSE** | Leap 15+/Tumbleweed | zypper | iptables | ✅ 完全支持 |
| **Alpine Linux** | 3.15+ | apk | iptables | ✅ 完全支持 |
| **Gentoo** | Rolling | emerge | iptables | 🧪 实验支持 |
| **Void Linux** | Rolling | xbps | iptables | 🧪 实验支持 |

### 系统要求

- **架构**：x86_64、ARM64、ARMv7
- **权限**：Root权限
- **网络**：可访问外网
- **内核**：支持WireGuard (内核5.6+或模块)

### 系统兼容性说明

#### **完全支持** ✅
- 经过充分测试，所有功能正常工作
- 自动检测包管理器和防火墙
- 完整的依赖安装和配置

#### **实验支持** 🧪  
- 基本功能可用，但测试覆盖有限
- 可能需要手动处理某些依赖
- 欢迎反馈使用情况

#### **智能适配特性**
- 🔍 **自动系统检测**：识别发行版和版本
- 📦 **包管理器适配**：apt/yum/dnf/pacman/zypper/apk/emerge/xbps
- 🛡️ **防火墙智能选择**：firewalld/ufw/iptables
- 🔧 **依赖自动处理**：解决不同系统的包依赖冲突

## 🔧 使用教程

### 1. 配置落地机（服务端）

```bash
# 运行脚本
chaojizhongzhuan

# 选择：1. 配置落地机
# 选择：1. 一键配置落地机
# 等待配置完成，复制生成的连接密钥
```

**输出示例：**
```
🎉 落地机配置完成！
📋 连接密钥：wg://AbCdEf123...@1.2.3.4:51820/XyZaBc456...
```

### 2. 配置中转机（客户端）

```bash
# 运行脚本
chaojizhongzhuan

# 选择：2. 配置中转机
# 选择：1. 添加落地机
# 输入落地机名称和连接密钥
# 选择：4. 生成3x-ui出站配置
```

### 3. 3x-ui配置

将生成的配置代码导入到3x-ui面板：
1. 登录3x-ui管理面板
2. 出站设置 → 批量添加
3. 粘贴配置内容并保存
4. 重启3x-ui服务

### 4. 客户端设置

**重要：** 请将客户端设置为 **规则模式** 或 **绕过大陆**：

- **V2rayN**：路由设置 → 绕过大陆
- **Clash**：模式选择 → Rule
- **Shadowrocket**：配置 → 规则

## 📊 性能对比

| 方案 | 延时增加 | 吞吐量 | CPU占用 | 稳定性 |
|------|---------|--------|---------|--------|
| 纯3x-ui中转 | +30-80ms | 200-500 Mbps | 15-30% | 一般 |
| **WireGuard+3x-ui** | **+8ms** | **1.98 Gbps** | **3-8%** | **优秀** |

## 🎛️ 功能菜单

### 落地机管理
```
╔══════════════════════════════════════╗
║            落地机管理                ║
╠══════════════════════════════════════╣
║  1. 一键配置落地机                   ║
║  2. 查看连接密钥                     ║
║  3. 查看连接状态                     ║
║  4. 一键优化系统                     ║
║  5. 重启WireGuard                    ║
║  6. 返回主菜单                       ║
╚══════════════════════════════════════╝
```

### 中转机管理
```
╔══════════════════════════════════════╗
║            中转机管理                ║
╠══════════════════════════════════════╣
║  1. 添加落地机                       ║
║  2. 查看落地机列表                   ║
║  3. 删除落地机                       ║
║  4. 生成3x-ui出站配置                ║
║  5. 查看连接状态                     ║
║  6. 一键优化系统                     ║
║  7. 重启WireGuard                    ║
║  8. 返回主菜单                       ║
╚══════════════════════════════════════╝
```

## 🌟 高级功能

### 多落地机管理

支持添加无限个落地机，每个落地机独立配置：

```bash
# 添加多个落地机示例
落地机1：美西高速服务器 (1.2.3.4:51820)
落地机2：美东备用服务器 (5.6.7.8:51821)  
落地机3：日本优化服务器 (9.10.11.12:51822)
```

### 自动生成配置

脚本会自动生成完整的3x-ui出站配置：

```json
{
  "outbounds": [
    {
      "tag": "wg-美西高速服务器",
      "protocol": "wireguard",
      "settings": {
        "secretKey": "客户端私钥",
        "address": ["10.0.1.2/24"],
        "peers": [...]
      }
    }
  ]
}
```

### 系统优化

自动应用以下优化：
- ✅ BBR拥塞控制算法
- ✅ TCP/UDP缓冲区优化  
- ✅ 网络连接参数调优
- ✅ 内核网络栈优化

## 🔍 常见问题

<details>
<summary><strong>Q: 安装失败怎么办？</strong></summary>

**A:** 请检查以下几点：
1. 确保使用root权限运行
2. 检查网络连接是否正常
3. 确认系统版本是否支持
4. 查看错误日志并反馈

</details>

<details>
<summary><strong>Q: 连接测试失败？</strong></summary>

**A:** 可能的原因：
1. 防火墙阻挡了WireGuard端口
2. 服务商禁用了UDP协议
3. 密钥配置错误
4. 网络路由问题

解决方法：
```bash
# 检查防火墙状态
ufw status
# 检查WireGuard状态  
systemctl status wg-quick@wg0
# 查看连接日志
journalctl -u wg-quick@wg0 -f
```

</details>

<details>
<summary><strong>Q: 如何切换不同的落地机？</strong></summary>

**A:** 有两种方式：
1. **客户端切换**：在V2rayN、Clash等客户端中手动选择不同的出站
2. **脚本管理**：使用脚本菜单删除/添加落地机

</details>

<details>
<summary><strong>Q: 国内网站访问很慢？</strong></summary>

**A:** 请确保客户端设置正确：
- V2rayN：选择"绕过大陆"
- Clash：设置mode为"rule"  
- 其他客户端：启用"规则模式"或"PAC模式"

</details>

## 🛠️ 手动安装

如果一键安装失败，可以手动安装：

```bash
# 1. 下载脚本（GitHub）
wget https://raw.githubusercontent.com/396001000/zhongzhuan/main/chaojizhongzhuan.sh

# 或从Gitee下载（国内用户）
wget https://gitee.com/dlaasd/zhongzhuan/raw/master/chaojizhongzhuan.sh

# 2. 添加执行权限
chmod +x chaojizhongzhuan.sh

# 3. 运行脚本
./chaojizhongzhuan.sh

# 4. 创建快捷命令（可选）
cp chaojizhongzhuan.sh /usr/local/bin/chaojizhongzhuan
```

## 🔄 更新脚本

```bash
# 方法1：脚本内更新（开发中）
chaojizhongzhuan
# 选择：5. 更新脚本

# 方法2：重新安装（GitHub）
curl -fsSL https://raw.githubusercontent.com/396001000/zhongzhuan/main/install.sh | bash

# 方法3：重新安装（Gitee，国内用户推荐）
curl -fsSL https://gitee.com/dlaasd/zhongzhuan/raw/master/install.sh | bash
```

## 🗑️ 卸载脚本

```bash
chaojizhongzhuan
# 选择：4. 卸载脚本

# 或手动卸载
rm -rf /etc/chaojizhongzhuan
rm -f /usr/local/bin/chaojizhongzhuan
systemctl stop wg-quick@*
systemctl disable wg-quick@*
```

## 📈 版本历史

### v1.1.0 (2025-01-09)
- 🌍 **扩展系统支持**：新增支持Fedora、Arch Linux、Manjaro、openSUSE、Alpine、Gentoo、Void Linux
- 🔧 **智能包管理器适配**：自动识别并使用apt/yum/dnf/pacman/zypper/apk/emerge/xbps
- 🛡️ **多防火墙支持**：智能选择firewalld/ufw/iptables，适配不同系统
- 🔍 **系统检测增强**：更准确的发行版和版本识别
- 📦 **依赖冲突解决**：修复Ubuntu 24.04的iptables-persistent冲突问题

### v1.0.0 (2025-01-09)
- ✅ 支持WireGuard多落地机管理
- ✅ 自动生成3x-ui出站配置  
- ✅ 系统网络优化
- ✅ 可视化管理界面
- ✅ 一键安装部署

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 📄 许可证

本项目采用MIT许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## ⭐ Star History

如果这个项目对您有帮助，请给我们一个Star！

[![Star History Chart](https://api.star-history.com/svg?repos=396001000/zhongzhuan&type=Date)](https://star-history.com/#396001000/zhongzhuan&Date)

## 🔗 项目链接

- 🌐 **GitHub主仓库**: https://github.com/396001000/zhongzhuan
- 🌐 **Gitee镜像仓库**: https://gitee.com/dlaasd/zhongzhuan
- 📖 **在线文档**: [GitHub Pages](https://396001000.github.io/zhongzhuan)

## 📞 联系我们

- 📧 邮箱：your-email@example.com
- 💬 Telegram：@your_telegram
- 🐛 问题反馈：[GitHub Issues](https://github.com/396001000/zhongzhuan/issues) | [Gitee Issues](https://gitee.com/dlaasd/zhongzhuan/issues)

---

<p align="center">
  <strong>🎉 感谢使用超级中转脚本！</strong><br>
  如果觉得有用，请给我们一个 ⭐ Star
</p>
