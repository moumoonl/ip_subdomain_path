#!/bin/bash
# 项目初始化脚本 - 检查工具和环境

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "IP 子域名扫描工具 - 环境检查"
echo "端口扫描: 两阶段 (top-1000 + 全端口，需 --allport)"
echo "=========================================="

# 检查 Go 环境
echo -e "\n[1/5] 检查 Go 环境..."
if command -v go &>/dev/null; then
    echo "  ✓ $(go version)"
else
    echo "  ✗ Go 未安装"
    echo "  安装方法: https://golang.org/dl/"
    exit 1
fi

# 检查 Python
echo -e "\n[2/5] 检查 Python..."
if command -v python3 &>/dev/null; then
    echo "  ✓ $(python3 --version)"
else
    echo "  ✗ Python3 未安装"
    exit 1
fi

# 检查各扫描工具
echo -e "\n[3/5] 检查扫描工具..."
ALL_OK=true
NEED_PATH_FIX=false

declare -A INSTALL_CMDS
INSTALL_CMDS[ksubdomain]="go install -v github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest"
INSTALL_CMDS[naabu]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
INSTALL_CMDS[httpx]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
INSTALL_CMDS[ffuf]="go install -v github.com/ffuf/ffuf/v2@latest"

for tool in ksubdomain naabu httpx ffuf; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool 已安装"
    else
        # 检查是否装在 ~/go/bin 但未加入 PATH
        if [ -f "$HOME/go/bin/$tool" ]; then
            echo "  ⚠ $tool 已安装但不在 PATH 中（位于 $HOME/go/bin/$tool）"
            NEED_PATH_FIX=true
            ALL_OK=false
        else
            echo "  ✗ $tool 未安装"
            echo "      安装命令："
            echo "        ${INSTALL_CMDS[$tool]}"
            ALL_OK=false
        fi
    fi
done

# 如果有工具在 ~/go/bin 但不在 PATH，统一给出 PATH 修复方案
if $NEED_PATH_FIX; then
    echo ""
    echo "  ── PATH 修复（复制以下命令执行）──────────────────────────"
    echo "  echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc"
    echo ""
    echo "  如果使用 zsh："
    echo "  echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc"
    echo "  ──────────────────────────────────────────────────────────"
fi

# 检查字典文件（项目目录下的 dict/）
echo -e "\n[4/5] 检查字典文件..."
DICT_DIR="$SCRIPT_DIR/dict"
DICT_FILES=(
    "oneforall_subnames.txt"
    "gov-edu-med-paths-clean.txt"
    "gov-edu-med-keywords-clean.txt"
    "gov-edu-med-dict-clean.txt"
    "resolvers.txt"
)

for dict in "${DICT_FILES[@]}"; do
    fpath="$DICT_DIR/$dict"
    if [ -f "$fpath" ]; then
        lines=$(wc -l < "$fpath")
        echo "  ✓ dict/$dict ($lines 行)"
    else
        echo "  ✗ dict/$dict 不存在"
        ALL_OK=false
    fi
done

# 创建输出目录
echo -e "\n[5/5] 创建输出目录..."
mkdir -p "$SCRIPT_DIR/results"
echo "  ✓ results/ 目录已就绪"

# 检查 ksubdomain 网卡缓存是否过期
YAML_FILE="$SCRIPT_DIR/ksubdomain.yaml"
if [ -f "$YAML_FILE" ]; then
    YAML_IP=$(grep "^src_ip:" "$YAML_FILE" 2>/dev/null | awk '{print $2}')
    CURRENT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$YAML_IP" ] && [ -n "$CURRENT_IP" ] && [ "$YAML_IP" != "$CURRENT_IP" ]; then
        echo "  ⚠ ksubdomain.yaml 网卡缓存过期（缓存 IP: $YAML_IP，当前 IP: $CURRENT_IP）"
        echo "    建议删除: rm $YAML_FILE（ksubdomain 会自动重新探测）"
        ALL_OK=false
    else
        echo "  ✓ ksubdomain.yaml 网卡缓存有效"
    fi
fi

# 运行项目测试
echo -e "\n[测试] 检查 Python 模块导入..."
cd "$SCRIPT_DIR" && python3 -c "
from utils import Colors, run_command, format_time_remaining
from module1_subdomain_collect import parse_ksubdomain_output, run_ksubdomain, verify_subdomains_dns, collect_subdomains_multipass
import socket, threading, concurrent.futures
print('  OK: module1 多轮扫描 + DNS 验证依赖正常')
"

echo -e "\n=========================================="
if $ALL_OK; then
    echo "✓ 环境检查完成，所有工具就绪"
    echo "=========================================="
    echo -e "\n快速开始:"
    echo "  # 仅端口扫描+目录爆破（已有 IP 列表）"
    echo "  python3 full_pipeline.py --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt --skip-module1"
    echo ""
    echo "  # 完整流程（子域名收集 + 两阶段端口扫描 + 目录爆破）"
    echo "  python3 full_pipeline.py --domains domains.txt --ips ips.txt --wordlist dict/gov-edu-med-paths-clean.txt"
    echo -e "\n查看文档:"
    echo "  cat README.md"
else
    echo "⚠ 部分工具未就绪，请根据上方提示处理后重新运行 ./setup.sh"
    echo "=========================================="
fi
