"""
模块2：端口扫描与服务识别
输入：
  1. subdomains_valid.txt (去重后验证有效的子域名列表)
  2. ips.txt (IP 列表)
注：子域名排在 IP 前面，naabu 先扫描子域名；仅输入一种类型时跳过 DNS 去重。
输出：
  1. all_ports.txt (两阶段合并后的开放端口，host:port 格式)
  2. http_services.txt (HTTP/HTTPS 服务列表，含 title/status/tech)
  3. non_http_services.txt (非 HTTP 服务列表，含推断的服务名)
扫描策略：
  Stage 1 — top-1000 快速探活 (rate 2000, retries 2)
  Stage 2 — 存活主机全端口精扫 (rate 5000, -stream 模式，需 --allport 启用，默认跳过)
  两阶段结果合并去重写入 all_ports.txt
工具：naabu, httpx
"""
import argparse
import socket
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlparse
from utils import run_command, print_info, print_success, print_warning, print_high_risk


def format_timeout_str(seconds: int) -> str:
    """将秒数格式化为可读字符串"""
    if seconds < 60:
        return f"{seconds}秒"
    elif seconds < 3600:
        return f"{seconds // 60}分{seconds % 60}秒"
    else:
        return f"{seconds // 3600}小时{(seconds % 3600) // 60}分"


def merge_targets(ips_file: Path, subdomains_file: Path, output_file: Path):
    """
    合并 IP 和子域名列表，DNS 去重：域名解析后若 IP 已在列表中则丢弃域名。
    子域名排在 IP 前面，使 naabu 先扫描子域名。
    当只有一种输入（仅 IP 或仅子域名）时，跳过 DNS 去重。

    Returns:
        合并后的目标数量
    """
    ip_set = set()

    if ips_file and ips_file.exists():
        with open(ips_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ip_set.add(line)
        print_info(f"读取 {len(ip_set)} 个 IP")

    # 域名列表：先收集，再按需做 DNS 去重
    domain_list = []
    if subdomains_file and subdomains_file.exists():
        with open(subdomains_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domain_list.append(line)
        print_info(f"读取 {len(domain_list)} 个子域名")

    has_ips = len(ip_set) > 0
    has_domains = len(domain_list) > 0

    if has_ips and has_domains:
        # 两种输入都有，执行 DNS 去重
        kept_domains = []
        dropped_count = 0
        for domain in domain_list:
            try:
                resolved_ip = socket.gethostbyname(domain)
                if resolved_ip in ip_set:
                    dropped_count += 1
                else:
                    kept_domains.append(domain)
            except socket.gaierror:
                kept_domains.append(domain)

        if dropped_count:
            print_info(f"DNS 去重：丢弃 {dropped_count} 个域名（解析 IP 已在 IP 列表中）")
    else:
        # 只有一种输入，跳过 DNS 去重
        kept_domains = domain_list
        if has_domains and not has_ips:
            print_info("仅输入子域名，跳过 DNS 去重")
        elif has_ips and not has_domains:
            print_info("仅输入 IP，跳过 DNS 去重")

    # 子域名在前，IP 在后
    targets = sorted(kept_domains) + sorted(ip_set)

    if targets:
        output_file.write_text('\n'.join(targets), encoding="utf-8")
        return len(targets)
    else:
        output_file.write_text('', encoding="utf-8")
        return 0


def extract_alive_hosts(port_file: Path) -> list:
    """从 host:port 格式结果中提取去重后的 host 列表（用于 Stage 2 输入）"""
    hosts = set()
    if port_file.exists() and port_file.stat().st_size > 0:
        with open(port_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    hosts.add(line.rsplit(":", 1)[0])
    return sorted(hosts)


def merge_port_files(stage1_file: Path, stage2_file: Path, output_file: Path) -> int:
    """合并 Stage 1 (top-1000) 和 Stage 2 (全端口) 的扫描结果，去重写入 output_file"""
    all_ports = set()

    for f in [stage1_file, stage2_file]:
        if f.exists() and f.stat().st_size > 0:
            with open(f, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        all_ports.add(line)

    if all_ports:
        output_file.write_text('\n'.join(sorted(all_ports)), encoding="utf-8")
        return len(all_ports)
    else:
        output_file.write_text('', encoding="utf-8")
        return 0


def run_naabu(cmd: list, timeout: int, output_file: Path, show_progress: bool = True):
    """
    运行 naabu 扫描命令，使用 Popen 控制 terminate 顺序：
    超时先发 SIGTERM（让 naabu flush 输出文件），等待 10 秒后再 SIGKILL。

    Returns:
        True if naabu exited normally, False if timed out
    """
    stop_monitor = threading.Event()

    if show_progress and output_file:
        from utils import format_time_remaining
        monitor_thread = threading.Thread(
            target=_monitor_naabu_output,
            args=(output_file, stop_monitor),
            daemon=True
        )
        monitor_thread.start()

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # 先 SIGTERM，让 naabu 优雅退出并 flush 输出文件
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        timed_out = True

    stop_monitor.set()
    if show_progress and output_file:
        monitor_thread.join(timeout=1)
        print()  # 换行

    if timed_out:
        print_warning(f"naabu 扫描超时（已发送 SIGTERM，结果已尽力保存）")

    return not timed_out


def _monitor_naabu_output(output_file: Path, stop_event: threading.Event):
    """监控 naabu 输出文件的实时变化"""
    from utils import format_time_remaining
    start_time = time.time()
    last_count = 0

    while not stop_event.is_set():
        try:
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    current_count = sum(1 for _ in f)
                if current_count > last_count:
                    elapsed = time.time() - start_time
                    elapsed_str = format_time_remaining(elapsed)
                    print(f"\r  ⏱️  运行时间: {elapsed_str} | 已发现: {current_count} 个端口", end='', flush=True)
                    last_count = current_count
            else:
                elapsed = time.time() - start_time
                elapsed_str = format_time_remaining(elapsed)
                print(f"\r  ⏱️  运行时间: {elapsed_str} | 等待结果...", end='', flush=True)
        except Exception:
            pass
        time.sleep(5)


def scan_ports_batch(targets_file: Path, output_file: Path, allport: bool = False):
    """
    两阶段端口扫描（naabu CONNECT scan）：
      Stage 1: top-1000 快速探活 — 发现存活主机和常见端口
               超时公式: max(300, min(目标数×90, 7200)) 秒
      Stage 2: 存活主机全端口 1-65535 (-stream 模式) — 发现非标准端口
               需 allport=True 启用，默认跳过
               超时公式: max(600, min(存活主机数×600, 86400)) 秒
      两阶段结果合并去重写入 output_file（若跳过 Stage 2 则直接使用 Stage 1 结果）。
    超时处理：通过 SIGTERM 优雅终止 naabu，flush 输出文件后再 SIGKILL。

    Returns:
        发现的端口总数
    """
    try:
        with open(targets_file) as f:
            target_count = sum(1 for line in f if line.strip())
    except Exception:
        target_count = 1000

    output_dir = output_file.parent

    # ── Stage 1: top-1000 快速探活（每目标约90秒，最少5分钟，最多2小时）──
    stage1_file = output_dir / "all_ports_stage1.txt"
    stage1_timeout = max(300, min(target_count * 90, 7200))
    stage1_timeout_str = format_timeout_str(stage1_timeout)

    print_info(f"Stage 1: top-1000 探活（目标 {target_count} 个，超时 {stage1_timeout_str}）...")

    run_naabu([
        "naabu",
        "-l", str(targets_file),
        "-top-ports", "1000",
        "-rate", "2000",
        "-retries", "2",
        "-timeout", "1500",
        "-o", str(stage1_file)
    ], timeout=stage1_timeout, output_file=stage1_file)

    # 从 Stage 1 结果中提取存活主机，作为 Stage 2 的输入
    alive_hosts = extract_alive_hosts(stage1_file)

    stage1_ports = set()
    if stage1_file.exists() and stage1_file.stat().st_size > 0:
        with open(stage1_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    stage1_ports.add(line)

    if stage1_ports:
        print_success(f"Stage 1: 发现 {len(stage1_ports)} 个开放端口（{len(alive_hosts)} 个存活主机）")
    else:
        print_warning("Stage 1: 未发现开放端口")

    # ── Stage 2: 存活主机全端口精扫（可选，需 --allport 启用）──
    if not allport:
        print_info("未启用 --allport，跳过 Stage 2 全端口扫描")
        # 直接将 Stage 1 结果作为最终输出
        if stage1_ports:
            output_file.write_text('\n'.join(sorted(stage1_ports)), encoding="utf-8")
            print_success(f"发现 {len(stage1_ports)} 个开放端口")
        else:
            print_warning("未发现开放端口")
            output_file.write_text('', encoding="utf-8")
        return len(stage1_ports)

    if not alive_hosts:
        print_warning("无存活主机，跳过 Stage 2 全端口扫描")
        total = merge_port_files(stage1_file, output_dir / "all_ports_stage2.txt", output_file)
        if total:
            print_success(f"发现 {total} 个开放端口")
        else:
            print_warning("未发现开放端口")
            output_file.write_text('', encoding="utf-8")
        return total

    alive_file = output_dir / "alive_hosts.txt"
    alive_file.write_text('\n'.join(alive_hosts), encoding="utf-8")

    stage2_file = output_dir / "all_ports_stage2.txt"
    alive_count = len(alive_hosts)
    stage2_timeout = max(600, min(alive_count * 600, 86400))
    stage2_timeout_str = format_timeout_str(stage2_timeout)

    print_info(f"Stage 2: 全端口扫描 -stream 模式（{alive_count} 个存活主机，超时 {stage2_timeout_str}）...")

    run_naabu([
        "naabu",
        "-l", str(alive_file),
        "-p", "1-65535",
        "-rate", "5000",
        "-timeout", "1500",
        "-stream",
        "-o", str(stage2_file)
    ], timeout=stage2_timeout, output_file=stage2_file)

    # ── 合并两阶段结果 ─────────────────────────────────────────────
    total = merge_port_files(stage1_file, stage2_file, output_file)

    if total:
        print_success(f"两阶段合并：发现 {total} 个开放端口")
    else:
        print_warning("未发现开放端口")
        output_file.write_text('', encoding="utf-8")

    return total


def detect_http_services(ports_file: Path, http_output: Path):
    """
    使用 httpx 探测 HTTP/HTTPS 服务，获取 title、status-code、tech 信息

    Args:
        ports_file: naabu 输出的端口文件（host:port 格式）
        http_output: HTTP 服务输出文件

    Returns:
        HTTP URL 列表
    """
    # 动态计算 httpx 超时：每端口约1秒，最少5分钟，最多2小时
    try:
        with open(ports_file) as f:
            port_count = sum(1 for line in f if line.strip())
    except Exception:
        port_count = 100
    httpx_timeout = max(300, min(port_count, 7200))
    httpx_timeout_str = format_timeout_str(httpx_timeout)

    print_info(f"探测 HTTP/HTTPS 服务（{port_count} 个端口，超时 {httpx_timeout_str}）...")

    run_command([
        "httpx",
        "-l", str(ports_file),
        "-silent",
        "-timeout", "10",
        "-threads", "100",
        "-title",
        "-status-code",
        "-tech-detect",
        "-o", str(http_output)
    ], timeout=httpx_timeout, output_file=http_output, show_progress=True)

    http_urls = []

    if http_output.exists() and http_output.stat().st_size > 0:
        with open(http_output, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        for line in lines:
            url = line.split()[0] if line.split() else ""
            if url.startswith(("http://", "https://")):
                http_urls.append(url)

        if http_urls:
            print_success(f"发现 {len(http_urls)} 个存活 HTTP/HTTPS 服务")

            # 高价值目标识别
            high_value_keywords = [
                "login", "admin", "dashboard", "panel", "console", "管理",
                "后台", "登录", "phpmyadmin", "jenkins", "gitlab", "grafana",
                "kibana", "portainer", "weblogic", "tomcat", "jboss"
            ]

            high_value_targets = []
            for line in lines:
                line_lower = line.lower()
                for keyword in high_value_keywords:
                    if keyword in line_lower:
                        high_value_targets.append(line)
                        break

            if high_value_targets:
                print_high_risk(f"发现 {len(high_value_targets)} 个高价值目标")
                print("\n高价值目标列表:")
                for target in high_value_targets[:10]:
                    print(f"  {target}")
                if len(high_value_targets) > 10:
                    print(f"  ... 还有 {len(high_value_targets) - 10} 个")
                print()
    else:
        print_warning("未发现 HTTP/HTTPS 服务")

    return http_urls


def extract_non_http_services(ports_file: Path, http_urls: list, output_file: Path):
    """
    从 all_ports.txt 中提取非 HTTP 服务，根据常见端口推断服务名
    """
    if not ports_file.exists():
        return

    http_endpoints = set()
    for url in http_urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port
            # httpx 对默认端口省略端口号，naabu 总是带端口，需要补齐才能对比
            if port is None:
                if parsed.scheme == 'https':
                    port = 443
                elif parsed.scheme == 'http':
                    port = 80
            if hostname and port:
                http_endpoints.add(f"{hostname}:{port}")
        except Exception:
            continue

    all_endpoints = []
    with open(ports_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                all_endpoints.append(line)

    non_http_endpoints = [ep for ep in all_endpoints if ep not in http_endpoints]

    common_services = {
        "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp",
        "53": "dns", "110": "pop3", "143": "imap", "389": "ldap",
        "445": "smb", "1433": "mssql", "3306": "mysql", "3389": "rdp",
        "5432": "postgresql", "5900": "vnc", "6379": "redis",
        "9200": "elasticsearch", "27017": "mongodb"
    }

    lines = []
    for endpoint in non_http_endpoints:
        try:
            port = endpoint.split(':')[-1]
            service_name = common_services.get(port, "unknown")
            lines.append(f"{endpoint} {service_name}")
        except Exception:
            lines.append(f"{endpoint} unknown")

    if lines:
        output_file.write_text('\n'.join(lines), encoding="utf-8")
        print_success(f"非 HTTP 服务已保存: {output_file}")
        print_info(f"发现 {len(lines)} 个非 HTTP 服务")
    else:
        print_info("所有服务均为 HTTP/HTTPS")
        output_file.write_text('', encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="模块2：端口扫描与服务识别",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例：
  python module2_port_scan_and_httpx.py --ips ips.txt --subdomains subdomains_valid.txt --output-dir results
  python module2_port_scan_and_httpx.py --ips ips.txt --output-dir results --force

输入文件格式：
  ips.txt: 每行一个 IP
  subdomains_valid.txt: 每行一个子域名

输出文件：
  - all_ports_stage1.txt   Stage 1 top-1000 探活结果（host:port）
  - all_ports_stage2.txt   Stage 2 全端口精扫结果（host:port，需 --allport）
  - alive_hosts.txt        Stage 1 发现的存活主机列表
  - all_ports.txt          合并去重结果（host:port）
  - http_services.txt      HTTP/HTTPS 服务列表（含 title、status、tech）
  - non_http_services.txt  非 HTTP 服务列表（含推断服务名）
        """
    )
    parser.add_argument("--ips", help="IP 列表文件", required=False)
    parser.add_argument("--subdomains", help="子域名列表文件", required=False)
    parser.add_argument("--output-dir", default="results", help="输出目录")
    parser.add_argument("--allport", action="store_true", help="启用 Stage 2 全端口扫描（默认跳过，仅 Stage 1 top-1000）")
    parser.add_argument("--force", action="store_true", help="强制重跑所有阶段，忽略已有结果")

    args = parser.parse_args()

    if not args.ips and not args.subdomains:
        parser.error("必须提供 --ips 或 --subdomains 其中一个参数！")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    print(f"\n{'='*60}")
    print(f"输出目录: {output_dir}")
    print(f"{'='*60}\n")

    ips_file = Path(args.ips) if args.ips else None
    subdomains_file = Path(args.subdomains) if args.subdomains else None
    targets_file = output_dir / "targets_merged.txt"
    ports_file = output_dir / "all_ports.txt"
    http_output = output_dir / "http_services.txt"
    non_http_output = output_dir / "non_http_services.txt"

    # Step 1: 合并目标
    targets_count = merge_targets(ips_file, subdomains_file, targets_file)
    if targets_count == 0:
        print_warning("没有有效的目标")
        return
    print_success(f"合并目标: {targets_count} 个")

    # Step 2: 两阶段端口扫描（断点续扫）
    if not args.force and ports_file.exists() and ports_file.stat().st_size > 0:
        print_info(f"发现已有结果文件 {ports_file.name}，跳过端口扫描（使用 --force 强制重跑）")
        ports_count = len(ports_file.read_text(encoding="utf-8").strip().splitlines())
        print_info(f"已有 {ports_count} 个开放端口记录")
    else:
        ports_count = scan_ports_batch(targets_file, ports_file, allport=args.allport)
        if ports_count == 0:
            print_warning("未发现开放端口")
            return

    # Step 3: HTTP 服务探测（断点续扫）
    if not args.force and http_output.exists() and http_output.stat().st_size > 0:
        print_info(f"发现已有结果文件 {http_output.name}，跳过 HTTP 探测（使用 --force 强制重跑）")
        with open(http_output, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        http_urls = [l.split()[0] for l in lines if l.split() and l.split()[0].startswith(("http://", "https://"))]
        print_info(f"已有 {len(http_urls)} 个 HTTP 服务记录")
    else:
        http_urls = detect_http_services(ports_file, http_output)

    # Step 4: 提取非 HTTP 服务
    extract_non_http_services(ports_file, http_urls, non_http_output)

    print(f"\n{'='*60}")
    print_success("扫描完成！")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
