"""
模块1：子域名收集（多轮扫描优化版）
输入：主域名列表文件 (domains.txt)
输出：去重后的子域名列表 (subdomains_valid.txt)
工具：ksubdomain

一致性优化（解决每次扫描结果不同的问题）：
  1. 多轮扫描：默认 3 轮 ksubdomain enum，每轮独立运行，结果取并集。
     UDP DNS 查询天然丢包，每轮遗漏不同子域名，多轮合并显著提升覆盖率。
  2. 自定义 DNS 解析器：dict/resolvers.txt 包含 7 个国内 + 7 个国际 DNS，
     替代 ksubdomain 默认仅 2 个解析器 (1.1.1.1 + 8.8.8.8)，减少限速丢包。
  3. 参数调优：-b 2m（原 5m，温和速率减少丢包）、--retry 3（原 10，依赖多轮补漏）、
     --ns（利用域名自身 NS 记录）、-r resolvers.txt（自定义解析器）。
  4. Popen + SIGTERM 优雅退出：超时时先 SIGTERM 等 10s 再 SIGKILL，
     与 module2 的 run_naabu() 模式一致，避免输出文件丢失。
  5. Python DNS 验证：多轮合并后用 socket.getaddrinfo（TCP 回退，3 次重试）
     验证子域名可解析性，替代 ksubdomain verify（纯 UDP，不可靠）。
"""
import argparse
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from utils import print_info, print_success, print_warning, format_time_remaining


def parse_ksubdomain_output(output_file: Path) -> set:
    """
    解析 ksubdomain 输出文件，提取纯净子域名集合。
    ksubdomain 输出格式: subdomain=>CNAME xxx=>ip，取 => 前的部分。
    """
    subdomains = set()
    if output_file.exists() and output_file.stat().st_size > 0:
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # ksubdomain 输出格式: subdomain=>CNAME xxx=>ip，取 => 前的纯净子域名
                clean = line.split("=>")[0].strip()
                if clean:
                    subdomains.add(clean)
    return subdomains


def _monitor_ksubdomain_output(output_file: Path, stop_event: threading.Event):
    """监控 ksubdomain 输出文件的实时变化"""
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
                    print(f"\r  ⏱️  运行时间: {elapsed_str} | 已发现: {current_count} 个子域名", end='', flush=True)
                    last_count = current_count
            else:
                elapsed = time.time() - start_time
                elapsed_str = format_time_remaining(elapsed)
                print(f"\r  ⏱️  运行时间: {elapsed_str} | 等待结果...", end='', flush=True)
        except Exception:
            pass
        time.sleep(5)


def run_ksubdomain(cmd: list, timeout: int, output_file: Path, show_progress: bool = True) -> str:
    """
    运行 ksubdomain 扫描命令，使用 Popen 控制 terminate 顺序。
    与 module2 的 run_naabu() 采用相同模式：
      - subprocess.Popen 替代 subprocess.run，便于进程控制
      - 超时时先 SIGTERM（Go 运行时默认处理会 flush fd），等 10s
      - 10s 后仍未退出则 SIGKILL 强杀
      - 避免 SIGKILL 直接强杀导致输出文件丢失

    Args:
        cmd: ksubdomain 命令列表
        timeout: 超时秒数
        output_file: 输出文件路径（用于进度监控）
        show_progress: 是否显示实时进度

    Returns:
        "ok" — 正常退出 (returncode == 0)
        "timeout" — 超时（已 SIGTERM，结果已尽力保存）
        "crash" — 非超时但非零退出（ksubdomain panic 等异常）
    """
    stop_monitor = threading.Event()

    if show_progress and output_file:
        monitor_thread = threading.Thread(
            target=_monitor_ksubdomain_output,
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
        # 先 SIGTERM，让 ksubdomain 优雅退出并 flush 输出文件
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
        print_warning("ksubdomain 扫描超时（已发送 SIGTERM，结果已尽力保存）")
        return "timeout"

    # 读取 stderr（崩溃时打印 panic 信息）
    if proc.stderr:
        stderr_output = proc.stderr.read().decode('utf-8', errors='ignore').strip()
        if stderr_output and proc.returncode != 0:
            print_warning(f"ksubdomain 警告: {stderr_output[:200]}")

    if proc.returncode != 0:
        return "crash"

    return "ok"


def verify_subdomains_dns(subdomains: set, workers: int = 20, retries: int = 3) -> set:
    """
    用 Python socket.getaddrinfo 验证子域名是否可解析。
    替代 ksubdomain verify（纯 UDP，结果不可靠）。
    优势：使用系统 DNS 解析器，支持 TCP 回退；每次验证重试 3 次，任一成功即视为有效。

    Args:
        subdomains: 待验证的子域名集合
        workers: 并发验证线程数
        retries: 每个子域名重试次数（默认 3，应对 DNS 解析瞬态失败）

    Returns:
        可解析的子域名集合
    """
    verified = set()
    failed = []

    def check_one(subdomain: str) -> tuple:
        for attempt in range(retries):
            try:
                socket.getaddrinfo(subdomain, None)
                return (subdomain, True)
            except socket.gaierror:
                if attempt < retries - 1:
                    time.sleep(0.5)
        return (subdomain, False)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_one, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            subdomain, ok = future.result()
            if ok:
                verified.add(subdomain)
            else:
                failed.append(subdomain)

    if failed:
        print_warning(f"DNS 验证移除 {len(failed)} 个无法解析的子域名")

    return verified


def collect_subdomains_multipass(
    domain: str,
    dict_file: Path,
    output_dir: Path,
    resolvers_file: Path = None,
    passes: int = 3,
    verify: bool = True,
    bandwidth: str = "2m",
    retry: int = 3,
    timeout_per_pass: int = None,
    wildcard_threshold: int = 500,
):
    """
    多轮 ksubdomain 子域名枚举 + 结果合并 + DNS 验证。

    核心思路：用 N 次温和扫描替代 1 次激进扫描。
    每轮 -b 2m + --retry 3 + 自定义解析器，温和速率减少丢包；
    N 轮并集补漏，覆盖率远优于单次 -b 5m + --retry 10。
    最后用 Python socket DNS 验证移除假阳性。

    泛解析提前拦截：每轮扫描后检查累计子域名数，超过 wildcard_threshold
    则跳过后续轮次和 DNS 验证，直接返回空列表。避免泛解析域名产生数万
    子域名后跑 DNS 验证导致卡死。

    Args:
        domain: 主域名
        dict_file: 字典文件路径
        output_dir: 临时输出目录
        resolvers_file: 自定义 DNS 解析器文件（None 则不传 -r，用 ksubdomain 默认）
        passes: 扫描轮数（默认 3，推荐 2-5）
        verify: 是否做 Python DNS 验证（默认 True）
        bandwidth: 每轮带宽限制（默认 2m，原 5m）
        retry: 每轮 ksubdomain --retry（默认 3，原 10）
        timeout_per_pass: 每轮超时秒数（None 则动态计算：max(300, min(字典行数×6, 3600))）
        wildcard_threshold: 泛解析阈值，累计子域名超过此数则跳过后续扫描和 DNS 验证（默认 500）

    Returns:
        发现的子域名列表（已去重排序）
    """
    print_info(f"开始收集子域名: {domain}（{passes} 轮扫描）")

    # 动态计算每轮超时：约每 10K 字典条目 60 秒，最少 5 分钟，最多 1 小时
    if timeout_per_pass is None:
        try:
            dict_entries = sum(1 for _ in open(dict_file, 'r', encoding='utf-8', errors='ignore'))
        except Exception:
            dict_entries = 95000
        timeout_per_pass = max(300, min(dict_entries * 6, 3600))

    all_subdomains = set()

    for pass_num in range(1, passes + 1):
        pass_output = output_dir / f"{domain.replace('.', '_')}_pass{pass_num}.txt"

        cmd = [
            "ksubdomain", "enum",
            "-d", domain,
            "-f", str(dict_file),
            "-o", str(pass_output),
            "--silent",
            "--skip-wild",
            "--ns",
            "-b", bandwidth,
            "--retry", str(retry),
            "--timeout", "10",
        ]
        if resolvers_file and resolvers_file.exists():
            cmd.extend(["-r", str(resolvers_file)])

        print_info(f"第 {pass_num}/{passes} 轮: {domain}")
        exit_status = run_ksubdomain(cmd, timeout=timeout_per_pass, output_file=pass_output)

        if exit_status == "timeout":
            print_warning(f"第 {pass_num} 轮超时（部分结果已保存）")

        # 解析本轮结果
        pass_subdomains = parse_ksubdomain_output(pass_output)
        new_in_this_pass = pass_subdomains - all_subdomains
        all_subdomains.update(pass_subdomains)

        status_map = {"ok": "正常", "timeout": "超时", "crash": "崩溃"}
        status = status_map[exit_status]
        print_info(
            f"第 {pass_num} 轮 [{status}]: 发现 {len(pass_subdomains)} 个子域名"
            f"（+{len(new_in_this_pass)} 新增，累计 {len(all_subdomains)}）"
        )

        # 崩溃时跳过剩余轮次（同一域名会重复 panic，继续扫无意义）
        if exit_status == "crash":
            print_warning(f"ksubdomain 崩溃，跳过剩余 {passes - pass_num} 轮: {domain}")
            break

        # 泛解析提前拦截：累计超阈值则跳过剩余轮次
        if len(all_subdomains) > wildcard_threshold:
            print_warning(
                f"累计子域名 {len(all_subdomains)} 超过阈值 {wildcard_threshold}，"
                f"判定为泛解析域名，跳过后续扫描轮次: {domain}"
            )
            return []

    # DNS 验证前再次检查（防御性，正常不会触发）
    if len(all_subdomains) > wildcard_threshold:
        print_warning(
            f"子域名数 {len(all_subdomains)} 超过阈值 {wildcard_threshold}，"
            f"判定为泛解析域名，跳过 DNS 验证: {domain}"
        )
        return []

    # DNS 验证：用 Python socket.getaddrinfo（TCP 回退 + 3 次重试）移除不可解析的假阳性
    if verify and all_subdomains:
        print_info(f"DNS 验证 {len(all_subdomains)} 个子域名...")
        verified = verify_subdomains_dns(all_subdomains)
        all_subdomains = verified

    return sorted(all_subdomains)


def filter_wildcard_subdomains(
    subdomains: list,
    domain: str,
    wildcard_threshold: int = 500,
) -> list:
    """
    泛解析/停放域名过滤：子域名数超过阈值则丢弃该域名全部结果。
    泛解析域名对每个子域名都返回相同 IP，无扫描价值。
    """
    if len(subdomains) > wildcard_threshold:
        print_warning(f"  子域名数 {len(subdomains)} 超过阈值 {wildcard_threshold}，丢弃全部子域名: {domain}")
        return []
    return subdomains


def main():
    parser = argparse.ArgumentParser(
        description="模块1：子域名收集（多轮扫描优化版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例：
  python module1_subdomain_collect.py --input domains.txt --output-dir results
  python module1_subdomain_collect.py --input domains.txt --output-dir results --passes 5     # 深度扫描
  python module1_subdomain_collect.py --input domains.txt --output-dir results --no-verify    # 跳过 DNS 验证
  python module1_subdomain_collect.py --input domains.txt --output-dir results --passes 1     # 单轮（最快）

参数对比（原版 vs 优化版）：
  原版：1 轮 @5m, retry=10, 默认 2 个 DNS 解析器, subprocess.run
  优化：3 轮 @2m, retry=3,  14 个自定义解析器, Popen+SIGTERM, Python DNS 验证

输入文件格式 (domains.txt)：
  example.com
  test.com

输出文件：
  - subdomains_valid.txt  去重后的子域名列表
        """
    )
    parser.add_argument("--input", required=True, help="主域名列表文件")
    parser.add_argument("--output-dir", default="results", help="输出目录")
    parser.add_argument("--dict", default=str(Path(__file__).parent / "dict" / "oneforall_subnames.txt"),
                        help="字典文件路径 (默认: dict/oneforall_subnames.txt)")
    parser.add_argument("--wildcard-threshold", type=int, default=500,
                        help="子域名数量超过此值则直接丢弃该域名全部子域名 (默认: 500)")
    parser.add_argument("--passes", type=int, default=3, choices=range(1, 6),
                        help="ksubdomain 扫描轮数，多轮合并提升稳定性 (默认: 3)")
    parser.add_argument("--no-verify", action="store_true",
                        help="跳过 DNS 验证轮（默认启用，httpx 会自然过滤无效域名，但验证能提升一致性）")
    parser.add_argument("--bandwidth", default="2m",
                        help="每轮扫描带宽限制 (默认: 2m，原 5m)")
    parser.add_argument("--resolvers", default=str(Path(__file__).parent / "dict" / "resolvers.txt"),
                        help="DNS 解析器文件路径 (默认: dict/resolvers.txt)")

    args = parser.parse_args()

    # 检查字典文件
    dict_file = Path(args.dict)
    if not dict_file.exists():
        print_warning(f"字典文件不存在: {dict_file}")
        return

    # 检查解析器文件
    resolvers_file = Path(args.resolvers) if args.resolvers else None
    if resolvers_file and not resolvers_file.exists():
        print_warning(f"解析器文件不存在: {resolvers_file}，将使用 ksubdomain 默认解析器")
        resolvers_file = None

    # 读取主域名列表
    input_file = Path(args.input)
    if not input_file.exists():
        print_warning(f"输入文件不存在: {input_file}")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not domains:
        print_warning("输入文件为空")
        return

    # 创建输出目录
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    # 创建临时目录
    temp_dir = output_dir / "temp_ksubdomain"
    temp_dir.mkdir(exist_ok=True)

    print(f"\n{'='*60}")
    print(f"主域名数量: {len(domains)}")
    print(f"字典文件: {dict_file}")
    print(f"扫描轮数: {args.passes}")
    print(f"带宽限制: {args.bandwidth}")
    print(f"DNS 解析器: {resolvers_file or 'ksubdomain 默认'}")
    print(f"Verify 验证: {'否' if args.no_verify else '是'}")
    print(f"输出目录: {output_dir}")
    print(f"{'='*60}\n")

    # 收集所有子域名
    all_subdomains = set()

    for idx, domain in enumerate(domains, 1):
        print(f"\n[{idx}/{len(domains)}] 处理域名: {domain}")

        subdomains = collect_subdomains_multipass(
            domain, dict_file, temp_dir,
            resolvers_file=resolvers_file,
            passes=args.passes,
            verify=not args.no_verify,
            bandwidth=args.bandwidth,
            wildcard_threshold=args.wildcard_threshold,
        )

        if subdomains:
            print_success(f"发现 {len(subdomains)} 个子域名")
            subdomains = filter_wildcard_subdomains(
                subdomains, domain,
                wildcard_threshold=args.wildcard_threshold,
            )
            all_subdomains.update(subdomains)
        else:
            print_warning(f"未发现子域名: {domain}")

    # 保存去重后的子域名
    output_file = output_dir / "subdomains_valid.txt"
    sorted_subdomains = sorted(list(all_subdomains))

    if sorted_subdomains:
        output_file.write_text('\n'.join(sorted_subdomains), encoding="utf-8")
    else:
        output_file.write_text('', encoding="utf-8")

    print(f"\n{'='*60}")
    print_success(f"总共收集到 {len(sorted_subdomains)} 个子域名")
    print_success(f"已保存到: {output_file}")
    print(f"{'='*60}\n")

    # 清理临时文件
    try:
        for temp_file in temp_dir.glob("*.txt"):
            temp_file.unlink()
        temp_dir.rmdir()
    except Exception:
        pass


if __name__ == "__main__":
    main()
