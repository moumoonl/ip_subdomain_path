"""
完整扫描流水线
串联三个模块：子域名收集 → 端口扫描 → 目录爆破

各模块可单独运行，此脚本仅作快捷串联入口。
分批模式：DNS 去重后合并所有资产（子域名在前，IP 在后），按 batch-size（默认 50）切分，
每批依次跑 module2（两阶段端口扫描）→ module3，结果实时追加到顶层汇总文件。
仅输入 IP 或仅输入子域名时跳过 DNS 去重。
module2 使用两阶段 naabu 扫描：
  Stage 1 — top-1000 快速探活（rate 2000, retries 2）
  Stage 2 — 存活主机全端口 -stream 模式（rate 5000，需 --allport 启用，默认跳过）
超时通过 SIGTERM 优雅终止，保存已有结果。
"""
import argparse
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from utils import print_info, print_success, print_warning, format_time_remaining

_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def is_ip(s: str) -> bool:
    return bool(_IP_RE.match(s))


def run_module(module_script: str, args: list, description: str) -> bool:
    """调用子模块脚本（module1/2/3），输出实时透传到终端，总超时 24 小时"""
    print_info(f"开始执行: {description}")
    print(f"  命令: python {module_script} {' '.join(args)}\n")

    try:
        result = subprocess.run(
            [sys.executable, module_script] + args,
            text=True,
            timeout=86400  # 24 小时
        )
        if result.returncode != 0:
            print_warning(f"{description} 执行失败（返回码 {result.returncode}）")
            return False
        print_success(f"{description} 执行完成")
        return True
    except subprocess.TimeoutExpired:
        print_warning(f"{description} 执行超时（>24h）")
        return False
    except Exception as e:
        print_warning(f"{description} 执行异常: {e}")
        return False


def read_and_dedupe(filepath) -> list:
    """读取文件并去重保序"""
    if not filepath or not Path(filepath).exists():
        return []
    with open(filepath, encoding="utf-8") as f:
        items = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    seen = set()
    unique = []
    for a in items:
        if a not in seen:
            seen.add(a)
            unique.append(a)
    return unique


def dns_dedupe(ips: list, subdomains: list) -> list:
    """
    DNS 去重：子域名解析后的 IP 若已在 IP 列表中则丢弃该子域名，
    避免对同一主机重复扫描。在分批之前执行，确保去重基于完整 IP 列表。
    子域名排在 IP 前面，使 naabu 先扫描子域名。
    当只有一种输入时，跳过 DNS 去重。

    Returns:
        去重后的合并资产列表（子域名在前，IP 在后）
    """
    if not ips or not subdomains:
        # 只有一种输入，跳过 DNS 去重
        if ips and not subdomains:
            print_info("仅输入 IP，跳过 DNS 去重")
        elif subdomains and not ips:
            print_info("仅输入子域名，跳过 DNS 去重")
        return subdomains + ips  # 子域名在前

    ip_set = set(ips)
    kept_subdomains = []
    dropped_count = 0

    for domain in subdomains:
        try:
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip in ip_set:
                dropped_count += 1
                continue
        except socket.gaierror:
            pass
        kept_subdomains.append(domain)

    if dropped_count:
        print_info(f"DNS 去重：丢弃 {dropped_count} 个子域名（解析 IP 已在 IP 列表中）")

    return kept_subdomains + ips  # 子域名在前


def split_into_batches(assets: list, batch_size: int) -> list:
    """将资产列表按 batch_size 切分"""
    if not assets:
        return []
    return [assets[i:i + batch_size] for i in range(0, len(assets), batch_size)]


def generate_title_file_from_urls(urls_file: Path, title_file: Path):
    """
    用 httpx 批量探测 URL 列表的页面标题，生成带标题的文件。
    兜底机制：当 pipeline 中断导致 sensitive_urls_title.txt 缺失或不完整时，
    从顶层 sensitive_urls.txt 重新生成。
    格式：URL [title]（无标题则只写 URL）
    """
    if not urls_file.exists() or urls_file.stat().st_size == 0:
        return

    urls = [l.strip() for l in urls_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not urls:
        return

    print_info(f"正在用 httpx 获取 {len(urls)} 个敏感 URL 的标题（兜底生成）...")

    try:
        result = subprocess.run(
            ["httpx", "-l", str(urls_file), "-json", "-silent", "-no-color"],
            capture_output=True, text=True, timeout=600
        )
    except FileNotFoundError:
        print_warning("httpx 未安装，跳过 title 文件生成")
        return
    except subprocess.TimeoutExpired:
        print_warning("httpx 获取标题超时，跳过 title 文件生成")
        return

    url_title_map = {}
    if result.stdout:
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                input_url = data.get("input", "")
                title = data.get("title", "")
                if input_url:
                    url_title_map[input_url] = title
            except json.JSONDecodeError:
                pass

    with open(title_file, "w", encoding="utf-8") as f:
        for url in urls:
            title = url_title_map.get(url, "")
            if title:
                f.write(f"{url} [{title}]\n")
            else:
                f.write(f"{url}\n")

    titled = sum(1 for t in url_title_map.values() if t)
    print_success(f"已生成 {title_file}（{titled}/{len(urls)} 个 URL 获取到标题）")


def append_file(src: Path, dst: Path):
    """将 src 内容追加到 dst"""
    if not src.exists() or src.stat().st_size == 0:
        return 0
    lines = src.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return 0
    with open(dst, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return len(lines)


def main():
    parser = argparse.ArgumentParser(
        description="完整扫描流水线（串联 module1 → module2 → module3，支持分批）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例：
  # 完整流程：module1 子域名收集 → 分批 module2+module3
  python full_pipeline.py --domains domains.txt --ips ips.txt --wordlist dict.txt

  # 直接用已有子域名+IP，跳过 module1（最常用）
  python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict.txt

  # 仅 IP，无子域名
  python full_pipeline.py --ips ips.txt --wordlist dict.txt --skip-module1

  # 调整批次大小
  python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict.txt --batch-size 50

  # 强制重跑所有批次
  python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt --wordlist dict.txt --force
        """
    )
    parser.add_argument("--domains", help="主域名列表文件（module1 输入）")
    parser.add_argument("--ips", help="IP 列表文件")
    parser.add_argument("--subdomains", help="子域名列表文件（跳过 module1 时使用）")
    parser.add_argument("--wordlist", required=True, help="目录爆破字典文件（module3 输入）")
    parser.add_argument("--recursion-depth", type=int, default=1, help="ffuf 递归深度（默认 1）")
    parser.add_argument("--concurrency", type=int, default=5, help="ffuf 并发数（默认 5）")
    parser.add_argument("--batch-size", type=int, default=50, help="每批资产数量（默认 50）")
    parser.add_argument("--output-dir", default="results", help="输出目录（默认 results）")
    parser.add_argument("--skip-module1", action="store_true", help="跳过 module1 子域名收集")
    parser.add_argument("--skip-module2", action="store_true", help="跳过 module2+module3（端口扫描和目录爆破）")
    parser.add_argument("--allport", action="store_true", help="启用 Stage 2 全端口扫描（默认跳过，仅 Stage 1 top-1000）")
    parser.add_argument("--force", action="store_true", help="强制重跑，忽略断点续扫缓存")

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    overall_start = time.time()

    print(f"\n{'='*60}")
    print("完整扫描流水线（分批模式）")
    print(f"输出目录: {output_dir}")
    print(f"每批资产数: {args.batch_size}")
    print(f"{'='*60}\n")

    subdomains_file = output_dir / "subdomains_valid.txt"

    # ── Module 1: 子域名收集（无断点续扫，每次从头跑）──────────────
    if args.subdomains:
        print_info(f"使用已有子域名文件: {args.subdomains}，跳过 module1")
        subdomains_file = Path(args.subdomains)
    elif not args.skip_module1:
        # 未提供 --subdomains 且未 --skip-module1，需要 --domains 来跑 module1
        if not args.domains:
            print_warning("未提供 --domains 也未提供 --subdomains，跳过 module1")
        else:
            print(f"\n{'='*60}")
            print("Module 1: 子域名收集")
            print(f"{'='*60}\n")
            ok = run_module(
                "module1_subdomain_collect.py",
                ["--input", args.domains, "--output-dir", str(output_dir)],
                "子域名收集"
            )
            if not ok:
                print_warning("module1 失败，终止流水线")
                return
    else:
        print_info("跳过 module1（--skip-module1）")

    # ── 分批 Module 2（两阶段端口扫描）+ Module 3（目录爆破）──────────
    if not args.skip_module2:
        print(f"\n{'='*60}")
        print("资产分批处理：Module 2（端口扫描）→ Module 3（目录爆破）")
        print(f"{'='*60}\n")

        # 读取子域名和 IP，DNS 去重后分批（子域名在前）
        all_ips = read_and_dedupe(args.ips)
        all_subdomains = read_and_dedupe(
            str(subdomains_file) if subdomains_file.exists() else None
        )

        if not all_ips and not all_subdomains:
            print_warning("没有可用资产（--ips 和子域名文件均为空或不存在），跳过扫描")
        else:
            # DNS 去重：在分批之前，基于完整 IP 列表（仅两种输入都有时执行）
            merged_assets = dns_dedupe(all_ips, all_subdomains)
            batches = split_into_batches(merged_assets, args.batch_size)

            total_batches = len(batches)
            print_info(f"子域名: {len(all_subdomains)} 个，IP: {len(all_ips)} 个，DNS 去重后: {len(merged_assets)} 个资产，分为 {total_batches} 批（每批 {args.batch_size} 个）")

            # 顶层汇总文件
            summary_http = output_dir / "http_services.txt"
            summary_sensitive = output_dir / "sensitive_urls.txt"
            summary_sensitive_title = output_dir / "sensitive_urls_title.txt"
            summary_non_http = output_dir / "non_http_services.txt"

            # 若非 force，保留已有汇总内容（追加模式）
            # 若 force，清空汇总文件
            if args.force:
                for f in [summary_http, summary_sensitive, summary_sensitive_title, summary_non_http]:
                    f.write_text("", encoding="utf-8")

            total_sensitive_count = 0
            total_http_count = 0

            for batch_idx, batch_assets in enumerate(batches, 1):
                batch_name = f"batch_{batch_idx:03d}"
                batch_dir = output_dir / batch_name
                batch_dir.mkdir(exist_ok=True)

                print(f"\n{'='*60}")
                print(f"批次 [{batch_idx}/{total_batches}]  {batch_name}  ({len(batch_assets)} 个资产)")
                print(f"{'='*60}\n")

                # 断点续扫：若该批次 ffuf_progress.txt 存在且非空，视为已完成
                batch_progress = batch_dir / "ffuf_progress.txt"
                batch_http = batch_dir / "http_services.txt"
                if not args.force and batch_progress.exists() and batch_progress.stat().st_size > 0:
                    print_info(f"  {batch_name} 已完成（ffuf_progress.txt 存在），跳过（--force 可强制重跑）")
                    # 仍然把结果计入汇总统计
                    if batch_http.exists():
                        total_http_count += len(batch_http.read_text(encoding="utf-8").strip().splitlines())
                    batch_sensitive = batch_dir / "sensitive_urls.txt"
                    if batch_sensitive.exists():
                        total_sensitive_count += len(batch_sensitive.read_text(encoding="utf-8").strip().splitlines())
                    continue

                # 写批次资产文件，并按 IP / 域名拆分给 module2
                batch_targets = batch_dir / "targets_batch.txt"
                batch_targets.write_text('\n'.join(batch_assets), encoding="utf-8")

                batch_ips = [a for a in batch_assets if is_ip(a)]
                batch_domains = [a for a in batch_assets if not is_ip(a)]

                ips_batch_file = batch_dir / "ips_batch.txt"
                domains_batch_file = batch_dir / "domains_batch.txt"
                ips_batch_file.write_text('\n'.join(batch_ips), encoding="utf-8")
                domains_batch_file.write_text('\n'.join(batch_domains), encoding="utf-8")

                # Module 2：两阶段端口扫描（分别传 --ips 和 --subdomains）
                m2_args = ["--output-dir", str(batch_dir)]
                if batch_ips:
                    m2_args += ["--ips", str(ips_batch_file)]
                if batch_domains:
                    m2_args += ["--subdomains", str(domains_batch_file)]
                if args.force:
                    m2_args.append("--force")
                if args.allport:
                    m2_args.append("--allport")

                ok = run_module("module2_port_scan_and_httpx.py", m2_args, f"端口扫描 {batch_name}")
                if not ok:
                    print_warning(f"module2 在 {batch_name} 失败，跳过该批 module3，继续下一批")
                    continue

                # Module 3：目录爆破（仅当 http_services.txt 存在且非空）
                if batch_http.exists() and batch_http.stat().st_size > 0:
                    m3_args = [
                        "--input", str(batch_http),
                        "--wordlist", args.wordlist,
                        "--recursion-depth", str(args.recursion_depth),
                        "--concurrency", str(args.concurrency),
                        "--output-dir", str(batch_dir),
                    ]
                    if args.force:
                        m3_args.append("--force")

                    run_module("module3_directory_bruteforce.py", m3_args, f"目录爆破 {batch_name}")
                else:
                    print_warning(f"  {batch_name} 无 HTTP 服务，跳过目录爆破")

                # 追加本批结果到顶层汇总文件
                n_http = append_file(batch_http, summary_http)
                n_sensitive = append_file(batch_dir / "sensitive_urls.txt", summary_sensitive)
                append_file(batch_dir / "sensitive_urls_title.txt", summary_sensitive_title)
                n_non_http = append_file(batch_dir / "non_http_services.txt", summary_non_http)
                total_http_count += n_http
                total_sensitive_count += n_sensitive

                if n_http or n_sensitive:
                    print_success(
                        f"  {batch_name} 完成：HTTP服务 +{n_http}，敏感URL +{n_sensitive}，"
                        f"非HTTP +{n_non_http}（已追加到汇总）"
                    )

            print(f"\n{'='*60}")
            print_success(f"所有批次完成！HTTP服务合计: {total_http_count}，敏感URL合计: {total_sensitive_count}")
            print(f"{'='*60}\n")

            # ── 兜底：确保顶层 sensitive_urls_title.txt 与 sensitive_urls.txt 一致 ──
            # 场景：module3 中断时 sensitive_urls.txt 有部分数据（实时写入），
            # 但 sensitive_urls_title.txt 未生成（结束时才批量生成），导致顶层 title 文件缺失。
            # 此时从顶层 sensitive_urls.txt 重新生成。
            if summary_sensitive.exists() and summary_sensitive.stat().st_size > 0:
                sensitive_lines = len(summary_sensitive.read_text(encoding="utf-8").strip().splitlines())
                title_lines = 0
                if summary_sensitive_title.exists() and summary_sensitive_title.stat().st_size > 0:
                    title_lines = len(summary_sensitive_title.read_text(encoding="utf-8").strip().splitlines())

                if title_lines < sensitive_lines:
                    print_warning(
                        f"sensitive_urls_title.txt 行数 ({title_lines}) 少于 "
                        f"sensitive_urls.txt ({sensitive_lines})，重新从汇总文件生成..."
                    )
                    generate_title_file_from_urls(summary_sensitive, summary_sensitive_title)

    else:
        print_info("跳过 module2+module3（--skip-module2）")

    # ── 总结 ─────────────────────────────────────────────────
    total_elapsed = time.time() - overall_start
    print(f"\n{'='*60}")
    print_success(f"流水线完成！总耗时: {format_time_remaining(total_elapsed)}")
    print(f"{'='*60}\n")

    print("输出文件:")
    for fname in [
        "subdomains_valid.txt",
        "http_services.txt",
        "sensitive_urls.txt",
        "sensitive_urls_title.txt",
        "non_http_services.txt",
    ]:
        fpath = output_dir / fname
        if fpath.exists() and fpath.stat().st_size > 0:
            lines = len(fpath.read_text(encoding="utf-8").strip().splitlines())
            print(f"  ✓ {fpath}  ({lines} 条)")
    print()


if __name__ == "__main__":
    main()
