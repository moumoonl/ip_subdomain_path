"""
模块3：目录爆破
输入：http_services.txt (HTTP/HTTPS 服务列表)
输出：sensitive_urls.txt (敏感文件目录列表)
      sensitive_urls_title.txt (带标题的敏感 URL 列表)
工具：ffuf + httpx
"""
import argparse
import json
import time
import threading
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import print_info, print_success, print_warning, print_high_risk, format_time_remaining


def filter_false_positives(ffuf_results: list) -> list:
    """
    WAF + 泛解析过滤：频率超过 70% 的 (status, length) 视为假阳性
    """
    if not ffuf_results:
        return []

    key_counter = Counter(
        (item.get("status"), item.get("length")) for item in ffuf_results
    )
    total = len(ffuf_results)

    filtered = []
    for item in ffuf_results:
        status = item.get("status")
        length = item.get("length")
        freq = key_counter[(status, length)] / total
        if freq > 0.70:
            continue
        filtered.append(item)

    return filtered


def run_ffuf_scan(url: str, wordlist: str, recursion_depth: int, output_file: Path):
    """
    对单个 URL 执行 ffuf 目录爆破

    Returns:
        扫描结果列表
    """
    import subprocess

    clean_url = url.rstrip("/")
    full_url = f"{clean_url}/FUZZ"

    try:
        subprocess.run([
            "ffuf",
            "-u", full_url,
            "-w", wordlist,
            "-recursion", "-recursion-depth", str(recursion_depth),
            "-t", "50", "-rate", "100",
            "-mc", "200,204,301,302,307,403,401,500",
            "-o", str(output_file),
            "-of", "json",
            "-s"
        ], timeout=1800, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    results = []
    if output_file.exists() and output_file.stat().st_size > 0:
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                results = data.get("results", [])
        except Exception:
            pass

    return results


def extract_sensitive_urls(filtered_results: list) -> list:
    """
    提取敏感 URL（200, 401, 403, 500 状态码）
    """
    sensitive_urls = []
    sensitive_status = [200, 204, 401, 403, 500]

    for item in filtered_results:
        status = item.get("status")
        url = item.get("url", "")
        if status in sensitive_status and url:
            sensitive_urls.append(url)

    return sensitive_urls


def generate_title_file(output_dir: Path):
    """
    用 httpx 批量探测 sensitive_urls.txt 中的 URL 标题，
    生成 sensitive_urls_title.txt（URL [title] 格式）。
    """
    import subprocess

    sensitive_file = output_dir / "sensitive_urls.txt"
    title_file = output_dir / "sensitive_urls_title.txt"

    if not sensitive_file.exists() or sensitive_file.stat().st_size == 0:
        return

    # 读取所有敏感 URL
    urls = []
    with open(sensitive_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)

    if not urls:
        return

    # 写临时文件供 httpx 读取
    temp_list = output_dir / "temp_title_urls.txt"
    try:
        with open(temp_list, "w", encoding="utf-8") as f:
            for url in urls:
                f.write(url + "\n")

        print_info(f"正在用 httpx 获取 {len(urls)} 个敏感 URL 的标题...")

        try:
            result = subprocess.run(
                ["httpx", "-l", str(temp_list), "-json", "-silent", "-no-color"],
                capture_output=True, text=True, timeout=600
            )
        except FileNotFoundError:
            print_warning("httpx 未安装，跳过 title 文件生成")
            return
        except subprocess.TimeoutExpired:
            print_warning("httpx 获取标题超时，跳过 title 文件生成")
            return

        # 解析 httpx JSON 输出，建立 url → title 映射
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

        # 写入 sensitive_urls_title.txt
        with open(title_file, "w", encoding="utf-8") as f:
            for url in urls:
                title = url_title_map.get(url, "")
                if title:
                    f.write(f"{url} [{title}]\n")
                else:
                    f.write(f"{url}\n")

        titled = sum(1 for t in url_title_map.values() if t)
        print_success(f"已生成 {title_file}（{titled}/{len(urls)} 个 URL 获取到标题）")

    finally:
        try:
            temp_list.unlink()
        except Exception:
            pass


def scan_one_url(args_tuple):
    """
    线程任务：扫描单个 URL，返回 (url, sensitive_urls)
    """
    url, wordlist, recursion_depth, temp_dir, idx = args_tuple
    temp_output = temp_dir / f"ffuf_{idx}.json"
    results = run_ffuf_scan(url, wordlist, recursion_depth, temp_output)
    filtered = filter_false_positives(results)
    sensitive = extract_sensitive_urls(filtered)
    # 清理临时文件
    try:
        temp_output.unlink()
    except Exception:
        pass
    return url, sensitive


def main():
    parser = argparse.ArgumentParser(
        description="模块3：目录爆破",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例：
  python module3_directory_bruteforce.py --input http_services.txt --wordlist dict.txt
  python module3_directory_bruteforce.py --input http_services.txt --wordlist dict.txt --concurrency 10 --force

输入文件格式 (http_services.txt)：
  http://example.com [200] [Title]
  https://test.com:8443 [301] [Title]

输出文件：
  - sensitive_urls.txt        敏感文件目录列表（每行一个 URL，实时追加）
  - sensitive_urls_title.txt  带标题的敏感 URL 列表（URL [title] 格式，扫描结束后生成）
        """
    )
    parser.add_argument("--input", required=True, help="HTTP/HTTPS 服务列表文件")
    parser.add_argument("--wordlist", required=True, help="字典文件路径")
    parser.add_argument("--recursion-depth", type=int, default=1, help="递归深度（默认 1）")
    parser.add_argument("--output-dir", default="results", help="输出目录")
    parser.add_argument("--concurrency", type=int, default=5, help="ffuf 并发数（默认 5）")
    parser.add_argument("--force", action="store_true", help="忽略进度记录，强制重跑所有 URL")

    args = parser.parse_args()

    input_file = Path(args.input)
    if not input_file.exists():
        print_warning(f"输入文件不存在: {input_file}")
        return

    # 读取所有 URL（取每行第一个字段）
    all_urls = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                url = line.split()[0]
                if url.startswith(("http://", "https://")):
                    all_urls.append(url)

    if not all_urls:
        print_warning("输入文件中没有有效 URL")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    temp_dir = output_dir / "temp_ffuf"
    temp_dir.mkdir(exist_ok=True)

    output_file = output_dir / "sensitive_urls.txt"
    progress_file = output_dir / "ffuf_progress.txt"

    # 读取断点进度
    done_urls = set()
    if not args.force and progress_file.exists():
        with open(progress_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    done_urls.add(line)
        if done_urls:
            print_info(f"续扫模式：已完成 {len(done_urls)} 个 URL，跳过（使用 --force 重跑全部）")

    pending_urls = [u for u in all_urls if u not in done_urls]

    if not pending_urls:
        print_success("所有 URL 均已完成扫描")
        return

    print(f"\n{'='*60}")
    print(f"待扫描 URL 数量: {len(pending_urls)} / {len(all_urls)}")
    print(f"字典文件: {args.wordlist}")
    print(f"递归深度: {args.recursion_depth}")
    print(f"并发数量: {args.concurrency}")
    print(f"输出目录: {output_dir}")
    print(f"{'='*60}\n")

    # 进度统计（线程安全）
    completed_count = 0
    total_sensitive = 0
    lock = threading.Lock()
    start_time = time.time()

    # 如果是续扫模式且 output_file 已存在，追加模式打开；否则覆盖
    write_mode = "a" if done_urls and output_file.exists() else "w"
    out_f = open(output_file, write_mode, encoding="utf-8")

    progress_f = open(progress_file, "a", encoding="utf-8")

    try:
        tasks = [
            (url, args.wordlist, args.recursion_depth, temp_dir, idx)
            for idx, url in enumerate(pending_urls, start=len(done_urls) + 1)
        ]

        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            future_to_url = {executor.submit(scan_one_url, t): t[0] for t in tasks}

            for future in as_completed(future_to_url):
                url, sensitive = future.result()

                with lock:
                    completed_count += 1
                    total_sensitive += len(sensitive)

                    # 实时追加写入 sensitive_urls.txt
                    if sensitive:
                        for su in sensitive:
                            out_f.write(su + "\n")
                        out_f.flush()
                        print(f"\n  [{url}] 发现 {len(sensitive)} 个敏感路径:")
                        for su in sensitive:
                            print(f"    {su}")

                    # 记录进度
                    progress_f.write(url + "\n")
                    progress_f.flush()

                    # ETA
                    elapsed = time.time() - start_time
                    avg = elapsed / completed_count
                    remaining = len(pending_urls) - completed_count
                    eta_str = format_time_remaining(avg * remaining) if remaining > 0 else "完成"
                    print(
                        f"\r进度: [{completed_count}/{len(pending_urls)}] "
                        f"敏感路径: {total_sensitive} | ETA: {eta_str}",
                        end='', flush=True
                    )

    finally:
        out_f.close()
        progress_f.close()

    print()  # 换行

    # 清理临时目录
    try:
        temp_dir.rmdir()
    except Exception:
        pass

    # 用 httpx 获取敏感 URL 的标题，生成 sensitive_urls_title.txt
    if output_file.exists() and output_file.stat().st_size > 0:
        generate_title_file(output_dir)

    print(f"\n{'='*60}")
    if total_sensitive > 0:
        print_high_risk(f"发现 {total_sensitive} 个敏感 URL")
        print_success(f"已实时保存到: {output_file}")
        title_file = output_dir / "sensitive_urls_title.txt"
        if title_file.exists():
            print_success(f"带标题版本: {title_file}")
    else:
        print_info("未发现敏感 URL")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
