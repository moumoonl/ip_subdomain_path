"""
通用工具函数模块
提供颜色输出、时间格式化等功能
"""
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime


# ====================== 颜色输出工具 ======================
class Colors:
    """终端颜色代码"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def print_high_risk(message: str):
    """打印高危发现（红色加粗）"""
    print(f"{Colors.BOLD}{Colors.RED}🚨 {message}{Colors.RESET}")


def print_warning(message: str):
    """打印警告信息（黄色）"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.RESET}")


def print_info(message: str):
    """打印普通信息（蓝色）"""
    print(f"{Colors.CYAN}ℹ️  {message}{Colors.RESET}")


def print_success(message: str):
    """打印成功信息（绿色）"""
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")


def format_time_remaining(seconds):
    """格式化剩余时间"""
    if seconds < 60:
        return f"{int(seconds)}秒"
    elif seconds < 3600:
        return f"{int(seconds/60)}分{int(seconds%60)}秒"
    else:
        return f"{int(seconds/3600)}小时{int((seconds%3600)/60)}分"


def run_command(cmd: list, timeout: int = 1800, check: bool = False, output_file: Path = None, show_progress: bool = False):
    """
    执行命令并返回输出，支持实时进度监控

    Args:
        cmd: 命令列表
        timeout: 超时时间（秒）
        check: 是否检查返回码
        output_file: 输出文件路径（用于监控进度）
        show_progress: 是否显示实时进度

    Returns:
        命令输出字符串
    """
    try:
        # 如果需要显示进度，启动监控线程
        stop_monitor = threading.Event()
        monitor_thread = None

        if show_progress and output_file:
            monitor_thread = threading.Thread(
                target=_monitor_output_file,
                args=(output_file, stop_monitor),
                daemon=True
            )
            monitor_thread.start()

        # 执行命令，不捕获输出让工具直接写入文件
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=check
        )

        # 停止监控线程
        if monitor_thread:
            stop_monitor.set()
            monitor_thread.join(timeout=1)
            print()  # 换行

        return result.stderr.strip() if result.stderr else ""
    except subprocess.TimeoutExpired:
        if monitor_thread:
            stop_monitor.set()
            monitor_thread.join(timeout=1)
            print()
        print_warning(f"命令执行超时: {' '.join(cmd[:3])}")
        return ""
    except subprocess.CalledProcessError as e:
        if monitor_thread:
            stop_monitor.set()
            monitor_thread.join(timeout=1)
            print()
        print_warning(f"命令执行失败: {e}")
        return ""


def _monitor_output_file(output_file: Path, stop_event: threading.Event):
    """
    监控输出文件的实时变化

    Args:
        output_file: 要监控的文件
        stop_event: 停止信号
    """
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
                    print(f"\r  ⏱️  运行时间: {elapsed_str} | 已发现: {current_count} 条", end='', flush=True)
                    last_count = current_count
            else:
                elapsed = time.time() - start_time
                elapsed_str = format_time_remaining(elapsed)
                print(f"\r  ⏱️  运行时间: {elapsed_str} | 等待结果...", end='', flush=True)
        except Exception:
            pass

        time.sleep(5)  # 每5秒检查一次


def get_timestamp():
    """获取当前时间戳字符串"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")
