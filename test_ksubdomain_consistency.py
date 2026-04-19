"""
ksubdomain 一致性测试脚本
运行多次 module1 子域名收集，比较结果一致性

用法:
  python test_ksubdomain_consistency.py --input test_domains.txt --runs 3
  python test_ksubdomain_consistency.py --input test_domains.txt --runs 3 --passes 1  # 单轮对比
"""
import argparse
import shutil
import time
from pathlib import Path
from utils import print_info, print_success, print_warning


def run_module1(input_file: Path, output_dir: Path, extra_args: list = None) -> set:
    """运行 module1 并返回发现的子域名集合"""
    import subprocess

    cmd = [
        "python", "module1_subdomain_collect.py",
        "--input", str(input_file),
        "--output-dir", str(output_dir),
    ]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, timeout=7200)

    subdomains_file = output_dir / "subdomains_valid.txt"
    subdomains = set()
    if subdomains_file.exists():
        with open(subdomains_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    subdomains.add(line)

    return subdomains


def jaccard_similarity(set_a: set, set_b: set) -> float:
    """计算 Jaccard 相似度"""
    if not set_a and not set_b:
        return 1.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


def main():
    parser = argparse.ArgumentParser(description="ksubdomain 一致性测试")
    parser.add_argument("--input", required=True, help="测试域名文件")
    parser.add_argument("--runs", type=int, default=3, help="运行次数 (默认: 3)")
    parser.add_argument("--passes", type=int, default=None,
                        help="覆盖 --passes 参数 (不传则用 module1 默认值)")
    parser.add_argument("--no-verify", action="store_true", help="跳过 verify")
    parser.add_argument("--bandwidth", default=None, help="覆盖带宽参数")

    args = parser.parse_args()

    input_file = Path(args.input)
    if not input_file.exists():
        print_warning(f"输入文件不存在: {input_file}")
        return

    base_dir = Path("test_consistency_results")
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(exist_ok=True)

    # 构建额外参数
    extra_args = []
    if args.passes is not None:
        extra_args.extend(["--passes", str(args.passes)])
    if args.no_verify:
        extra_args.append("--no-verify")
    if args.bandwidth:
        extra_args.extend(["--bandwidth", args.bandwidth])

    # 运行多次
    results = []
    run_times = []

    for run_num in range(1, args.runs + 1):
        print(f"\n{'='*60}")
        print(f"  第 {run_num}/{args.runs} 次运行")
        print(f"{'='*60}")

        run_dir = base_dir / f"run_{run_num:02d}"
        start = time.time()
        subdomains = run_module1(input_file, run_dir, extra_args)
        elapsed = time.time() - start

        results.append(subdomains)
        run_times.append(elapsed)
        print_info(f"第 {run_num} 次运行完成: {len(subdomains)} 个子域名, 耗时 {elapsed:.1f}s")

    # 分析一致性
    print(f"\n{'='*60}")
    print("  一致性分析")
    print(f"{'='*60}\n")

    # 每次运行的子域名数
    for i, (subdomains, elapsed) in enumerate(zip(results, run_times), 1):
        print(f"  运行 {i}: {len(subdomains)} 个子域名, 耗时 {elapsed:.1f}s")

    # 两两 Jaccard 相似度
    print(f"\n  Jaccard 相似度矩阵:")
    for i in range(len(results)):
        row = []
        for j in range(len(results)):
            sim = jaccard_similarity(results[i], results[j])
            row.append(f"{sim:.4f}")
        print(f"    运行 {i+1}: [{' | '.join(row)}]")

    # 交集和并集
    intersection = results[0]
    union = results[0]
    for r in results[1:]:
        intersection = intersection & r
        union = union | r

    print(f"\n  所有运行的交集: {len(intersection)} 个子域名")
    print(f"  所有运行的并集: {len(union)} 个子域名")
    overall_jaccard = len(intersection) / len(union) if union else 1.0
    print(f"  整体一致性 (交集/并集): {overall_jaccard:.4f} ({overall_jaccard*100:.1f}%)")

    # 仅在某次运行中出现的子域名
    only_in = {}
    for i, r in enumerate(results, 1):
        unique = r - intersection
        if unique:
            only_in[i] = unique

    if only_in:
        print(f"\n  仅在单次运行中出现的子域名:")
        for run_num, unique_subdomains in only_in.items():
            print(f"    运行 {run_num} 独有 ({len(unique_subdomains)} 个):")
            for s in sorted(unique_subdomains)[:10]:
                print(f"      - {s}")
            if len(unique_subdomains) > 10:
                print(f"      ... 还有 {len(unique_subdomains) - 10} 个")
    else:
        print(f"\n  所有运行结果完全一致！")

    # 保存并集结果作为参考
    union_file = base_dir / "subdomains_union.txt"
    union_file.write_text('\n'.join(sorted(union)), encoding="utf-8")

    # 保存交集结果
    intersection_file = base_dir / "subdomains_intersection.txt"
    intersection_file.write_text('\n'.join(sorted(intersection)), encoding="utf-8")

    print(f"\n  并集结果已保存: {union_file}")
    print(f"  交集结果已保存: {intersection_file}")

    # 评估
    print(f"\n{'='*60}")
    if overall_jaccard >= 0.95:
        print_success(f"一致性优秀 ({overall_jaccard*100:.1f}%)")
    elif overall_jaccard >= 0.85:
        print_warning(f"一致性良好 ({overall_jaccard*100:.1f}%)，仍有少量差异")
    else:
        print_warning(f"一致性较差 ({overall_jaccard*100:.1f}%)，建议增加扫描轮数或调整参数")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
