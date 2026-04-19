# IP 子域名扫描工具

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

模块化的安全扫描工具，支持子域名收集、端口扫描、服务识别和目录爆破。三个模块完全独立可运行，`full_pipeline.py` 作为统一调度入口，支持分批流水线处理大规模资产。

---

## 特性

- **分批流水线**：资产按批次循环跑 module2→module3，每批完成后结果实时追加到汇总文件，无需等待全部资产处理完毕
- **两阶段端口扫描**：Stage 1 top-1000 快速探活 + Stage 2 存活主机全端口精扫（需 `--allport` 启用，默认跳过），兼顾速度与覆盖
- **智能过滤**：DNS 去重（子域名解析 IP 与 IP 列表重叠自动丢弃；仅单一输入时跳过去重）、泛解析/停放域名自动丢弃、ffuf 假阳性过滤
- **断点续扫**：每批次独立记录进度，中断后重跑自动跳过已完成批次和已完成 URL
- **优雅超时**：naabu 超时先发 SIGTERM（flush 输出文件），再 SIGKILL，避免结果丢失
- **实时输出**：敏感 URL、HTTP 服务每批完成后立即追加到顶层汇总文件，随时可查
- **标题提取**：目录爆破完成后自动用 httpx 获取敏感 URL 的页面标题，生成带标题版本 `sensitive_urls_title.txt`

---

## 工作流程

```
═══════════════════════════════════════════════════════════════════════════
Module 1：子域名收集
═══════════════════════════════════════════════════════════════════════════

  输入: domains.txt                    格式: 每行一个主域名
        dict/oneforall_subnames.txt    格式: 每行一个子域名字典词

        ksubdomain 爆破 ──> 清洗=>格式 ──> 泛解析阈值过滤

  输出: results/subdomains_valid.txt   格式: 每行一个纯子域名

═══════════════════════════════════════════════════════════════════════════
分批：full_pipeline 先 DNS 去重（仅两种输入都有时执行），再按 --batch-size 切分（默认 50）
═══════════════════════════════════════════════════════════════════════════

  subdomains_valid.txt ──┐
  格式: 每行一个纯子域名   │  DNS去重（子域名解析IP与IP列表重叠则丢弃子域名；仅两种输入都有时执行）
                          ▼
  ips.txt ──────────────> dns_dedupe ──> split_into_batches ──> 每批生成:
  格式: 每行一个IP                                        targets_batch.txt  格式: 每行一个子域名或IP（子域名在前）

═══════════════════════════════════════════════════════════════════════════
Module 2：两阶段端口扫描与服务识别（每批独立运行）
═══════════════════════════════════════════════════════════════════════════

  输入: targets_batch.txt              格式: 每行一个子域名或IP（子域名在前，DNS去重已完成）

        ┌─ Stage 1: top-1000 快速探活 ─────────────────────────────────┐
        │  naabu -top-ports 1000 -rate 2000 -retries 2                 │
        │  超时: max(300, 目标数×90, 7200) 秒                          │
        │  输出: all_ports_stage1.txt + alive_hosts.txt                │
        └──────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌─ Stage 2: 存活主机全端口精扫（需 --allport 启用）───────────┐
        │  naabu -p 1-65535 -rate 5000 -stream                        │
        │  超时: max(600, 存活主机数×600, 86400) 秒                    │
        │  输出: all_ports_stage2.txt                                  │
        └──────────────────────────────────────────────────────────────┘
                            │
                            ▼
        合并去重 ──> all_ports.txt      格式: 每行 host:port
                            │
                            ▼
        httpx 探测 HTTP 服务（title/status/tech）

  输出: batch_dir/all_ports.txt         格式: 每行 host:port
        batch_dir/http_services.txt     格式: 每行 URL [状态码] [标题] [技术栈]
        batch_dir/non_http_services.txt 格式: 每行 host:port 服务名

  注意: naabu 使用 CONNECT scan，超时时先发 SIGTERM 让 naabu flush 输出文件，
        等待 10 秒后再 SIGKILL，确保已发现的结果不丢失。

═══════════════════════════════════════════════════════════════════════════
Module 3：目录爆破（每批独立运行）
═══════════════════════════════════════════════════════════════════════════

  输入: batch_dir/http_services.txt     格式: 每行 URL [状态码] [标题] [技术栈]
        dict/gov-edu-med-paths-clean.txt 格式: 每行一个路径

        逐行取第一个字段作为URL ──> ffuf 并发目录爆破
                                      │ 假阳性过滤（相同status+length超70%视为WAF泛解析）
                                      ▼
                                sensitive_urls.txt
                                      │
                                      ▼
                                httpx 批量获取标题 ──> sensitive_urls_title.txt

  输出: batch_dir/sensitive_urls.txt        格式: 每行一个完整URL
        batch_dir/sensitive_urls_title.txt  格式: 每行 URL [标题]（ffuf 结束后由 httpx 生成）
        batch_dir/ffuf_progress.txt        格式: 每行一个已完成URL（断点续扫标记）

═══════════════════════════════════════════════════════════════════════════
汇总：每批完成后结果追加到顶层
═══════════════════════════════════════════════════════════════════════════

  results/http_services.txt             格式: 每行 URL [状态码] [标题] [技术栈]
  results/sensitive_urls.txt            格式: 每行一个完整URL
  results/sensitive_urls_title.txt      格式: 每行 URL [标题]（兜底机制：行数不足时自动从汇总重新生成）
  results/non_http_services.txt         格式: 每行 host:port 服务名
```

---

## 安装

### 依赖工具

```bash
go install -v github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

确保 `$HOME/go/bin` 在 PATH 中：

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

### 环境检查

```bash
chmod +x setup.sh
./setup.sh
```

---

## 快速开始

### 场景1：完整流程（module1 → 分批 module2+module3）

适合从零开始，自动完成子域名收集 + 分批端口扫描 + 目录爆破：

```bash
python full_pipeline.py \
    --domains domains.txt \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt
```

### 场景2：直接用已有子域名+IP，跳过 module1（最常用）

已有子域名列表时直接传 `--subdomains`，自动跳过 module1 进入分批流程：

```bash
python full_pipeline.py \
    --subdomains subdomains_valid.txt \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt
```

### 场景3：仅 IP，无子域名

```bash
python full_pipeline.py \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt \
    --skip-module1
```

### 场景4：调整批次大小

目标量大时建议调小批次，减少单批 naabu 超时风险：

```bash
python full_pipeline.py \
    --subdomains subdomains_valid.txt \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt \
    --batch-size 30
```

### 场景5：中断后续扫

直接重新运行原命令，已完成批次（`ffuf_progress.txt` 存在）自动跳过：

```bash
python full_pipeline.py \
    --subdomains subdomains_valid.txt \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt
```

强制重跑所有批次（忽略所有缓存）：

```bash
python full_pipeline.py \
    --subdomains subdomains_valid.txt \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt \
    --force
```

### 场景6：深度扫描

```bash
python full_pipeline.py \
    --subdomains subdomains_valid.txt \
    --ips ips.txt \
    --wordlist dict/gov-edu-med-keywords-clean.txt \
    --recursion-depth 2 \
    --concurrency 10
```

---

## 模块详解

### Module 1：子域名收集

**工具**：ksubdomain
**输入**：domains.txt（每行一个主域名）
**输出**：`results/subdomains_valid.txt`

**泛解析/停放域名过滤**：ksubdomain 爆破后若某主域名发现的子域名数超过阈值，直接丢弃该主域名全部子域名（视为泛解析或域名停放，无渗透价值）。

**注意**：Module 1 无断点续扫，每次运行都从头开始。

```bash
# 单独运行
python module1_subdomain_collect.py --input domains.txt --output-dir results

# 调低阈值（子域名数 >200 的主域名直接丢弃）
python module1_subdomain_collect.py --input domains.txt --output-dir results \
    --wildcard-threshold 200
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--input` | 必填 | 主域名列表文件 |
| `--output-dir` | results | 输出目录 |
| `--dict` | dict/oneforall_subnames.txt | 子域名字典 |
| `--wildcard-threshold` | 500 | 子域名数超过此值则丢弃该主域名全部结果 |

---

### Module 2：两阶段端口扫描与服务识别

**工具**：naabu（两阶段）+ httpx
**输入**：子域名列表 + IP 列表（单独运行时内部自动 DNS 去重，仅两种输入都有时执行；流水线模式下 DNS 去重由 full_pipeline 提前完成）
**输出**：`all_ports.txt`、`http_services.txt`、`non_http_services.txt`

**两阶段扫描**：
1. **Stage 1**：top-1000 快速探活（rate 2000, retries 2），发现存活主机和常见端口
   - 超时公式：`max(300, 目标数×90, 7200)` 秒（每目标约 90 秒，最少 5 分钟，最多 2 小时）
2. **Stage 2**：对 Stage 1 确认存活的 host 做全端口扫描（1-65535，rate 5000, -stream 模式，需 `--allport` 启用，默认跳过）
   - 超时公式：`max(600, 存活主机数×600, 86400)` 秒（每存活主机约 10 分钟，最少 10 分钟，最多 24 小时）
3. 两阶段结果合并去重写入 `all_ports.txt`（若跳过 Stage 2 则直接使用 Stage 1 结果）

**超时处理**：naabu 超时时先发 SIGTERM（让 naabu flush 输出文件），等待 10 秒后再 SIGKILL，确保已发现的结果不丢失。

**断点续扫**：已存在 `all_ports.txt` 或 `http_services.txt` 时自动跳过对应阶段。

```bash
# 单独运行
python module2_port_scan_and_httpx.py \
    --ips ips.txt \
    --subdomains results/subdomains_valid.txt \
    --output-dir results

# 强制重跑
python module2_port_scan_and_httpx.py --ips ips.txt --output-dir results --force
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--ips` | - | IP 列表文件 |
| `--subdomains` | - | 子域名列表文件 |
| `--output-dir` | results | 输出目录 |
| `--allport` | - | 启用 Stage 2 全端口扫描（默认跳过，仅 Stage 1 top-1000） |
| `--force` | - | 忽略缓存，强制重跑 |

---

### Module 3：目录爆破

**工具**：ffuf（多目标并发）+ httpx（标题提取）
**输入**：`http_services.txt`（每行一个 URL）
**输出**：`sensitive_urls.txt`（实时追加）、`sensitive_urls_title.txt`（扫描结束后生成）、`ffuf_progress.txt`（进度记录）

**假阳性过滤**：对每个目标的 ffuf 结果，统计 (status_code, content_length) 组合频率，超过 70% 的视为 WAF/泛解析假阳性自动过滤。

**标题提取**：ffuf 扫描结束后，`generate_title_file()` 用 httpx 批量探测所有敏感 URL 的页面标题，生成 `sensitive_urls_title.txt`（格式：`URL [title]`）。若 httpx 未安装或超时则优雅跳过。

**断点续扫**：读取 `ffuf_progress.txt` 跳过已完成 URL。

```bash
# 单独运行
python module3_directory_bruteforce.py \
    --input results/http_services.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt \
    --concurrency 10 \
    --output-dir results

# 对某批次单独续扫
python module3_directory_bruteforce.py \
    --input results/batch_001/http_services.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt \
    --output-dir results/batch_001
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--input` | 必填 | HTTP 服务列表文件 |
| `--wordlist` | 必填 | 目录字典文件 |
| `--output-dir` | results | 输出目录 |
| `--concurrency` | 5 | ffuf 目标并发数 |
| `--recursion-depth` | 1 | ffuf 递归深度 |
| `--force` | - | 忽略进度记录，强制重跑 |

---

## full_pipeline.py 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--domains` | - | 主域名列表（module1 输入） |
| `--ips` | - | IP 列表文件 |
| `--subdomains` | - | 已有子域名文件，传入时自动跳过 module1 |
| `--wordlist` | 必填 | 目录爆破字典 |
| `--batch-size` | 50 | 每批资产数量 |
| `--concurrency` | 5 | ffuf 目标并发数 |
| `--recursion-depth` | 1 | ffuf 递归深度 |
| `--output-dir` | results | 输出目录 |
| `--skip-module1` | - | 跳过子域名收集 |
| `--skip-module2` | - | 跳过 module2+module3（端口扫描和目录爆破） |
| `--allport` | - | 启用 Stage 2 全端口扫描（默认跳过，仅 Stage 1 top-1000） |
| `--force` | - | 强制重跑所有批次，忽略缓存 |

---

## 输出文件结构

```
results/
├── subdomains_valid.txt          # module1 输出：有效子域名列表
├── batch_001/                    # 第1批（DNS 去重后资产 1~50）
│   ├── targets_batch.txt         # 本批资产列表（子域名+IP，已去重，子域名在前）
│   ├── ips_batch.txt             # 本批 IP 列表
│   ├── domains_batch.txt         # 本批子域名列表
│   ├── targets_merged.txt        # module2 内部 DNS 去重后（独立运行时；子域名在前，IP 在后）
│   ├── all_ports_stage1.txt      # Stage 1 top-1000 探活结果（host:port）
│   ├── alive_hosts.txt           # Stage 1 发现的存活主机
│   ├── all_ports_stage2.txt      # Stage 2 全端口精扫结果（host:port，需 --allport）
│   ├── all_ports.txt             # 合并去重结果（host:port）
│   ├── http_services.txt         # HTTP/HTTPS 服务（含 title/status/tech）
│   ├── non_http_services.txt     # 非 HTTP 服务（含服务类型推断）
│   ├── sensitive_urls.txt        # ffuf 发现的敏感路径
│   ├── sensitive_urls_title.txt  # 敏感路径（含页面标题，URL [title] 格式）
│   └── ffuf_progress.txt         # 断点续扫标记（已完成 URL 列表）
├── batch_002/                    # 第2批，结构同上
├── ...
├── http_services.txt             # 汇总：所有批次 HTTP 服务（每批完成后实时追加）
├── sensitive_urls.txt            # 汇总：所有批次敏感 URL（每批完成后实时追加）
├── sensitive_urls_title.txt      # 汇总：所有批次敏感 URL 标题（含兜底重新生成机制）
└── non_http_services.txt         # 汇总：所有批次非 HTTP 服务（每批完成后实时追加）
```

实时查看进度：

```bash
# 查看已发现的敏感 URL（随批次实时更新）
tail -f results/sensitive_urls.txt

# 查看已发现的 HTTP 服务
wc -l results/http_services.txt

# 查看各批次完成情况
ls results/batch_*/ffuf_progress.txt 2>/dev/null | wc -l
```

---

## 性能参数

| 参数/配置 | 默认值 | 说明 |
|-----------|--------|------|
| `--batch-size` | 50 | 每批资产数，建议根据网络带宽调整 |
| naabu Stage 1 -rate | 2000/s | top-1000 探活速率 |
| naabu Stage 1 -retries | 2 | 探活重试次数 |
| naabu Stage 1 超时 | `max(300, 目标数×90, 7200)` | 最少 5 分钟，最多 2 小时 |
| naabu Stage 2 -rate | 5000/s | 全端口扫描速率（-stream 模式，需 `--allport`） |
| naabu Stage 2 超时 | `max(600, 存活主机数×600, 86400)` | 最少 10 分钟，最多 24 小时（需 `--allport`） |
| httpx -threads | 100 | HTTP 探测并发 |
| httpx 超时 | `max(300, 端口数, 7200)` | 最少 5 分钟，最多 2 小时 |
| ffuf -t | 50 | 单目标 ffuf 线程数 |
| ffuf -rate | 100 req/s | 单目标请求速率 |
| `--concurrency` | 5 | ffuf 多目标并发数 |

**调优建议**：
- 目标量大（>5000）：`--batch-size 30`，避免单批 naabu 运行时间过长
- 带宽充足：`--concurrency 10` 或更高，加速目录爆破
- 时间紧张：换用 `gov-edu-med-paths-clean.txt`（最小字典，速度最快）

---

## 常见问题

### 工具未找到（ksubdomain/naabu/httpx/ffuf）

```bash
which ksubdomain naabu httpx ffuf
# 若缺失，确保 Go bin 目录在 PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

### 子域名爆破后全部被丢弃

某主域名子域名数超过 `--wildcard-threshold`（默认500），判定为泛解析/停放域名，直接丢弃。若确实需要保留，调高阈值：

```bash
python module1_subdomain_collect.py --input domains.txt --wildcard-threshold 2000
```

### naabu 扫描超时

naabu 使用 CONNECT scan（非 SYN scan），全端口扫描较慢。超时时会先发 SIGTERM 保存已有结果，不会丢失。若频繁超时：

- 缩小 `--batch-size`（如 30）
- Stage 1 top-1000 通常足够发现主要服务，Stage 2 全端口是补充（需 `--allport` 启用）

### 假阳性过多

调低 `module3_directory_bruteforce.py` 中 `filter_false_positives` 函数的阈值（默认 0.70）。

### 长时间运行建议使用 screen/tmux

```bash
screen -S scan
python full_pipeline.py --subdomains subdomains_valid.txt --ips ips.txt \
    --wordlist dict/gov-edu-med-paths-clean.txt
# Ctrl+A D 挂起，screen -r scan 恢复
```

---

## 字典说明

| 字典文件 | 大小 | 适用场景 |
|----------|------|----------|
| `gov-edu-med-paths-clean.txt` | 小 | 常规扫描，速度快 |
| `gov-edu-med-dict-clean.txt` | 中 | 均衡覆盖 |
| `gov-edu-med-keywords-clean.txt` | 大 | 深度扫描，覆盖率高 |
| `oneforall_subnames.txt` | 大 | 子域名爆破专用 |

---

## 项目结构

```
ip_subdomain_path/
├── module1_subdomain_collect.py      # 子域名收集
├── module2_port_scan_and_httpx.py    # 两阶段端口扫描与服务识别
├── module3_directory_bruteforce.py   # 目录爆破
├── full_pipeline.py                  # 统一调度脚本（分批流水线）
├── utils.py                          # 工具函数（颜色输出、进度监控等）
├── setup.sh                          # 环境检查与依赖安装
├── README.md
└── dict/
    ├── oneforall_subnames.txt
    ├── gov-edu-med-dict-clean.txt
    ├── gov-edu-med-keywords-clean.txt
    └── gov-edu-med-paths-clean.txt
```

---

## 注意事项

- 仅用于授权的安全测试，遵守相关法律法规
- 建议人工复核扫描结果，避免误报
- 大规模扫描注意目标防火墙限速，适当调小 batch-size
- 完整流程对数千目标可能需要数十小时，建议使用 screen 或 tmux 后台运行

---

## 致谢

- [ksubdomain](https://github.com/boy-hack/ksubdomain)
- [naabu](https://github.com/projectdiscovery/naabu)
- [httpx](https://github.com/projectdiscovery/httpx)
- [ffuf](https://github.com/ffuf/ffuf)
