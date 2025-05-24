# Bscan -- 子域名&探活工具

专业级子域名发现和存活检测工具，支持DNS解析、HTTP/HTTPS状态检测、多线程扫描、**批量域名扫描**等高级功能。

## ✨ 主要特性

- 🚀 **高性能扫描** - 多线程并发，智能重试机制
- 🔍 **多种DNS记录** - 支持A记录和CNAME记录检查
- 🌐 **HTTP/HTTPS检测** - 状态码、标题、服务器信息获取
- 📊 **多种输出格式** - TXT、CSV、JSON格式支持
- 🎛️ **灵活配置** - 丰富的命令行参数
- 🔧 **专业功能** - 代理支持、自定义DNS、静默模式
- 📈 **实时统计** - 扫描进度、速度、成功率显示
- 🛡️ **错误处理** - 优雅的异常处理和信号处理
- 📋 **批量扫描** - 支持从文件读取多个域名进行批量探活

## 📦 安装

### 安装依赖
```bash
pip install -r requirements.txt
```

## 🚀 快速开始

### 单域名扫描
```bash
# 基本扫描
python scanner.py example.com

# 快速扫描指定子域名
python scanner.py example.com -s www mail ftp admin api
```

### 批量域名扫描
```bash
# 批量扫描多个域名
python scanner.py -D domains.txt

# 批量扫描指定子域名
python scanner.py -D domains.txt -s www mail api

# 批量扫描保存到指定目录
python scanner.py -D domains.txt --output-dir ./scan_results
```

### 预设模式扫描
```bash
# 单域名预设模式
python Bscan.py example.com fast                    # 快速扫描
python Bscan.py example.com standard -o results.json # 标准扫描
python Bscan.py example.com comprehensive           # 全面扫描

# 批量域名预设模式
python Bscan.py -D domains.txt fast                 # 批量快速扫描
python Bscan.py -D domains.txt standard --output-dir ./results  # 批量标准扫描
python Bscan.py -D domains.txt comprehensive        # 批量全面扫描
```

## 📝 命令行参数

### 基本参数
```bash
# 单域名扫描
python scanner.py <域名> [选项]

# 批量域名扫描
python scanner.py -D <域名列表文件> [选项]
```

| 参数 | 长参数 | 说明 | 默认值 |
|------|---------|------|--------|
| `domain` | - | 目标域名 (单域名模式) | - |
| `-D` | `--domain-list` | 域名列表文件路径 (批量模式) | - |
| `-s` | `--subdomains` | 手动指定子域名 | - |
| `-f` | `--file` | 字典文件路径 | - |
| `-o` | `--output` | 输出文件路径 (单域名) | - |
| | `--output-dir` | 输出目录 (批量扫描) | batch_results |

### 扫描配置
| 参数 | 长参数 | 说明 | 默认值 |
|------|---------|------|--------|
| `-t` | `--threads` | 线程数量 | 50 |
| `-T` | `--timeout` | 超时时间/秒 | 5 |
| | `--max-retries` | 最大重试次数 | 1 |
| | `--delay` | 请求间延迟/秒 | 0 |

### 输出控制
| 参数 | 说明 |
|------|------|
| `--silent` | 静默模式，只输出结果 |
| `-v` `--verbose` | 详细输出模式 |

### 网络配置
| 参数 | 说明 | 示例 |
|------|------|------|
| `--dns-servers` | 自定义DNS服务器 | `--dns-servers 8.8.8.8 1.1.1.1` |
| `--proxy` | 代理服务器 | `--proxy http://127.0.0.1:8080` |
| `--user-agent` | 自定义User-Agent | `--user-agent "Custom Bot 1.0"` |

### 功能选项
| 参数 | 说明 |
|------|------|
| `--check-cname` | 检查CNAME记录 |

## 📋 使用示例

### 单域名扫描
```bash
# 扫描常用子域名
python scanner.py example.com -s www mail ftp admin api blog

# 使用自定义字典文件
python scanner.py example.com -f wordlist.txt

# 高性能扫描
python scanner.py example.com -t 100 -T 10
```

### 批量域名扫描
```bash
# 基本批量扫描
python scanner.py -D domains.txt

# 批量扫描指定子域名
python scanner.py -D domains.txt -s www mail api blog

# 批量扫描使用字典文件
python scanner.py -D domains.txt -f subdomains.txt

# 批量扫描保存到指定目录
python scanner.py -D domains.txt --output-dir ./scan_results -t 100
```

### 域名列表文件格式
创建 `domains.txt` 文件：
```
# 域名列表文件
# 支持注释行（以#开头）
# 支持HTTP/HTTPS格式，工具会自动清理

# 主要目标
example.com
target.org
test-site.net

# 其他目标
https://another-site.com
http://old-site.org
```

### 高级功能
```bash
# 使用自定义DNS服务器
python scanner.py example.com --dns-servers 8.8.8.8 1.1.1.1

# 通过代理扫描
python scanner.py example.com --proxy http://127.0.0.1:8080

# 隐蔽扫描（避免被检测）
python scanner.py example.com -t 10 --delay 1 --max-retries 2

# 批量隐蔽扫描
python scanner.py -D domains.txt -t 10 --delay 0.5 --silent

# CNAME记录检查
python scanner.py example.com --check-cname -v
```

### 输出格式

> 目前支持两种个数输出

```bash
# 单域名JSON格式输出
python scanner.py example.com -o results.json

# 单域名CSV格式输出
python scanner.py example.com -o results.csv

# 批量扫描输出到指定目录
python scanner.py -D domains.txt --output-dir ./batch_results
```

### 静默和批量处理
```bash
# 静默模式，适合脚本调用
python scanner.py example.com --silent -o results.json

# 批量静默扫描
python scanner.py -D domains.txt --silent

# Shell脚本批量扫描
for domain in $(cat domains.txt); do
    python scanner.py $domain --silent -o "results_$domain.json"
done
```

### 预设模式使用
```bash
# 单域名预设模式
python Bscan.py example.com fast           # 快速扫描
python Bscan.py example.com standard       # 标准扫描
python Bscan.py example.com comprehensive  # 全面扫描
python Bscan.py example.com stealth        # 隐蔽扫描
python Bscan.py example.com silent         # 静默扫描

# 批量域名预设模式
python Bscan.py -D domains.txt fast
python Bscan.py -D domains.txt standard --output-dir ./results
python Bscan.py -D domains.txt comprehensive -t 200
python Bscan.py -D domains.txt stealth
python Bscan.py -D domains.txt silent
```

## ⚠️ 免责声明

本工具仅用于授权的安全测试和研究目的。使用者需要确保：

1. **合法使用** - 只对自己拥有或获得明确授权的域名进行扫描
2. **遵守法律** - 遵守当地法律法规和相关道德准则
3. **责任使用** - 不得用于恶意攻击或未授权的渗透测试
4. **频率控制** - 合理控制扫描频率，避免对目标造成负担
5. **批量扫描注意** - 批量扫描时更要注意合规性和目标负载

使用本工具即表示您同意承担使用风险，开发者不对任何误用或滥用行为承担责任。

---

**版本**: v2.1  
**更新时间**: 2025年5月  