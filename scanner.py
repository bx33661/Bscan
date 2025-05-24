#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author : Bpple
# Date : 2025

import socket
import requests
import threading
import time
import argparse
import sys
import os
import signal
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import ssl
from colorama import init, Fore, Style
import csv
import json
from pathlib import Path

# 初始化colorama
init()

class SubdomainScanner:
    def __init__(self, domain, threads=50, timeout=5, output_file=None, 
                 silent=False, verbose=False, user_agent=None, proxy=None,
                 dns_servers=None, max_retries=1, delay=0, check_cname=False):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.silent = silent
        self.verbose = verbose
        self.max_retries = max_retries
        self.delay = delay
        self.check_cname = check_cname
        
        self.alive_subdomains = []
        self.total_checked = 0
        self.start_time = None
        self.lock = threading.Lock()
        self.stop_scan = False
        
        # 设置日志
        self.setup_logging()
        
        # 设置DNS解析器
        self.setup_dns_resolver(dns_servers)
        
        # 设置HTTP会话
        self.setup_http_session(user_agent, proxy)
        
        # 注册信号处理
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def setup_logging(self):
        """设置日志记录"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        if self.silent:
            log_level = logging.WARNING
            
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()] if not self.silent else []
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_dns_resolver(self, dns_servers):
        """设置DNS解析器"""
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        if dns_servers:
            self.resolver.nameservers = dns_servers
            self.logger.info(f"使用自定义DNS服务器: {dns_servers}")
    
    def setup_http_session(self, user_agent, proxy):
        """设置HTTP会话"""
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
        # 设置User-Agent
        default_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        self.session.headers.update({
            'User-Agent': user_agent or default_ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # 设置代理
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            self.logger.info(f"使用代理: {proxy}")
        
        # 禁用SSL警告
        requests.packages.urllib3.disable_warnings()
        
    def signal_handler(self, signum, frame):
        """信号处理器"""
        self.stop_scan = True
        self.logger.warning("接收到中断信号，正在停止扫描...")
        
    def print_banner(self):
        """打印横幅"""
        if self.silent:
            return
            
        banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗
║                    Bscan v2.1                                  ║
║                Professional Subdomain Scanner                  ║
╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}扫描配置:{Style.RESET_ALL}
  目标域名: {self.domain}
  线程数量: {self.threads}
  超时时间: {self.timeout}s
  最大重试: {self.max_retries}
  扫描延迟: {self.delay}s
"""
        if self.output_file:
            banner += f"  输出文件: {self.output_file}\n"
        if self.check_cname:
            banner += f"  CNAME检查: 启用\n"
            
        print(banner)
    
    def dns_resolve(self, subdomain, record_type='A'):
        """DNS解析检查 - 优化版本"""
        results = {}
        full_domain = f"{subdomain}.{self.domain}"
        
        for retry in range(self.max_retries + 1):
            try:
                # A记录查询
                if record_type in ['A', 'ALL']:
                    answers = self.resolver.resolve(full_domain, 'A')
                    results['A'] = [str(answer) for answer in answers]
                
                # CNAME记录查询
                if (record_type in ['CNAME', 'ALL'] or self.check_cname) and 'A' not in results:
                    try:
                        answers = self.resolver.resolve(full_domain, 'CNAME')
                        results['CNAME'] = [str(answer) for answer in answers]
                    except:
                        pass
                
                if results:
                    return results
                    
            except dns.resolver.NXDOMAIN:
                break
            except dns.resolver.NoAnswer:
                break
            except Exception as e:
                if retry == self.max_retries:
                    self.logger.debug(f"DNS解析失败 {full_domain}: {e}")
                else:
                    time.sleep(0.1 * (retry + 1))  # 递增延迟
                    
        return None
    
    def check_http_status(self, subdomain):
        """检查HTTP/HTTPS状态 - 优化版本"""
        full_domain = f"{subdomain}.{self.domain}"
        results = {}
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            if self.stop_scan:
                break
                
            for retry in range(self.max_retries + 1):
                try:
                    url = f"{protocol}://{full_domain}"
                    response = self.session.get(
                        url, 
                        verify=False, 
                        allow_redirects=True,
                        stream=True,
                        timeout=self.timeout
                    )
                    
                    # 只读取前2KB来提取标题和基本信息
                    content = ''
                    try:
                        content = response.raw.read(2048).decode('utf-8', errors='ignore')
                    except:
                        pass
                    finally:
                        response.close()
                    
                    results[protocol] = {
                        'status_code': response.status_code,
                        'title': self.extract_title(content),
                        'redirect_url': response.url if response.url != url else None,
                        'content_length': response.headers.get('content-length', ''),
                        'server': response.headers.get('server', ''),
                        'content_type': response.headers.get('content-type', '').split(';')[0],
                        'response_time': getattr(response, 'elapsed', None)
                    }
                    break
                    
                except Exception as e:
                    if retry == self.max_retries:
                        self.logger.debug(f"{protocol.upper()}请求失败 {full_domain}: {e}")
                        results[protocol] = None
                    else:
                        time.sleep(0.1 * (retry + 1))
            
            # 如果HTTPS成功，通常不需要检查HTTP
            if protocol == 'https' and results.get('https') and results['https']['status_code'] < 400:
                break
                
        return results
    
    def extract_title(self, html):
        """提取HTML标题 - 优化版本"""
        try:
            import re
            # 更robust的标题提取
            title_patterns = [
                r'<title[^>]*>([^<]+)</title>',
                r'<title[^>]*>\s*([^<]+?)\s*</title>',
            ]
            
            for pattern in title_patterns:
                title_match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()
                    # 清理标题
                    title = re.sub(r'\s+', ' ', title)
                    title = re.sub(r'[\r\n\t]', ' ', title)
                    return title[:80]  # 限制长度
        except Exception:
            pass
        return ""
    
    def check_subdomain(self, subdomain):
        """检查单个子域名"""
        if self.stop_scan:
            return None
            
        try:
            # 应用延迟
            if self.delay > 0:
                time.sleep(self.delay)
            
            # DNS解析
            dns_results = self.dns_resolve(subdomain)
            if not dns_results:
                return None
            
            # HTTP检查
            http_results = self.check_http_status(subdomain)
            
            result = {
                'subdomain': f"{subdomain}.{self.domain}",
                'dns_results': dns_results,
                'http_results': http_results,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            with self.lock:
                self.alive_subdomains.append(result)
                self.total_checked += 1
                if not self.silent:
                    self.print_result(result)
                    
                if self.verbose:
                    progress = (self.total_checked / getattr(self, 'total_subdomains', 1)) * 100
                    elapsed = time.time() - self.start_time
                    rate = self.total_checked / elapsed if elapsed > 0 else 0
                    print(f"{Fore.BLUE}[进度] {progress:.1f}% | 速度: {rate:.1f}/s | 已发现: {len(self.alive_subdomains)}{Style.RESET_ALL}")
            
            return result
            
        except Exception as e:
            self.logger.debug(f"检查子域名失败 {subdomain}: {e}")
            return None
    
    def print_result(self, result):
        """打印结果 - 优化显示"""
        subdomain = result['subdomain']
        
        # 获取IP地址
        ips = []
        if result['dns_results'].get('A'):
            ips.extend(result['dns_results']['A'])
        if result['dns_results'].get('CNAME'):
            ips.extend([f"CNAME:{cname}" for cname in result['dns_results']['CNAME']])
        
        ip_str = ', '.join(ips[:2])  # 最多显示2个IP
        if len(ips) > 2:
            ip_str += f" (+{len(ips)-2}个)"
        
        # 构建状态信息
        status_info = []
        
        if result['http_results'].get('https'):
            https_info = result['http_results']['https']
            status_info.append(f"HTTPS:{https_info['status_code']}")
            
        if result['http_results'].get('http'):
            http_info = result['http_results']['http']
            status_info.append(f"HTTP:{http_info['status_code']}")
        
        status_str = ' | '.join(status_info) if status_info else "DNS_ONLY"
        
        # 获取标题
        title = ""
        if result['http_results'].get('https') and result['http_results']['https']['title']:
            title = result['http_results']['https']['title']
        elif result['http_results'].get('http') and result['http_results']['http']['title']:
            title = result['http_results']['http']['title']
        
        # 获取服务器信息
        server = ""
        if result['http_results'].get('https') and result['http_results']['https']['server']:
            server = result['http_results']['https']['server']
        elif result['http_results'].get('http') and result['http_results']['http']['server']:
            server = result['http_results']['http']['server']
        
        # 优化显示格式
        if self.verbose and server:
            print(f"{Fore.GREEN}[+] {subdomain:<30} {ip_str:<25} {status_str:<15} [{server[:15]}] {title[:40]}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] {subdomain:<30} {ip_str:<25} {status_str:<15} {title[:45]}{Style.RESET_ALL}")
    
    def load_subdomains_from_file(self, filename):
        """从文件加载子域名字典 - 优化版本"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                subdomains = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):  # 支持注释
                        # 验证子域名格式
                        if self.is_valid_subdomain(line):
                            subdomains.append(line.lower())
                        elif self.verbose:
                            self.logger.debug(f"跳过无效子域名 (行 {line_num}): {line}")
                
                # 去重并保持顺序
                seen = set()
                unique_subdomains = []
                for sub in subdomains:
                    if sub not in seen:
                        seen.add(sub)
                        unique_subdomains.append(sub)
                
                self.logger.info(f"从文件 {filename} 加载了 {len(unique_subdomains)} 个子域名")
                return unique_subdomains
                
        except FileNotFoundError:
            self.logger.error(f"字典文件未找到: {filename}")
        except Exception as e:
            self.logger.error(f"无法读取子域名字典文件 {filename}: {e}")
        return []
    
    def is_valid_subdomain(self, subdomain):
        """验证子域名格式"""
        import re
        # 基本的子域名格式验证
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(pattern, subdomain)) and len(subdomain) <= 63
    
    def get_default_subdomains(self):
        """获取默认子域名字典 - 优化：优先使用外部字典文件"""
        # 优先尝试加载自定义字典文件
        dictionary_files = ['subdomains.txt', 'wordlist.txt', 'dict.txt']
        
        for dict_file in dictionary_files:
            if os.path.exists(dict_file):
                subdomains = self.load_subdomains_from_file(dict_file)
                if subdomains:
                    self.logger.info(f"使用字典文件: {dict_file}")
                    return subdomains
        
        # 如果没有找到字典文件，使用精简的内置字典
        self.logger.info("使用内置精简字典")
        return [
            # 核心高频子域名
            'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'shop',
            'dev', 'test', 'staging', 'beta', 'demo', 'cdn', 'static',
            'img', 'assets', 'login', 'secure', 'portal', 'dashboard',
            'manage', 'panel', 'docs', 'help', 'support', 'status',
            'm', 'mobile', 'wap', 'vpn', 'ssl', 'email', 'smtp',
            'pop', 'imap', 'ns', 'dns', 'search', 'db', 'mysql',
            'redis', 'git', 'jenkins', 'ci', 'monitor', 'backup'
        ]
    
    def scan(self, subdomain_list=None, use_file=None):
        """主扫描功能 - 优化版本"""
        self.print_banner()
        self.start_time = time.time()
        
        # 获取子域名列表
        if use_file:
            subdomains = self.load_subdomains_from_file(use_file)
            if not subdomains:
                self.logger.error("无法加载子域名字典")
                return False
        elif subdomain_list:
            subdomains = subdomain_list
        else:
            subdomains = self.get_default_subdomains()
        
        self.total_subdomains = len(subdomains)
        
        if not self.silent:
            dict_source = "自定义" if use_file else "指定" if subdomain_list else "默认"
            print(f"{Fore.YELLOW}[*] 开始扫描，使用 {dict_source} 字典，共 {len(subdomains)} 个子域名{Style.RESET_ALL}")
            if not self.verbose:
                print(f"{Fore.CYAN}{'子域名':<30} {'IP地址':<25} {'状态':<15} {'标题'}{Style.RESET_ALL}")
                print("-" * 120)
        
        # 动态调整线程数
        optimal_threads = min(self.threads, len(subdomains), 200)
        if optimal_threads != self.threads and not self.silent:
            self.logger.info(f"自动调整线程数: {self.threads} -> {optimal_threads}")
        
        # 多线程扫描
        with ThreadPoolExecutor(max_workers=optimal_threads) as executor:
            try:
                futures = {executor.submit(self.check_subdomain, sub): sub for sub in subdomains}
                
                for future in as_completed(futures):
                    if self.stop_scan:
                        break
                    try:
                        future.result()  # 获取结果以处理异常
                    except Exception as e:
                        self.logger.debug(f"扫描任务异常: {e}")
                        
            except KeyboardInterrupt:
                self.stop_scan = True
                self.logger.warning("扫描被用户中断")
        
        # 输出统计信息
        end_time = time.time()
        duration = end_time - self.start_time
        
        if not self.silent:
            print("\n" + "="*120)
            print(f"{Fore.GREEN}[+] 扫描完成！{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}统计信息:")
            print(f"  总耗时: {duration:.2f}s")
            print(f"  扫描速度: {len(subdomains)/duration:.2f} 域名/秒")
            print(f"  检查域名: {self.total_checked}/{len(subdomains)}")
            print(f"  存活域名: {len(self.alive_subdomains)} 个")
            if self.alive_subdomains:
                success_rate = (len(self.alive_subdomains) / self.total_checked) * 100 if self.total_checked > 0 else 0
                print(f"  成功率: {success_rate:.2f}%")
                
                # 显示发现的服务类型统计
                service_types = {}
                for result in self.alive_subdomains:
                    subdomain = result['subdomain'].split('.')[0]
                    if subdomain in ['www', 'mail', 'ftp', 'admin', 'api']:
                        service_types[subdomain] = service_types.get(subdomain, 0) + 1
                
                if service_types:
                    print(f"  主要服务: {', '.join([f'{k}({v})' for k, v in service_types.items()])}")
            print(f"{Style.RESET_ALL}")
        
        # 保存结果
        if self.output_file:
            self.save_results()
            
        return True
    
    def save_results(self):
        """保存扫描结果"""
        if not self.alive_subdomains:
            self.logger.warning("没有发现存活的子域名，不保存结果")
            return False
        
        try:
            # 确保输出目录存在
            output_path = Path(self.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 根据文件扩展名保存不同格式
            if self.output_file.endswith('.json'):
                self.save_as_json()
            elif self.output_file.endswith('.csv'):
                self.save_as_csv()
            else:
                self.save_as_txt()
            
            self.logger.info(f"结果已保存到: {self.output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"保存结果失败: {e}")
            return False
    
    def save_as_json(self):
        """保存为JSON格式"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_info': {
                    'domain': self.domain,
                    'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'total_found': len(self.alive_subdomains),
                    'scan_duration': time.time() - self.start_time,
                    'scanner_version': '2.1'
                },
                'results': self.alive_subdomains
            }, f, ensure_ascii=False, indent=2)
    
    def save_as_csv(self):
        """保存为CSV格式"""
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['子域名', 'IP地址', 'CNAME', 'HTTPS状态', 'HTTP状态', '标题', '服务器', '时间戳'])
            
            for result in self.alive_subdomains:
                ips = ', '.join(result['dns_results'].get('A', []))
                cnames = ', '.join(result['dns_results'].get('CNAME', []))
                
                https_status = result['http_results'].get('https', {}).get('status_code', '') if result['http_results'].get('https') else ''
                http_status = result['http_results'].get('http', {}).get('status_code', '') if result['http_results'].get('http') else ''
                
                title = ''
                server = ''
                if result['http_results'].get('https'):
                    title = result['http_results']['https'].get('title', '')
                    server = result['http_results']['https'].get('server', '')
                elif result['http_results'].get('http'):
                    title = result['http_results']['http'].get('title', '')
                    server = result['http_results']['http'].get('server', '')
                
                writer.writerow([
                    result['subdomain'],
                    ips,
                    cnames,
                    https_status,
                    http_status,
                    title,
                    server,
                    result['timestamp']
                ])
    
    def save_as_txt(self):
        """保存为文本格式"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(f"子域名探活扫描结果\n")
            f.write(f"{'='*80}\n")
            f.write(f"目标域名: {self.domain}\n")
            f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"发现子域名: {len(self.alive_subdomains)} 个\n")
            f.write(f"扫描耗时: {time.time() - self.start_time:.2f}s\n")
            f.write(f"{'='*80}\n\n")
            
            for result in self.alive_subdomains:
                f.write(f"子域名: {result['subdomain']}\n")
                
                # DNS信息
                if result['dns_results'].get('A'):
                    f.write(f"IP地址: {', '.join(result['dns_results']['A'])}\n")
                if result['dns_results'].get('CNAME'):
                    f.write(f"CNAME: {', '.join(result['dns_results']['CNAME'])}\n")
                
                # HTTP信息
                if result['http_results'].get('https'):
                    https = result['http_results']['https']
                    f.write(f"HTTPS: {https['status_code']}")
                    if https.get('title'):
                        f.write(f" - {https['title']}")
                    if https.get('server'):
                        f.write(f" [{https['server']}]")
                    f.write("\n")
                
                if result['http_results'].get('http'):
                    http = result['http_results']['http']
                    f.write(f"HTTP: {http['status_code']}")
                    if http.get('title'):
                        f.write(f" - {http['title']}")
                    if http.get('server'):
                        f.write(f" [{http['server']}]")
                    f.write("\n")
                
                f.write(f"扫描时间: {result['timestamp']}\n")
                f.write("-" * 80 + "\n")

class BatchScanner:
    """批量域名扫描器 - 优化版本"""
    
    def __init__(self, threads=50, timeout=5, output_dir="batch_results", 
                 silent=False, verbose=False, user_agent=None, proxy=None,
                 dns_servers=None, max_retries=1, delay=0, check_cname=False):
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.silent = silent
        self.verbose = verbose
        self.user_agent = user_agent
        self.proxy = proxy
        self.dns_servers = dns_servers
        self.max_retries = max_retries
        self.delay = delay
        self.check_cname = check_cname
        
        self.all_results = {}
        self.total_domains = 0
        self.completed_domains = 0
        self.start_time = None
        
        # 确保输出目录存在
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
    def load_domains_from_file(self, filename):
        """从文件加载域名列表 - 优化版本"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                domains = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 清理域名格式
                        if line.startswith('http://') or line.startswith('https://'):
                            line = urlparse(line).netloc
                        
                        # 验证域名格式
                        if self.is_valid_domain(line):
                            domains.append(line.lower())
                        elif not self.silent:
                            print(f"⚠️  跳过无效域名 (行 {line_num}): {line}")
                
                # 去重
                domains = list(dict.fromkeys(domains))  # 保持顺序的去重
                print(f"从文件加载了 {len(domains)} 个有效域名")
                return domains
                
        except FileNotFoundError:
            print(f"❌ 域名列表文件未找到: {filename}")
        except Exception as e:
            print(f"❌ 无法读取域名列表文件 {filename}: {e}")
        return []
    
    def is_valid_domain(self, domain):
        """验证域名格式"""
        import re
        # 基本的域名格式验证
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
    
    def scan_domain(self, domain, subdomain_list=None, use_file=None):
        """扫描单个域名"""
        try:
            if not self.silent:
                print(f"\n{Fore.CYAN}[{self.completed_domains+1}/{self.total_domains}] 正在扫描: {domain}{Style.RESET_ALL}")
            
            # 创建域名特定的输出文件
            domain_safe = domain.replace('.', '_').replace(':', '_')
            output_file = f"{self.output_dir}/{domain_safe}_results.json"
            
            # 创建扫描器
            scanner = SubdomainScanner(
                domain=domain,
                threads=self.threads,
                timeout=self.timeout,
                output_file=output_file,
                silent=True,  # 批量扫描时使用静默模式
                verbose=False,
                user_agent=self.user_agent,
                proxy=self.proxy,
                dns_servers=self.dns_servers,
                max_retries=self.max_retries,
                delay=self.delay,
                check_cname=self.check_cname
            )
            
            # 执行扫描
            success = scanner.scan(subdomain_list=subdomain_list, use_file=use_file)
            
            if success:
                found_count = len(scanner.alive_subdomains)
                self.all_results[domain] = {
                    'found_count': found_count,
                    'subdomains': scanner.alive_subdomains,
                    'output_file': output_file,
                    'scan_time': time.time() - scanner.start_time
                }
                
                if not self.silent:
                    print(f"  ✅ {domain}: 发现 {found_count} 个存活子域名 ({scanner.total_checked} 个已检查)")
                    
                return True
            else:
                if not self.silent:
                    print(f"  ❌ {domain}: 扫描失败")
                return False
                
        except Exception as e:
            if not self.silent:
                print(f"  ❌ {domain}: 扫描异常 - {e}")
            return False
        finally:
            self.completed_domains += 1
    
    def batch_scan(self, domain_list_file, subdomain_list=None, use_file=None):
        """批量扫描多个域名"""
        self.start_time = time.time()
        
        # 加载域名列表
        domains = self.load_domains_from_file(domain_list_file)
        if not domains:
            print("❌ 没有有效的域名需要扫描")
            return False
        
        self.total_domains = len(domains)
        
        if not self.silent:
            print(f"\n{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗")
            print(f"║                    批量域名探活扫描                            ║")
            print(f"╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            print(f"总域名数量: {self.total_domains}")
            print(f"输出目录: {self.output_dir}")
            print(f"线程数量: {self.threads}")
            print(f"超时时间: {self.timeout}s")
            if use_file:
                print(f"字典文件: {use_file}")
            elif subdomain_list:
                print(f"指定子域名: {len(subdomain_list)} 个")
            else:
                print(f"使用: 默认字典")
            print("=" * 70)
        
        # 扫描每个域名
        successful_scans = 0
        for domain in domains:
            if self.scan_domain(domain, subdomain_list, use_file):
                successful_scans += 1
        
        # 输出汇总结果
        self.print_summary(successful_scans)
        
        # 保存汇总结果
        self.save_summary()
        
        return successful_scans > 0
    
    def print_summary(self, successful_scans):
        """打印汇总信息"""
        if self.silent:
            return
            
        end_time = time.time()
        duration = end_time - self.start_time
        
        print(f"\n{'='*70}")
        print(f"{Fore.GREEN}[+] 批量扫描完成！{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}汇总统计:")
        print(f"  总域名数量: {self.total_domains}")
        print(f"  成功扫描: {successful_scans}")
        print(f"  失败扫描: {self.total_domains - successful_scans}")
        print(f"  总耗时: {duration:.2f}s")
        print(f"  平均耗时: {duration/self.total_domains:.2f}s/域名")
        
        # 显示发现的子域名统计
        total_found = sum(result['found_count'] for result in self.all_results.values())
        print(f"  总发现子域名: {total_found} 个")
        
        if total_found > 0:
            avg_per_domain = total_found / successful_scans if successful_scans > 0 else 0
            print(f"  平均每域名: {avg_per_domain:.1f} 个{Style.RESET_ALL}")
        
        if self.all_results:
            print(f"\n{Fore.CYAN}各域名发现情况:{Style.RESET_ALL}")
            sorted_results = sorted(self.all_results.items(), 
                                  key=lambda x: x[1]['found_count'], reverse=True)
            
            for domain, result in sorted_results[:10]:  # 显示前10个
                scan_time = result.get('scan_time', 0)
                print(f"  {domain:<30} {result['found_count']:>3} 个子域名 ({scan_time:.1f}s)")
            
            if len(sorted_results) > 10:
                print(f"  ... 还有 {len(sorted_results) - 10} 个域名")
    
    def save_summary(self):
        """保存汇总结果"""
        try:
            summary_file = f"{self.output_dir}/batch_summary.json"
            
            summary_data = {
                'scan_info': {
                    'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'total_domains': self.total_domains,
                    'successful_scans': len(self.all_results),
                    'total_found_subdomains': sum(result['found_count'] for result in self.all_results.values()),
                    'scan_duration': time.time() - self.start_time,
                    'output_directory': self.output_dir,
                    'scanner_version': '2.1'
                },
                'domain_results': {}
            }
            
            for domain, result in self.all_results.items():
                summary_data['domain_results'][domain] = {
                    'found_count': result['found_count'],
                    'output_file': result['output_file'],
                    'scan_time': result.get('scan_time', 0),
                    'subdomains': [sub['subdomain'] for sub in result['subdomains']]
                }
            
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, ensure_ascii=False, indent=2)
            
            if not self.silent:
                print(f"\n📊 汇总报告已保存到: {summary_file}")
                
        except Exception as e:
            print(f"❌ 保存汇总结果失败: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Bscan v2.1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 单域名扫描
  %(prog)s example.com
  %(prog)s example.com -t 100 -T 10 -o results.json
  %(prog)s example.com -f subdomains.txt --silent
  %(prog)s example.com -s www mail ftp admin --verbose
  %(prog)s example.com --dns-servers 8.8.8.8 1.1.1.1
  %(prog)s example.com --proxy http://127.0.0.1:8080
  
  # 批量域名扫描
  %(prog)s -D domains.txt
  %(prog)s -D domains.txt -f subdomains.txt --output-dir ./results
  %(prog)s -D domains.txt -s www mail api --silent
        """)
    
    # 域名输入参数（互斥）
    domain_group = parser.add_mutually_exclusive_group(required=True)
    domain_group.add_argument('domain', nargs='?', help='目标域名 (例如: example.com)')
    domain_group.add_argument('-D', '--domain-list', help='域名列表文件路径 (批量扫描)')
    
    # 扫描配置
    parser.add_argument('-t', '--threads', type=int, default=50, 
                       help='线程数量 (默认: 50)')
    parser.add_argument('-T', '--timeout', type=int, default=5, 
                       help='超时时间/秒 (默认: 5)')
    parser.add_argument('--max-retries', type=int, default=1,
                       help='最大重试次数 (默认: 1)')
    parser.add_argument('--delay', type=float, default=0,
                       help='请求间延迟/秒 (默认: 0)')
    
    # 输入源
    parser.add_argument('-f', '--file', help='子域名字典文件路径')
    parser.add_argument('-s', '--subdomains', nargs='+', 
                       help='手动指定要测试的子域名')
    
    # 输出配置
    parser.add_argument('-o', '--output', help='输出文件路径 (支持 .txt, .csv, .json)')
    parser.add_argument('--output-dir', default='batch_results',
                       help='批量扫描输出目录 (默认: batch_results)')
    parser.add_argument('--silent', action='store_true', help='静默模式，只输出结果')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出模式')
    
    # 网络配置
    parser.add_argument('--dns-servers', nargs='+', 
                       help='自定义DNS服务器 (例如: 8.8.8.8 1.1.1.1)')
    parser.add_argument('--proxy', help='代理服务器 (例如: http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='自定义User-Agent')
    
    # 功能选项
    parser.add_argument('--check-cname', action='store_true', 
                       help='检查CNAME记录')
    
    args = parser.parse_args()
    
    try:
        if args.domain_list:
            # 批量扫描模式
            batch_scanner = BatchScanner(
                threads=args.threads,
                timeout=args.timeout,
                output_dir=args.output_dir,
                silent=args.silent,
                verbose=args.verbose,
                user_agent=args.user_agent,
                proxy=args.proxy,
                dns_servers=args.dns_servers,
                max_retries=args.max_retries,
                delay=args.delay,
                check_cname=args.check_cname
            )
            
            success = batch_scanner.batch_scan(
                domain_list_file=args.domain_list,
                subdomain_list=args.subdomains,
                use_file=args.file
            )
            
        else:
            # 单域名扫描模式
            # 验证域名格式
            domain = args.domain.lower().strip()
            if domain.startswith('http://') or domain.startswith('https://'):
                domain = urlparse(domain).netloc
            
            # 创建扫描器
            scanner = SubdomainScanner(
                domain=domain,
                threads=args.threads,
                timeout=args.timeout,
                output_file=args.output,
                silent=args.silent,
                verbose=args.verbose,
                user_agent=args.user_agent,
                proxy=args.proxy,
                dns_servers=args.dns_servers,
                max_retries=args.max_retries,
                delay=args.delay,
                check_cname=args.check_cname
            )
            
            # 开始扫描
            success = scanner.scan(
                subdomain_list=args.subdomains,
                use_file=args.file
            )
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] 扫描被用户中断{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[-] 扫描过程中发生错误: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main() 