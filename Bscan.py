#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author : Bpple
# Date : 2025

import sys
import argparse
import subprocess
from pathlib import Path
import time

def get_scanner_path():
    """获取主扫描器路径"""
    possible_paths = ['scanner.py', 'subdomain_scanner.py']
    for path in possible_paths:
        if Path(path).exists():
            return path
    raise FileNotFoundError("找不到主扫描器文件 (scanner.py)")

def run_scan(domain, mode, output=None, threads=None, timeout=None, extra_args=None):
    """运行单域名扫描"""
    try:
        scanner_path = get_scanner_path()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        return False
    
    cmd = [sys.executable, scanner_path, domain]
    
    # 根据模式添加参数
    if mode == 'fast':
        # 快速扫描 - 只检测最常见的子域名
        cmd.extend(['-s', 'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'shop', 'dev'])
        cmd.extend(['-t', str(threads or 30)])
        cmd.extend(['-T', str(timeout or 3)])
        print(f"🚀 [快速模式] 扫描 10 个高频子域名...")
        
    elif mode == 'standard':
        # 标准扫描 - 使用自定义字典文件 (这是主要优化)
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
            print(f"📋 [标准模式] 使用自定义字典文件 subdomains.txt...")
        else:
            print(f"📋 [标准模式] 使用内置字典...")
        cmd.extend(['-t', str(threads or 50)])
        cmd.extend(['-T', str(timeout or 5)])
        
    elif mode == 'comprehensive':
        # 全面扫描 - 大字典 + 所有功能
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
        cmd.extend(['-t', str(threads or 80)])
        cmd.extend(['-T', str(timeout or 8)])
        cmd.extend(['--check-cname'])
        cmd.extend(['--max-retries', '2'])
        cmd.extend(['-v'])  # 详细模式
        print(f"🔍 [全面模式] 使用大字典 + CNAME检查 + 详细输出...")
        
    elif mode == 'stealth':
        # 隐蔽扫描 - 低速避免检测
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
        cmd.extend(['-t', str(threads or 10)])
        cmd.extend(['-T', str(timeout or 10)])
        cmd.extend(['--delay', '0.8'])
        cmd.extend(['--max-retries', '3'])
        print(f"🥷 [隐蔽模式] 低速扫描，避免被检测...")
        
    elif mode == 'silent':
        # 静默扫描 - 只输出结果
        cmd.extend(['--silent'])
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
        cmd.extend(['-t', str(threads or 50)])
        cmd.extend(['-T', str(timeout or 5)])
        
    elif mode == 'basic':
        # 基础扫描 - 最基本的子域名
        cmd.extend(['-s', 'www', 'mail', 'ftp', 'admin'])
        cmd.extend(['-t', str(threads or 20)])
        cmd.extend(['-T', str(timeout or 3)])
        print(f"⚡ [基础模式] 检测 4 个核心子域名...")
        
    # 添加额外参数
    if extra_args:
        cmd.extend(extra_args)
        
    # 添加输出文件
    if output:
        cmd.extend(['-o', output])
        
    # 运行命令
    try:
        start_time = time.time()
        result = subprocess.run(cmd, check=True)
        end_time = time.time()
        
        if mode != 'silent':
            print(f"\n⏱️  扫描耗时: {end_time - start_time:.2f}s")
        
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"❌ 扫描失败: {e}")
        return False
    except KeyboardInterrupt:
        print("\n🛑 扫描被中断")
        return False

def run_batch_scan(domain_list_file, mode, output_dir=None, threads=None, timeout=None, extra_args=None):
    """运行批量域名扫描"""
    try:
        scanner_path = get_scanner_path()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        return False
    
    cmd = [sys.executable, scanner_path, '-D', domain_list_file]
    
    # 根据模式添加参数
    if mode == 'fast':
        cmd.extend(['-s', 'www', 'mail', 'ftp', 'admin', 'api'])
        cmd.extend(['-t', str(threads or 30)])
        cmd.extend(['-T', str(timeout or 3)])
        print(f"🚀 [批量快速] 每域名检测 5 个高频子域名...")
        
    elif mode == 'standard':
        # 标准批量扫描 - 使用自定义字典
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
            print(f"📋 [批量标准] 使用自定义字典文件...")
        else:
            print(f"📋 [批量标准] 使用内置字典...")
        cmd.extend(['-t', str(threads or 50)])
        cmd.extend(['-T', str(timeout or 5)])
        
    elif mode == 'comprehensive':
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
        cmd.extend(['-t', str(threads or 80)])
        cmd.extend(['-T', str(timeout or 8)])
        cmd.extend(['--check-cname'])
        cmd.extend(['--max-retries', '2'])
        print(f"🔍 [批量全面] 使用大字典 + CNAME检查...")
        
    elif mode == 'stealth':
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
        cmd.extend(['-t', str(threads or 10)])
        cmd.extend(['-T', str(timeout or 10)])
        cmd.extend(['--delay', '1.0'])
        cmd.extend(['--max-retries', '3'])
        print(f"🥷 [批量隐蔽] 低速批量扫描...")
        
    elif mode == 'silent':
        cmd.extend(['--silent'])
        if Path('subdomains.txt').exists():
            cmd.extend(['-f', 'subdomains.txt'])
        cmd.extend(['-t', str(threads or 50)])
        cmd.extend(['-T', str(timeout or 5)])
        
    elif mode == 'basic':
        cmd.extend(['-s', 'www', 'mail', 'admin'])
        cmd.extend(['-t', str(threads or 20)])
        cmd.extend(['-T', str(timeout or 3)])
        print(f"⚡ [批量基础] 每域名检测 3 个核心子域名...")
        
    # 添加额外参数
    if extra_args:
        cmd.extend(extra_args)
        
    # 添加输出目录
    if output_dir:
        cmd.extend(['--output-dir', output_dir])
        
    # 运行命令
    try:
        start_time = time.time()
        result = subprocess.run(cmd, check=True)
        end_time = time.time()
        
        if mode != 'silent':
            print(f"\n⏱️  批量扫描总耗时: {end_time - start_time:.2f}s")
        
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"❌ 批量扫描失败: {e}")
        return False
    except KeyboardInterrupt:
        print("\n🛑 批量扫描被中断")
        return False

def check_environment():
    """检查运行环境"""
    issues = []
    
    # 检查主扫描器
    try:
        get_scanner_path()
    except FileNotFoundError:
        issues.append("❌ 主扫描器文件 scanner.py 未找到")
    
    # 检查字典文件
    if not Path('subdomains.txt').exists():
        issues.append("⚠️  字典文件 subdomains.txt 未找到，将使用内置字典")
    else:
        try:
            with open('subdomains.txt', 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if lines:
                    issues.append(f"✅ 字典文件包含 {len(lines)} 个子域名")
                else:
                    issues.append("⚠️  字典文件为空")
        except Exception as e:
            issues.append(f"⚠️  字典文件读取失败: {e}")
    
    return issues

def print_banner():
    """打印横幅"""
    banner = """
╔════════════════════════════════════════════════════════════════╗
║                      Bscan v2.1 快速扫描                       ║
║                    Professional Quick Scanner                   ║
╚════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description='子域名探活工具 - 快速扫描 v2.1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 扫描模式说明:
  basic        基础扫描 - 检测 4 个核心子域名 (www, mail, ftp, admin)
  fast         快速扫描 - 检测 10 个高频子域名
  standard     标准扫描 - 使用完整自定义字典 ⭐推荐⭐
  comprehensive 全面扫描 - 使用大字典 + CNAME检查 + 详细输出
  stealth      隐蔽扫描 - 低速扫描，避免被检测
  silent       静默扫描 - 只输出结果，适合脚本调用

📝 单域名示例:
  %(prog)s example.com basic
  %(prog)s example.com fast 
  %(prog)s example.com standard -o results.json    # 推荐
  %(prog)s example.com comprehensive -t 100
  %(prog)s example.com stealth --timeout 15

📋 批量域名示例:
  %(prog)s -D domains.txt standard                # 推荐批量方式
  %(prog)s -D domains.txt fast --output-dir ./results
  %(prog)s -D domains.txt comprehensive -t 150
  %(prog)s -D domains.txt stealth
  %(prog)s -D domains.txt silent

🔧 高级用法:
  %(prog)s example.com standard --dns-servers 8.8.8.8 1.1.1.1
  %(prog)s example.com standard --proxy http://127.0.0.1:8080
  %(prog)s -D domains.txt standard --check-cname -v
        """)
    
    # 域名输入参数（互斥）
    domain_group = parser.add_mutually_exclusive_group(required=True)
    domain_group.add_argument('domain', nargs='?', help='目标域名')
    domain_group.add_argument('-D', '--domain-list', help='域名列表文件路径 (批量扫描)')
    
    parser.add_argument('mode', choices=['basic', 'fast', 'standard', 'comprehensive', 'stealth', 'silent'],
                       help='扫描模式')
    
    # 输出配置
    parser.add_argument('-o', '--output', help='输出文件路径 (单域名扫描)')
    parser.add_argument('--output-dir', help='输出目录 (批量扫描)')
    
    # 性能调优
    parser.add_argument('-t', '--threads', type=int, help='自定义线程数')
    parser.add_argument('--timeout', type=int, help='自定义超时时间/秒')
    
    # 网络选项
    parser.add_argument('--dns-servers', nargs='+', help='自定义DNS服务器')
    parser.add_argument('--proxy', help='代理服务器')
    parser.add_argument('--user-agent', help='自定义User-Agent')
    
    # 功能选项
    parser.add_argument('--check-cname', action='store_true', help='启用CNAME检查')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--max-retries', type=int, help='最大重试次数')
    parser.add_argument('--delay', type=float, help='请求延迟/秒')
    
    # 环境检查
    parser.add_argument('--check', action='store_true', help='检查运行环境')
    
    args = parser.parse_args()
    
    # 环境检查模式
    if args.check:
        print_banner()
        print("🔍 检查运行环境...")
        issues = check_environment()
        for issue in issues:
            print(f"  {issue}")
        return
    
    # 构建额外参数
    extra_args = []
    if args.dns_servers:
        extra_args.extend(['--dns-servers'] + args.dns_servers)
    if args.proxy:
        extra_args.extend(['--proxy', args.proxy])
    if args.user_agent:
        extra_args.extend(['--user-agent', args.user_agent])
    if args.check_cname:
        extra_args.append('--check-cname')
    if args.verbose:
        extra_args.append('-v')
    if args.max_retries:
        extra_args.extend(['--max-retries', str(args.max_retries)])
    if args.delay:
        extra_args.extend(['--delay', str(args.delay)])
    
    # 显示配置信息
    if args.mode != 'silent':
        print_banner()
        
        if args.domain_list:
            print(f"📋 域名列表: {args.domain_list}")
            print(f"🎯 扫描模式: {args.mode}")
            if args.output_dir:
                print(f"📁 输出目录: {args.output_dir}")
            else:
                print(f"📁 输出目录: batch_results (默认)")
        else:
            print(f"🎯 目标域名: {args.domain}")
            print(f"🎯 扫描模式: {args.mode}")
            if args.output:
                print(f"📄 输出文件: {args.output}")
        
        # 显示性能配置
        if args.threads or args.timeout:
            print(f"⚙️  性能配置:", end="")
            if args.threads:
                print(f" 线程:{args.threads}", end="")
            if args.timeout:
                print(f" 超时:{args.timeout}s", end="")
            print()
        
        # 显示网络配置  
        if args.dns_servers or args.proxy:
            print(f"🌐 网络配置:", end="")
            if args.dns_servers:
                print(f" DNS:{','.join(args.dns_servers[:2])}", end="")
            if args.proxy:
                print(f" 代理:已配置", end="")
            print()
            
        print("-" * 66)
    
    # 执行扫描
    if args.domain_list:
        # 批量扫描
        success = run_batch_scan(
            args.domain_list, 
            args.mode, 
            args.output_dir, 
            args.threads, 
            args.timeout,
            extra_args
        )
        
        if success and args.mode != 'silent':
            print(f"\n✅ 批量扫描完成")
            output_dir = args.output_dir or 'batch_results'
            print(f"📊 结果已保存到目录: {output_dir}")
            if Path(f"{output_dir}/batch_summary.json").exists():
                print(f"📋 查看汇总报告: {output_dir}/batch_summary.json")
    else:
        # 单域名扫描
        success = run_scan(
            args.domain, 
            args.mode, 
            args.output, 
            args.threads, 
            args.timeout,
            extra_args
        )
        
        if success and args.mode != 'silent':
            print(f"\n✅ 扫描完成")
            if args.output:
                print(f"📄 结果已保存到: {args.output}")
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main() 