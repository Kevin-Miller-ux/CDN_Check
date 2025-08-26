#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整CDN检测器 - 加载外部数据文件
提供最全面的CDN检测能力，返回1或0
"""

import json
import socket
import requests
import ipaddress
import subprocess
import time
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CompleteCDNDetector:
    """完整CDN检测器"""
    
    def __init__(self, data_file='cdn_data.json'):
        """初始化检测器，加载数据文件"""
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
        except FileNotFoundError:
            print(f"⚠️ 数据文件 {data_file} 未找到，使用内置数据")
            self._load_builtin_data()
        
        self.timeout = 5
        
    def _load_builtin_data(self):
        """加载内置数据（精简版）"""
        self.data = {
            "cname_patterns": {
                "cloudflare": ["cloudflare.com", "cloudflare.net", "cf-"],
                "akamai": ["akamai.com", "akamai.net", "akadns.net"],
                "amazon": ["amazonaws.com", "cloudfront.net"],
                "alibaba": ["alicdn.com", "aliyuncs.com", "tbcache.com"],
                "tencent": ["tcdn.qq.com", "cdntip.com"],
                "baidu": ["bdydns.com", "bcebos.com"]
            },
            "header_patterns": {
                "cache_headers": ["x-cache", "x-cached", "age"],
                "cdn_headers": ["x-cdn", "x-via", "via"],
                "cloudflare_headers": ["cf-ray", "cf-request-id"],
                "akamai_headers": ["x-akamai", "x-akamai-request-id"],
                "amazon_headers": ["x-amz-cf-id", "x-amz-cf-pop"],
                "fastly_headers": ["x-fastly-request-id", "x-served-by"]
            },
            "ip_ranges": {
                "cloudflare": ["173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13"],
                "akamai": ["23.0.0.0/12", "104.64.0.0/10"],
                "amazon": ["52.46.0.0/18", "54.230.0.0/16"],
                "alibaba": ["106.11.0.0/16", "115.124.0.0/16"],
                "tencent": ["58.247.0.0/16", "119.28.0.0/16"]
            }
        }
    
    def check_cname_patterns(self, domain: str) -> Tuple[bool, List[str]]:
        """检查CNAME模式"""
        found_providers = []
        
        try:
            # 使用nslookup获取CNAME
            result = subprocess.run(
                ['nslookup', '-type=CNAME', domain],
                capture_output=True, text=True, timeout=self.timeout
            )
            
            if result.returncode == 0:
                cname_output = result.stdout.lower()
                
                for provider, patterns in self.data['cname_patterns'].items():
                    for pattern in patterns:
                        if pattern in cname_output:
                            if provider not in found_providers:
                                found_providers.append(provider)
        except:
            pass
        
        return len(found_providers) > 0, found_providers
    
    def check_http_headers(self, domain: str) -> Tuple[bool, List[str]]:
        """检查HTTP响应头"""
        found_headers = []
        
        try:
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{domain}"
                    response = requests.head(
                        url, timeout=self.timeout, verify=False, allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                    )
                    
                    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    # 检查所有类型的CDN头部
                    for category, header_list in self.data['header_patterns'].items():
                        for header_key in header_list:
                            if header_key in headers:
                                found_headers.append(f"{header_key}: {headers[header_key]}")
                    
                    # 检查Server头
                    if 'server' in headers:
                        server_value = headers['server']
                        cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'nginx/cloudflare']
                        for keyword in cdn_keywords:
                            if keyword in server_value:
                                found_headers.append(f"server: {server_value}")
                    
                    break  # 成功获取响应后退出循环
                except:
                    continue
        except:
            pass
        
        return len(found_headers) > 0, found_headers
    
    def check_ip_ranges(self, domain: str) -> Tuple[bool, List[str]]:
        """检查IP网段"""
        matched_ips = []
        
        try:
            # 获取域名IP地址
            ips = []
            addr_info = socket.getaddrinfo(domain, None)
            for item in addr_info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            
            # 检查IP是否在CDN网段中
            for ip_str in ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    for provider, ranges in self.data['ip_ranges'].items():
                        for ip_range in ranges:
                            try:
                                if ip in ipaddress.ip_network(ip_range):
                                    matched_ips.append(f"{ip_str} in {ip_range} ({provider})")
                                    break
                            except:
                                continue
                except:
                    continue
        except:
            pass
        
        return len(matched_ips) > 0, matched_ips
    
    def check_response_content(self, domain: str) -> Tuple[bool, List[str]]:
        """检查响应内容模式"""
        content_evidence = []
        
        try:
            response = requests.get(
                f"https://{domain}",
                timeout=self.timeout, verify=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            content = response.text.lower()
            
            # 检查内容中的CDN标识
            cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'cdn', 'cache']
            for keyword in cdn_keywords:
                if keyword in content:
                    content_evidence.append(f"content contains: {keyword}")
        except:
            pass
        
        return len(content_evidence) > 0, content_evidence
    
    def check_multiple_dns_servers(self, domain: str) -> Tuple[bool, List[str]]:
        """使用多个DNS服务器检查地理分布"""
        geo_evidence = []
        
        dns_servers = ['8.8.8.8', '1.1.1.1', '114.114.114.114', '223.5.5.5']
        ip_sets = []
        
        for dns_server in dns_servers:
            try:
                # 这里简化处理，实际需要dns.resolver
                result = subprocess.run(
                    ['nslookup', domain, dns_server],
                    capture_output=True, text=True, timeout=3
                )
                
                if result.returncode == 0:
                    # 简单解析IP地址
                    lines = result.stdout.split('\n')
                    ips = []
                    for line in lines:
                        if 'address:' in line.lower() and '::' not in line:
                            ip = line.split(':')[-1].strip()
                            if ip and ip.replace('.', '').isdigit():
                                ips.append(ip)
                    ip_sets.append(set(ips))
            except:
                continue
        
        # 如果不同DNS服务器返回不同IP集合，可能使用了CDN的地理分布
        all_ips = set()
        for ip_set in ip_sets:
            all_ips.update(ip_set)
        
        if len(ip_sets) > 1 and len(all_ips) > max(len(s) for s in ip_sets if s):
            geo_evidence.append("Multiple geographic IP distributions detected")
        
        return len(geo_evidence) > 0, geo_evidence
    
    def check_ttl_patterns(self, domain: str) -> Tuple[bool, List[str]]:
        """检查TTL模式"""
        ttl_evidence = []
        
        try:
            result = subprocess.run(
                ['nslookup', '-debug', domain],
                capture_output=True, text=True, timeout=self.timeout
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                # 简化TTL检查，寻找TTL信息
                if 'ttl' in output:
                    # CDN通常使用较短的TTL
                    lines = output.split('\n')
                    for line in lines:
                        if 'ttl' in line and any(short_ttl in line for short_ttl in ['60', '120', '180', '300']):
                            ttl_evidence.append("Short TTL detected (typical for CDN)")
                            break
        except:
            pass
        
        return len(ttl_evidence) > 0, ttl_evidence
    
    def comprehensive_detection(self, domain: str) -> Dict:
        """全面检测域名CDN状态"""
        # 清理域名
        if '://' in domain:
            domain = urlparse(domain).netloc
        domain = domain.strip().lower()
        
        print(f"🔍 检测域名: {domain}")
        
        result = {
            'domain': domain,
            'is_cdn': False,
            'confidence_score': 0,
            'cdn_providers': [],
            'evidence': [],
            'detection_methods': {
                'cname': False,
                'headers': False,
                'ip_ranges': False,
                'content': False,
                'geo_distribution': False,
                'ttl': False
            }
        }
        
        start_time = time.time()
        
        # 1. CNAME检查
        print("  🔗 检查CNAME...")
        is_cname_cdn, cname_providers = self.check_cname_patterns(domain)
        if is_cname_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 35
            result['cdn_providers'].extend(cname_providers)
            result['evidence'].append(f"CNAME CDN: {', '.join(cname_providers)}")
            result['detection_methods']['cname'] = True
            print(f"    ✅ CNAME CDN: {', '.join(cname_providers)}")
        
        # 2. HTTP头部检查
        print("  📋 检查HTTP头部...")
        is_header_cdn, header_evidence = self.check_http_headers(domain)
        if is_header_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 30
            result['evidence'].extend([f"HTTP header: {h}" for h in header_evidence])
            result['detection_methods']['headers'] = True
            print(f"    ✅ HTTP头部CDN: {len(header_evidence)}个证据")
        
        # 3. IP网段检查
        print("  🌍 检查IP网段...")
        is_ip_cdn, ip_evidence = self.check_ip_ranges(domain)
        if is_ip_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 25
            result['evidence'].extend([f"IP range: {ip}" for ip in ip_evidence])
            result['detection_methods']['ip_ranges'] = True
            print(f"    ✅ IP网段CDN: {len(ip_evidence)}个匹配")
        
        # 4. 响应内容检查
        print("  📄 检查响应内容...")
        is_content_cdn, content_evidence = self.check_response_content(domain)
        if is_content_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 10
            result['evidence'].extend([f"Content: {c}" for c in content_evidence])
            result['detection_methods']['content'] = True
            print(f"    ✅ 响应内容CDN: {len(content_evidence)}个证据")
        
        # 5. 地理分布检查
        print("  🌏 检查地理分布...")
        is_geo_cdn, geo_evidence = self.check_multiple_dns_servers(domain)
        if is_geo_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 15
            result['evidence'].extend([f"Geographic: {g}" for g in geo_evidence])
            result['detection_methods']['geo_distribution'] = True
            print(f"    ✅ 地理分布CDN")
        
        # 6. TTL检查
        print("  ⏱️ 检查TTL...")
        is_ttl_cdn, ttl_evidence = self.check_ttl_patterns(domain)
        if is_ttl_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 5
            result['evidence'].extend([f"TTL: {t}" for t in ttl_evidence])
            result['detection_methods']['ttl'] = True
            print(f"    ✅ TTL模式CDN")
        
        # 计算总体置信度和结果
        result['confidence_score'] = min(result['confidence_score'], 100)
        result['cdn_providers'] = list(set(result['cdn_providers']))  # 去重
        
        detection_time = time.time() - start_time
        
        # 输出结果
        if result['is_cdn']:
            confidence_level = "高" if result['confidence_score'] >= 70 else "中" if result['confidence_score'] >= 40 else "低"
            providers_text = f" ({', '.join(result['cdn_providers'])})" if result['cdn_providers'] else ""
            print(f"  🎯 检测结果: 使用CDN{providers_text} - 置信度: {confidence_level} ({result['confidence_score']}%)")
        else:
            print(f"  🎯 检测结果: 未检测到CDN")
        
        print(f"  ⏱️ 检测耗时: {detection_time:.2f}秒")
        
        return result
    
    def is_cdn(self, domain: str) -> int:
        """简化接口：检测域名是否使用CDN，返回1或0"""
        try:
            result = self.comprehensive_detection(domain)
            return 1 if result['is_cdn'] else 0
        except Exception as e:
            print(f"❌ 检测失败: {e}")
            return 0
    
    def batch_detection(self, domains: List[str]) -> Dict[str, int]:
        """批量检测多个域名"""
        results = {}
        
        print(f"🚀 开始批量CDN检测，共{len(domains)}个域名")
        print("=" * 60)
        
        for i, domain in enumerate(domains, 1):
            print(f"\n[{i}/{len(domains)}] ", end="")
            results[domain] = self.is_cdn(domain)
        
        print(f"\n📊 批量检测完成:")
        print("-" * 40)
        for domain, result in results.items():
            status = "CDN" if result else "非CDN"
            print(f"{domain:<25} -> {result} ({status})")
        
        return results


def main():
    """主函数"""
    import sys
    
    # 创建检测器
    detector = CompleteCDNDetector()
    
    if len(sys.argv) < 2:
        # 如果没有参数，运行测试
        test_domains = [
            'baidu.com',
            'taobao.com', 
            'cloudflare.com',
            'github.com',
            'example.com'
        ]
        
        print("🧪 CDN检测测试:")
        print("=" * 50)
        
        for domain in test_domains:
            result = detector.is_cdn(domain)
            print()
        
        print("\n📊 批量检测测试:")
        print("=" * 50)
        batch_results = detector.batch_detection(test_domains)
        
    else:
        # 使用命令行参数
        domains = sys.argv[1:]
        
        if len(domains) == 1:
            result = detector.is_cdn(domains[0])
            print(f"\n最终结果: {domains[0]} -> {result}")
        else:
            results = detector.batch_detection(domains)


if __name__ == '__main__':
    main()
