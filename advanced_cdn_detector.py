#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级CDN检测器 - 完整版
集成多种检测方法，提供最全面的CDN检测能力
基于OneForAll、CDNCheck等多个项目的检测逻辑
"""

import socket
import requests
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import subprocess
import dns.resolver
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Set
import ssl
import hashlib

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedCDNDetector:
    """高级CDN检测器"""
    
    def __init__(self):
        """初始化检测器"""
        self.timeout = 10
        self.max_workers = 20
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '114.114.114.114', '223.5.5.5']
        
        # 初始化所有检测数据
        self._init_cname_patterns()
        self._init_header_patterns()
        self._init_ip_ranges()
        self._init_asn_data()
        self._init_ssl_patterns()
        self._init_response_patterns()
        self._init_domain_patterns()
        self._init_port_patterns()
        
    def _init_cname_patterns(self):
        """初始化CNAME模式库"""
        self.cname_patterns = {
            # 国际CDN提供商
            'cloudflare': [
                'cloudflare.com', 'cloudflare.net', 'cf-', 'cloudflare',
                'cdnjs.cloudflare.com', 'workers.dev'
            ],
            'akamai': [
                'akamai.com', 'akamai.net', 'akadns.net', 'akamaized.net',
                'akamaitech.net', 'akamai-staging.net', 'edgekey.net',
                'edgesuite.net', 'srip.net', 'akamaitechnologies.com'
            ],
            'amazon': [
                'amazonaws.com', 'cloudfront.net', 'awsglobalaccel.com',
                'awsdns', 'aws.com', 'amazon.com', 'amazonwebservices.com'
            ],
            'fastly': [
                'fastly.com', 'fastlylb.net', 'fastly.net', 'global.prod.fastly.com'
            ],
            'azure': [
                'azureedge.net', 'azure.com', 'msecnd.net', 'azurefd.net',
                'trafficmanager.net', 'cloudapp.net'
            ],
            'google': [
                'googleusercontent.com', 'googlesyndication.com', 'googleapis.com',
                'gstatic.com', 'googleapis.com', 'appspot.com'
            ],
            'maxcdn': [
                'maxcdn.com', 'netdna-cdn.com', 'netdna-ssl.com'
            ],
            'incapsula': [
                'incapdns.net', 'incapsula.com'
            ],
            'sucuri': [
                'sucuri.net', 'cloudproxy.net'
            ],
            'keycdn': [
                'keycdn.com', 'kxcdn.com'
            ],
            'stackpath': [
                'stackpathcdn.com', 'stackpath.bootstrapcdn.com'
            ],
            'jsdelivr': [
                'jsdelivr.net', 'cdn.jsdelivr.net'
            ],
            'unpkg': [
                'unpkg.com'
            ],
            'cdnjs': [
                'cdnjs.cloudflare.com', 'cdnjs.com'
            ],
            
            # 中国CDN提供商
            'alibaba': [
                'alicdn.com', 'aliyuncs.com', 'alicloudsec.com', 'tbcache.com',
                'taobaocdn.com', 'alikunlun.com', 'aliyun-inc.com',
                'mmstat.com', 'yunos.com'
            ],
            'tencent': [
                'tcdn.qq.com', 'cdntip.com', 'dnsv1.com', 'qcloud.com',
                'myqcloud.com', 'qcloudcdn.com', 'cdn.qcloud.com'
            ],
            'baidu': [
                'bdydns.com', 'bcebos.com', 'bdstatic.com', 'shifen.com',
                'baidubce.com', 'yunjiasu-cdn.net'
            ],
            'wangsu': [
                'wscdns.com', 'lxdns.com', 'ourwebcdn.com', 'wsglb0.com',
                'wsdvs.com', 'speedcdns.com'
            ],
            'chinacache': [
                'chinacache.net', 'ccgslb.com', 'ccgslb.net', 'ccgslb.com.cn',
                'chinanetcenter.com', 'customcdn.com', 'customcdn.cn',
                'china-cache.com'
            ],
            'upyun': [
                'aicdn.com', 'upyun.com', 'upaiyun.com'
            ],
            'qiniu': [
                'qiniudns.com', 'clouddn.com', 'qnssl.com'
            ],
            'ksyun': [
                'ksyuncdn.com', 'ksyun.com'
            ],
            'huawei': [
                'hwcdn.net', 'myhuaweicloud.com'
            ],
            'volcengine': [
                'volcdnbj.com', 'volccdn.com', 'bytedance.com'
            ],
            
            # 其他CDN
            'bootcdn': [
                'bootcdn.cn', 'staticfile.org'
            ],
            'staticfile': [
                'staticfile.org'
            ],
            '360': [
                '360wzb.com', 'qhimg.com', 'qhmsg.com'
            ],
            'netease': [
                '163.com', 'netease.com', 'neteaseimg.com'
            ]
        }
    
    def _init_header_patterns(self):
        """初始化HTTP头部模式库"""
        self.header_patterns = {
            'cache_headers': [
                'x-cache', 'x-cached', 'x-cacheable', 'x-hit-cache',
                'x-cache-status', 'x-cache-hits', 'x-cache-lookup',
                'cc_cache', 'webcache', 'cache-control', 'age'
            ],
            'cdn_headers': [
                'x-cdn', 'x-cdn-forward', 'x-cdn-provider', 'x-via', 'via'
            ],
            'cloudflare_headers': [
                'cf-ray', 'cf-request-id', 'cf-visitor', 'cf-connecting-ip',
                'cf-ipcountry', 'cf-cache-status', 'x-cf-tsc'
            ],
            'akamai_headers': [
                'x-akamai', 'x-akamai-request-id', 'x-akamai-transformed',
                'x-check-cacheable'
            ],
            'amazon_headers': [
                'x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-request-id',
                'x-cache', 'x-amz-id-2'
            ],
            'fastly_headers': [
                'x-fastly-request-id', 'x-served-by', 'x-cache',
                'fastly-debug-digest', 'x-timer'
            ],
            'azure_headers': [
                'x-azure-ref', 'x-msedge-ref', 'x-cache'
            ],
            'chinese_cdn_headers': [
                'chinacache', 'powered-by-chinacache', 'x-ser',
                'x-req-id', 'x-requestid', 'yunjiasu', 'verycdn'
            ],
            'other_headers': [
                'x-edge-', 'x-proxy-node', 'x-served-by', 'x-iinfo',
                'x-llid', 'sozu-id', 'x-ws-request-id', 'fss-cache',
                'x-beluga-cache-status', 'skyparkcdn'
            ]
        }
    
    def _init_ip_ranges(self):
        """初始化IP网段数据库"""
        self.ip_ranges = {
            'cloudflare': [
                '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
                '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
            ],
            'akamai': [
                '23.0.0.0/12', '104.64.0.0/10', '184.24.0.0/13',
                '23.32.0.0/11', '23.64.0.0/14', '95.100.0.0/15',
                '96.6.0.0/15', '184.26.0.0/15', '2.16.0.0/13'
            ],
            'amazon': [
                '52.46.0.0/18', '52.84.0.0/15', '54.230.0.0/16',
                '54.239.128.0/18', '99.84.0.0/16', '205.251.192.0/19',
                '54.182.0.0/16', '54.192.0.0/16', '52.222.128.0/17'
            ],
            'fastly': [
                '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
                '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
                '151.101.0.0/16', '157.52.64.0/18'
            ],
            'azure': [
                '13.107.42.14/32', '13.107.6.171/32', '204.79.197.200/32'
            ],
            'alibaba': [
                '106.11.0.0/16', '111.13.0.0/16', '115.124.0.0/16',
                '118.178.0.0/16', '120.55.0.0/16', '121.40.0.0/16',
                '47.88.0.0/16', '47.89.0.0/16', '47.90.0.0/16'
            ],
            'tencent': [
                '58.247.0.0/16', '58.250.0.0/16', '119.28.0.0/16',
                '129.204.0.0/16', '132.232.0.0/16', '134.175.0.0/16',
                '148.70.0.0/16', '150.109.0.0/16'
            ],
            'baidu': [
                '14.215.0.0/16', '111.206.0.0/16', '115.239.0.0/16',
                '119.75.0.0/16', '180.149.0.0/16', '220.181.0.0/16',
                '123.125.0.0/16', '61.135.0.0/16'
            ],
            'chinacache': [
                '60.190.0.0/16', '61.158.0.0/16', '125.39.0.0/16',
                '183.131.0.0/16', '219.153.0.0/16'
            ]
        }
    
    def _init_asn_data(self):
        """初始化ASN数据"""
        self.asn_data = {
            'AS13335': 'Cloudflare',
            'AS16509': 'Amazon',
            'AS20940': 'Akamai',
            'AS54113': 'Fastly',
            'AS32934': 'Facebook',
            'AS15169': 'Google',
            'AS8075': 'Microsoft',
            'AS45102': 'Alibaba',
            'AS132203': 'Tencent',
            'AS38365': 'Baidu',
            'AS37963': 'Alibaba Cloud',
            'AS23910': 'ChinaCache',
            'AS4812': 'China Telecom',
            'AS4837': 'China Unicom',
            'AS9808': 'China Mobile',
            'AS24424': 'UPYUN',
            'AS56040': 'Qiniu'
        }
    
    def _init_ssl_patterns(self):
        """初始化SSL证书模式"""
        self.ssl_patterns = {
            'cloudflare': ['cloudflare', 'cloudflaressl'],
            'akamai': ['akamai'],
            'amazon': ['amazon', 'aws', 'cloudfront'],
            'fastly': ['fastly'],
            'letsencrypt': ['letsencrypt'],
            'alibaba': ['alibaba', 'aliyun'],
            'tencent': ['tencent', 'qcloud']
        }
    
    def _init_response_patterns(self):
        """初始化响应内容模式"""
        self.response_patterns = {
            'cloudflare': [
                'cloudflare', 'cf-ray', 'cloudflare-nginx'
            ],
            'akamai': [
                'akamai', 'ghost'
            ],
            'amazon': [
                'cloudfront', 'amazon'
            ],
            'error_pages': {
                'cloudflare': ['cloudflare', 'attention required', 'checking your browser'],
                'akamai': ['reference #', 'akamai'],
                'incapsula': ['incapsula', 'request unsuccessful']
            }
        }
    
    def _init_domain_patterns(self):
        """初始化域名模式"""
        self.domain_patterns = {
            'cdn_subdomains': [
                'cdn', 'static', 'assets', 'img', 'js', 'css',
                'media', 'upload', 'download', 'file'
            ],
            'cache_subdomains': [
                'cache', 'cached', 'edge'
            ]
        }
    
    def _init_port_patterns(self):
        """初始化端口检测模式"""
        self.common_ports = [80, 443, 8080, 8443, 3128, 8000]
    
    def resolve_with_multiple_dns(self, domain: str, record_type: str = 'A') -> List[str]:
        """使用多个DNS服务器解析域名"""
        results = []
        
        for dns_server in self.dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3
                resolver.lifetime = 3
                
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    result = str(answer).rstrip('.')
                    if result not in results:
                        results.append(result)
            except:
                continue
        
        return results
    
    def get_comprehensive_dns_info(self, domain: str) -> Dict:
        """获取全面的DNS信息"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'soa_records': []
        }
        
        record_types = {
            'A': 'a_records',
            'AAAA': 'aaaa_records', 
            'CNAME': 'cname_records',
            'MX': 'mx_records',
            'NS': 'ns_records',
            'TXT': 'txt_records',
            'SOA': 'soa_records'
        }
        
        for record_type, key in record_types.items():
            try:
                records = self.resolve_with_multiple_dns(domain, record_type)
                dns_info[key] = records
            except:
                pass
        
        return dns_info
    
    def check_cname_comprehensive(self, cname_records: List[str]) -> Tuple[bool, List[str]]:
        """全面检查CNAME记录"""
        if not cname_records:
            return False, []
        
        found_providers = []
        
        for cname in cname_records:
            cname_lower = cname.lower()
            
            for provider, patterns in self.cname_patterns.items():
                for pattern in patterns:
                    if pattern in cname_lower:
                        if provider not in found_providers:
                            found_providers.append(provider)
        
        return len(found_providers) > 0, found_providers
    
    def get_advanced_http_info(self, domain: str) -> Dict:
        """获取高级HTTP信息"""
        http_info = {
            'status_codes': {},
            'headers': {},
            'response_times': {},
            'server_info': {},
            'redirect_chain': [],
            'ssl_info': {}
        }
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{domain}"
                start_time = time.time()
                
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                
                end_time = time.time()
                response_time = (end_time - start_time) * 1000
                
                http_info['status_codes'][protocol] = response.status_code
                http_info['headers'][protocol] = dict(response.headers)
                http_info['response_times'][protocol] = response_time
                
                # 获取重定向链
                if response.history:
                    redirect_chain = []
                    for resp in response.history:
                        redirect_chain.append({
                            'url': resp.url,
                            'status_code': resp.status_code
                        })
                    http_info['redirect_chain'] = redirect_chain
                
                # 获取SSL信息
                if protocol == 'https':
                    http_info['ssl_info'] = self.get_ssl_certificate_info(domain)
                
                break
                
            except Exception as e:
                http_info['errors'] = http_info.get('errors', {})
                http_info['errors'][protocol] = str(e)
        
        return http_info
    
    def get_ssl_certificate_info(self, domain: str) -> Dict:
        """获取SSL证书信息"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['version'] = cert.get('version')
                    ssl_info['serial_number'] = cert.get('serialNumber')
                    ssl_info['not_before'] = cert.get('notBefore')
                    ssl_info['not_after'] = cert.get('notAfter')
                    ssl_info['san'] = cert.get('subjectAltName', [])
                    
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def check_headers_comprehensive(self, headers_data: Dict) -> Tuple[bool, List[str]]:
        """全面检查HTTP响应头"""
        found_evidence = []
        
        for protocol, headers in headers_data.items():
            if not headers:
                continue
                
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            
            # 检查所有CDN头部模式
            for category, header_list in self.header_patterns.items():
                for header_key in header_list:
                    if header_key in headers_lower:
                        found_evidence.append(f"{protocol.upper()} {header_key}: {headers_lower[header_key]}")
            
            # 检查Server头的特殊模式
            if 'server' in headers_lower:
                server_value = headers_lower['server']
                cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'nginx/cloudflare', 'amazon']
                for keyword in cdn_keywords:
                    if keyword in server_value:
                        found_evidence.append(f"{protocol.upper()} server: {server_value}")
        
        return len(found_evidence) > 0, found_evidence
    
    def check_ip_ranges_comprehensive(self, ip_addresses: List[str]) -> Tuple[bool, List[str]]:
        """全面检查IP网段"""
        if not ip_addresses:
            return False, []
        
        matched_ips = []
        
        for ip_str in ip_addresses:
            try:
                ip = ipaddress.ip_address(ip_str)
                
                for provider, ranges in self.ip_ranges.items():
                    for ip_range in ranges:
                        try:
                            if ip in ipaddress.ip_network(ip_range):
                                matched_ips.append(f"{ip_str} in {ip_range} ({provider})")
                                break
                        except:
                            continue
            except:
                continue
        
        return len(matched_ips) > 0, matched_ips
    
    def get_asn_info(self, ip: str) -> Optional[str]:
        """获取IP的ASN信息"""
        try:
            # 尝试使用在线ASN查询服务
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                org = data.get('org', '')
                if org.startswith('AS'):
                    asn = org.split()[0]
                    return asn
        except:
            pass
        
        return None
    
    def check_asn_comprehensive(self, ip_addresses: List[str]) -> Tuple[bool, List[str]]:
        """全面检查ASN信息"""
        asn_evidence = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_ip = {executor.submit(self.get_asn_info, ip): ip for ip in ip_addresses[:5]}
            
            for future in future_to_ip:
                ip = future_to_ip[future]
                try:
                    asn = future.result(timeout=5)
                    if asn and asn in self.asn_data:
                        provider = self.asn_data[asn]
                        asn_evidence.append(f"{ip} -> {asn} ({provider})")
                except:
                    continue
        
        return len(asn_evidence) > 0, asn_evidence
    
    def check_ssl_patterns(self, ssl_info: Dict) -> Tuple[bool, List[str]]:
        """检查SSL证书模式"""
        ssl_evidence = []
        
        if 'issuer' in ssl_info:
            issuer_info = ssl_info['issuer']
            issuer_text = ' '.join(str(v) for v in issuer_info.values()).lower()
            
            for provider, patterns in self.ssl_patterns.items():
                for pattern in patterns:
                    if pattern in issuer_text:
                        ssl_evidence.append(f"SSL issuer contains: {pattern}")
        
        return len(ssl_evidence) > 0, ssl_evidence
    
    def check_response_patterns(self, domain: str) -> Tuple[bool, List[str]]:
        """检查响应内容模式"""
        response_evidence = []
        
        try:
            response = requests.get(
                f"https://{domain}",
                timeout=5,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            content = response.text.lower()
            
            for provider, patterns in self.response_patterns.items():
                if provider != 'error_pages':
                    for pattern in patterns:
                        if pattern in content:
                            response_evidence.append(f"Response content contains: {pattern}")
        except:
            pass
        
        return len(response_evidence) > 0, response_evidence
    
    def check_multiple_locations(self, domain: str) -> Tuple[bool, List[str]]:
        """检查多地理位置解析"""
        location_evidence = []
        
        # 使用不同地区的DNS服务器
        regional_dns = {
            'US': ['8.8.8.8', '1.1.1.1'],
            'CN': ['114.114.114.114', '223.5.5.5'],
            'EU': ['9.9.9.9', '1.0.0.1']
        }
        
        ip_sets = {}
        
        for region, dns_servers in regional_dns.items():
            ips = set()
            for dns_server in dns_servers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 3
                    
                    answers = resolver.resolve(domain, 'A')
                    for answer in answers:
                        ips.add(str(answer))
                except:
                    continue
            
            ip_sets[region] = ips
        
        # 检查是否有不同的IP集合（表明使用了CDN的地理分布）
        all_ips = set()
        for ips in ip_sets.values():
            all_ips.update(ips)
        
        if len(all_ips) > len(max(ip_sets.values(), key=len)):
            location_evidence.append("Multiple geographic IP sets detected")
        
        return len(location_evidence) > 0, location_evidence
    
    def check_ttl_patterns(self, domain: str) -> Tuple[bool, List[str]]:
        """检查TTL模式"""
        ttl_evidence = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            answer = resolver.resolve(domain, 'A')
            ttl = answer.rrset.ttl
            
            # CDN通常使用较短的TTL（< 300秒）
            if ttl < 300:
                ttl_evidence.append(f"Short TTL detected: {ttl}s (typical for CDN)")
        except:
            pass
        
        return len(ttl_evidence) > 0, ttl_evidence
    
    def comprehensive_cdn_detection(self, domain: str) -> Dict:
        """全面CDN检测"""
        print(f"🔍 开始全面CDN检测: {domain}")
        
        # 清理域名
        if '://' in domain:
            domain = urlparse(domain).netloc
        domain = domain.strip().lower()
        
        result = {
            'domain': domain,
            'is_cdn': False,
            'confidence_score': 0,
            'cdn_providers': [],
            'evidence': {
                'cname': [],
                'headers': [],
                'ip_ranges': [],
                'asn': [],
                'ssl': [],
                'response': [],
                'location': [],
                'ttl': []
            },
            'technical_details': {
                'dns_info': {},
                'http_info': {},
                'timing_info': {}
            }
        }
        
        start_time = time.time()
        
        # 1. DNS信息收集
        print("  📡 收集DNS信息...")
        dns_info = self.get_comprehensive_dns_info(domain)
        result['technical_details']['dns_info'] = dns_info
        
        # 2. CNAME检查
        print("  🔗 检查CNAME记录...")
        is_cname_cdn, cname_providers = self.check_cname_comprehensive(dns_info['cname_records'])
        if is_cname_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 30
            result['cdn_providers'].extend(cname_providers)
            result['evidence']['cname'] = cname_providers
            print(f"    ✅ CNAME CDN检测: {', '.join(cname_providers)}")
        
        # 3. HTTP信息收集
        print("  🌐 收集HTTP信息...")
        http_info = self.get_advanced_http_info(domain)
        result['technical_details']['http_info'] = http_info
        
        # 4. HTTP头部检查
        print("  📋 检查HTTP响应头...")
        is_header_cdn, header_evidence = self.check_headers_comprehensive(http_info['headers'])
        if is_header_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 25
            result['evidence']['headers'] = header_evidence
            print(f"    ✅ HTTP头部CDN检测: {len(header_evidence)}个证据")
        
        # 5. IP网段检查
        print("  🌍 检查IP网段...")
        all_ips = dns_info['a_records'] + dns_info['aaaa_records']
        is_ip_cdn, ip_evidence = self.check_ip_ranges_comprehensive(all_ips)
        if is_ip_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 20
            result['evidence']['ip_ranges'] = ip_evidence
            print(f"    ✅ IP网段CDN检测: {len(ip_evidence)}个匹配")
        
        # 6. ASN检查
        print("  🏢 检查ASN信息...")
        is_asn_cdn, asn_evidence = self.check_asn_comprehensive(all_ips[:3])
        if is_asn_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 15
            result['evidence']['asn'] = asn_evidence
            print(f"    ✅ ASN CDN检测: {len(asn_evidence)}个匹配")
        
        # 7. SSL证书检查
        print("  🔒 检查SSL证书...")
        if 'ssl_info' in http_info:
            is_ssl_cdn, ssl_evidence = self.check_ssl_patterns(http_info['ssl_info'])
            if is_ssl_cdn:
                result['is_cdn'] = True
                result['confidence_score'] += 10
                result['evidence']['ssl'] = ssl_evidence
                print(f"    ✅ SSL证书CDN检测: {len(ssl_evidence)}个证据")
        
        # 8. 响应内容检查
        print("  📄 检查响应内容...")
        is_response_cdn, response_evidence = self.check_response_patterns(domain)
        if is_response_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 5
            result['evidence']['response'] = response_evidence
            print(f"    ✅ 响应内容CDN检测: {len(response_evidence)}个证据")
        
        # 9. 多地理位置检查
        print("  🌏 检查地理分布...")
        is_location_cdn, location_evidence = self.check_multiple_locations(domain)
        if is_location_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 10
            result['evidence']['location'] = location_evidence
            print(f"    ✅ 地理分布CDN检测")
        
        # 10. TTL检查
        print("  ⏱️ 检查TTL模式...")
        is_ttl_cdn, ttl_evidence = self.check_ttl_patterns(domain)
        if is_ttl_cdn:
            result['is_cdn'] = True
            result['confidence_score'] += 5
            result['evidence']['ttl'] = ttl_evidence
            print(f"    ✅ TTL模式CDN检测")
        
        # 计算总体置信度
        result['confidence_score'] = min(result['confidence_score'], 100)
        
        # 记录时间信息
        end_time = time.time()
        result['technical_details']['timing_info'] = {
            'total_time': end_time - start_time,
            'timestamp': time.time()
        }
        
        # 去重CDN提供商
        result['cdn_providers'] = list(set(result['cdn_providers']))
        
        # 输出结果
        if result['is_cdn']:
            confidence_level = "高" if result['confidence_score'] >= 70 else "中" if result['confidence_score'] >= 40 else "低"
            providers_text = f" ({', '.join(result['cdn_providers'])})" if result['cdn_providers'] else ""
            print(f"  🎯 检测结果: 使用CDN{providers_text} - 置信度: {confidence_level} ({result['confidence_score']}%)")
        else:
            print(f"  🎯 检测结果: 未检测到CDN")
        
        return result
    
    def is_cdn(self, domain: str) -> int:
        """简化接口：返回1或0"""
        result = self.comprehensive_cdn_detection(domain)
        return 1 if result['is_cdn'] else 0
    
    def batch_detection(self, domains: List[str]) -> List[Dict]:
        """批量检测"""
        results = []
        
        print(f"🚀 开始批量CDN检测，共{len(domains)}个域名")
        print("=" * 80)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self.comprehensive_cdn_detection, domain): domain 
                for domain in domains
            }
            
            for future in future_to_domain:
                domain = future_to_domain[future]
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                except Exception as e:
                    print(f"❌ {domain} 检测失败: {e}")
                    results.append({
                        'domain': domain,
                        'is_cdn': False,
                        'error': str(e)
                    })
        
        return results


def main():
    """主函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("使用方法: python advanced_cdn_detector.py <域名1> [域名2] ...")
        print("示例: python advanced_cdn_detector.py baidu.com taobao.com")
        sys.exit(1)
    
    domains = sys.argv[1:]
    detector = AdvancedCDNDetector()
    
    if len(domains) == 1:
        result = detector.comprehensive_cdn_detection(domains[0])
        print(f"\n最终结果: {result['domain']} -> {1 if result['is_cdn'] else 0}")
    else:
        results = detector.batch_detection(domains)
        print(f"\n批量检测结果:")
        for result in results:
            status = 1 if result.get('is_cdn', False) else 0
            print(f"{result['domain']} -> {status}")


if __name__ == '__main__':
    main()
