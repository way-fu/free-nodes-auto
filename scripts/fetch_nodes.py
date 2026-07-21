#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadowrocket 节点爬虫 (优化高可用版)
✨ 优化点：并发高效 TCP Ping、正确域名解析、先测后筛选、精准协议提取
"""

import requests
import base64
import json
import os
import re
import socket
import time
from datetime import datetime
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== 📡 更新高可用节点源配置 ====================
SOURCES = [
    'https://raw.githubusercontent.com/free18/v2ray/main/v.txt',
    'https://raw.githubusercontent.com/freefq/free/master/v2',
    'https://raw.githubusercontent.com/v2ray-links/v2ray-free-node/main/v2ray',
    'https://raw.githubusercontent.com/m2ray/v2ray/main/v2ray',
    'https://raw.githubusercontent.com/Pawroid/Free-Servers/main/sub',
    'https://raw.githubusercontent.com/er26/free/main/v2ray',
]

def fetch_with_retry(url, timeout=10, retries=2):
    """带重试的网络请求"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                return response.text.strip()
        except Exception:
            if attempt < retries - 1:
                continue
    return ""

def parse_nodes(content):
    """解析 Base64 或明文文本中的节点"""
    nodes = []
    if not content:
        return nodes
    
    decoded_content = content
    # 尝试 Base64 解码
    try:
        missing_padding = len(content) % 4
        test_content = content + '=' * (4 - missing_padding) if missing_padding else content
        decoded_text = base64.b64decode(test_content).decode('utf-8', errors='ignore')
        if any(proto in decoded_text for proto in ['vmess://', 'ss://', 'vless://', 'trojan://']):
            decoded_content = decoded_text
    except Exception:
        pass
    
    # 匹配节点链接
    patterns = [
        r'vmess://[A-Za-z0-9+/=\-_]+',
        r'ss://[A-Za-z0-9+/=\-_%@:\.\?\#]+',
        r'vless://[A-Za-z0-9+/=\-_%@:\.\?\#]+',
        r'trojan://[A-Za-z0-9+/=\-_%@:\.\?\#]+',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, decoded_content)
        nodes.extend(matches)
    
    return list(set(nodes))

class NodeTester:
    """节点提取与延迟测试"""
    
    def __init__(self, timeout=3, max_workers=30):
        self.timeout = timeout
        self.max_workers = max_workers

    def parse_vmess(self, node_str):
        try:
            payload = node_str.replace('vmess://', '')
            missing_padding = len(payload) % 4
            if missing_padding:
                payload += '=' * (4 - missing_padding)
            decoded = base64.b64decode(payload).decode('utf-8')
            data = json.loads(decoded)
            host = data.get('add') or data.get('server')
            port = data.get('port')
            return host, int(port) if port else None
        except Exception:
            return None, None

    def parse_url_style(self, node_str):
        """解析 ss, vless, trojan 类型的节点"""
        try:
            url = urlparse(node_str)
            host = url.hostname
            port = url.port
            
            # 兼容 SS 标准 Base64 编码的 userinfo
            if not host and node_str.startswith('ss://'):
                # ss://BASE64@host:port
                main_part = node_str.replace('ss://', '').split('#')[0]
                if '@' in main_part:
                    user_info, server_info = main_part.rsplit('@', 1)
                    if ':' in server_info:
                        host, port = server_info.split(':')
                        return host, int(port)
            return host, port
        except Exception:
            return None, None

    def extract_host_port(self, node_str):
        if node_str.startswith('vmess://'):
            return self.parse_vmess(node_str)
        else:
            return self.parse_url_style(node_str)

    def tcp_ping(self, host, port):
        """TCP 建连测速"""
        if not host or not port:
            return None
        
        start_time = time.time()
        try:
            # 采用 getaddrinfo 避免 dns 卡死
            ip = socket.gethostbyname(host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.close()
            latency = (time.time() - start_time) * 1000
            return latency
        except Exception:
            return None

    def test_single_node(self, node_str):
        protocol = node_str.split('://')[0] if '://' in node_str else 'unknown'
        host, port = self.extract_host_port(node_str)
        
        if not host or not port:
            return {'node': node_str, 'protocol': protocol, 'latency': 9999, 'status': '❌ 解析失败', 'host': host, 'port': port}
        
        latency = self.tcp_ping(host, port)
        if latency is not None:
            status = '✅ 可用'
            return {'node': node_str, 'protocol': protocol, 'latency': latency, 'status': status, 'host': host, 'port': port}
        else:
            return {'node': node_str, 'protocol': protocol, 'latency': 9999, 'status': '❌ 连接超时', 'host': host, 'port': port}

    def test_nodes(self, nodes):
        results = []
        print(f"⚡ 开始并发测速（使用 {self.max_workers} 个线程，超时时间 {self.timeout}s）...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.test_single_node, node) for node in nodes]
            completed = 0
            total = len(nodes)
            
            for future in as_completed(futures):
                res = future.result()
                results.append(res)
                completed += 1
                if completed % 10 == 0 or completed == total:
                    print(f"  进度: [{completed}/{total}] ...", end='\r')
        
        print("\n")
        # 按延迟从低到高排序
        results.sort(key=lambda x: x['latency'])
        return results

def main():
    print("🚀 Shadowrocket 节点爬虫 v3 (优化版) 启动...\n")
    
    all_nodes = []
    print("📥 采集节点中...")
    for idx, url in enumerate(SOURCES, 1):
        content = fetch_with_retry(url)
        if content:
            nodes = parse_nodes(content)
            all_nodes.extend(nodes)
            print(f"  [{idx}/{len(SOURCES)}] {url.split('/')[-1]} -> 获取 {len(nodes)} 个节点")
        else:
            print(f"  [{idx}/{len(SOURCES)}] {url.split('/')[-1]} -> ⚠️ 抓取失败/为空")
    
    unique_nodes = list(set(all_nodes))
    print(f"\n📊 抓取去重完成，共 {len(unique_nodes)} 个待测节点")
    if not unique_nodes:
        print("❌ 未获取到任何节点，退出。")
        return 1

    # ⚠️ 关键修改：测速所有节点，不再提前截断 25 个
    tester = NodeTester(timeout=3, max_workers=50)
    test_results = tester.test_nodes(unique_nodes)
    
    # 筛选可用节点 (延迟 < 3000ms)
    available_results = [r for r in test_results if r['latency'] < 3000]
    
    print(f"📊 测速完成:")
    print(f"  ✅ 最终可用节点: {len(available_results)} 个")
    print(f"  ❌ 死节点/不可达: {len(test_results) - len(available_results)} 个")

    if not available_results:
        print("❌ 很遗憾，本次未检测到可通畅连接的节点。请检查本地网络环境或稍后再试。")
        return 1

    # 取前 50 个延迟最低的最佳节点
    final_results = available_results[:50]
    valid_nodes = [r['node'] for r in final_results]

    # 保存文件
    os.makedirs('output', exist_ok=True)
    
    # Base64 订阅
    base64_content = base64.b64encode('\n'.join(valid_nodes).encode('utf-8')).decode('utf-8')
    with open('output/nodes_base64.txt', 'w', encoding='utf-8') as f:
        f.write(base64_content)
        
    # 明文列表
    with open('output/nodes_plain.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_nodes))

    print(f"\n✨ 已将最好的 {len(valid_nodes)} 个节点输出至 ./output/ 目录：")
    print(f"  • output/nodes_base64.txt  (Shadowrocket 订阅用)")
    print(f"  • output/nodes_plain.txt   (明文列表)")
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
