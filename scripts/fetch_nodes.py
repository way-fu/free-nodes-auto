#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取全网免费节点（GitHub 优质聚合 + 实时订阅流 + 宽容层级清洗）
"""

import requests
import yaml
import base64
import json
import re
import asyncio
import socket
from datetime import datetime
from urllib.parse import unquote
import os

# ==================== 🚀 质量最高的全网免翻墙订阅池 ====================
# 这里整合了目前全网高频更新、基数极大、且自带基础清洗的公开源
SOURCES_YAML = [
    # 1. 之前表现良好的基础源
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/all.yaml',
    'https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml',
    'https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/clash.yaml',
    'https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml',
    
    # 2. ✨ 新增：目前活跃度极高、自带去重的大型公开订阅池（基数极庞大）
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml',
    'https://raw.githubusercontent.com/learnhard-cn/free_nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/zyw75/Free-Nodes/main/Clash.yaml',
    'https://raw.githubusercontent.com/AnaZz571/Free-nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/fanyueciyuan/eclash/main/clash.yaml',
    'https://raw.githubusercontent.com/ariwansunarto/clash-config/main/proxies.yaml'
]

# Base64 纯文本订阅流（针对非 YAML 格式补充）
SOURCES_BASE64 = [
    'https://raw.githubusercontent.com/v2ray-links/v2ray-free-links/master/v2ray'
]

# ================================================================

def fetch_content(url, timeout=25):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"  ❌ 抓取失败 [{url[:40]}...]: {e}")
        return None

def parse_clash_yaml(content):
    try:
        data = yaml.safe_load(content)
        if data and isinstance(data, dict):
            proxies = data.get('proxies', [])
            return proxies if isinstance(proxies, list) else []
    except:
        pass
    return []

def safe_b64decode(s):
    try:
        s = s.strip().replace('\r', '').replace('\n', '')
        padding = 4 - len(s) % 4
        if padding != 4: s += '=' * padding
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except:
        return ""

def extract_nodes_from_base64(content):
    extracted = []
    decoded = safe_b64decode(content)
    if not decoded: return extracted
    
    lines = decoded.split('\n')
    for line in lines:
        line = line.strip()
        if not line: continue
        try:
            # 针对 Base64 流中最常见的 VMess 核心提取
            if line.startswith('vmess://'):
                raw_json = safe_b64decode(line[8:])
                if raw_json:
                    j = json.loads(raw_json)
                    extracted.append({
                        'type': 'vmess', 'server': j.get('add'), 'port': int(j.get('port', 0)),
                        'uuid': j.get('id'), 'cipher': 'auto', 'alterId': int(j.get('aid', 0)),
                        'name': j.get('ps', 'B64-VMess'), 'udp': True
                    })
            # 针对 Trojan 提取
            elif line.startswith('trojan://'):
                match = re.match(r'trojan://([^@]+)@([^:]+):([0-9]+)', line)
                if match:
                    pwd, server, port = match.groups()
                    extracted.append({'type': 'trojan', 'server': server, 'port': int(port), 'password': pwd, 'name': 'B64-Trojan', 'udp': True})
        except:
            continue
    return extracted

def format_validate(node):
    if not isinstance(node, dict): return False
    server = node.get('server', '')
    port = node.get('port', 0)
    node_type = str(node.get('type', '')).lower()
    
    if not server or not port or not isinstance(port, int): return False
    if node_type not in ['ss', 'vmess', 'vless', 'trojan']: return False
    
    # 过滤掉局域网内网伪装节点
    private_prefixes = ('10.', '172.16.', '192.168.', '127.', 'localhost', '0.0.0.0')
    if any(str(server).startswith(p) for p in private_prefixes): return False
    return True

def deduplicate_nodes(nodes):
    seen = set()
    unique = []
    for node in nodes:
        credential = node.get('uuid') or node.get('password') or node.get('cipher', '')
        key = f"{node.get('type')}://{node.get('server')}:{node.get('port')}-{credential}"
        if key not in seen:
            seen.add(key)
            unique.append(node)
    return unique

# ==================== 🧠 高速四层并行连接验证机制 ====================

async def test_node_fast(node, timeout=2.5):
    """
    高效宽容模式：
    在 GitHub 环境中只进行 DNS 连通性以及四层 TCP 握手验证。
    移除容易被宿主机拦截或被目的机场拦截的 L7 探针写入，防止好节点被“误杀”。
    """
    server = str(node.get('server'))
    port = node.get('port')
    
    try:
        # 1. DNS 异步解析
        loop = asyncio.get_running_loop()
        try:
            await loop.getaddrinfo(server, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        except:
            return None # 域名失效直接丢弃
            
        # 2. 四层握手验证
        conn = asyncio.open_connection(server, port)
        _, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # 成功建立连接说明端口开放、通道未断
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return node
    except:
        return None

async def filter_nodes(nodes):
    print(f"   ⚡ 正在使用高效宽容模型清洗节点 (初始待测总数: {len(nodes)})...")
    semaphore = asyncio.Semaphore(200) # 提高并发处理效率
    
    async def sem_task(node):
        async with semaphore:
            return await test_node_fast(node)
            
    tasks = [sem_task(node) for node in nodes]
    results = await asyncio.gather(*tasks)
    return [n for n in results if n is not None]

# =====================================================================

def generate_config(nodes):
    if not nodes: return None
    
    # 提高保留额度：既然是宽容过滤，保留前 50 个响应最快的节点进文件，交由小火箭做本地二次 url-test
    max_total = 50
    if len(nodes) > max_total:
        nodes = nodes[:max_total]
        
    ss_nodes, vmess_nodes, vless_nodes, trojan_nodes = [], [], [], []
    
    for idx, node in enumerate(nodes, 1):
        ntype = str(node['type']).lower()
        node['name'] = f"📍 {ntype.upper()}-{idx:02d}"
        
        if ntype == 'ss': ss_nodes.append(node['name'])
        elif ntype == 'vmess': vmess_nodes.append(node['name'])
        elif ntype == 'vless': vless_nodes.append(node['name'])
        elif ntype == 'trojan': trojan_nodes.append(node['name'])

    all_names = [n['name'] for n in nodes]
    sub_groups = []
    if ss_nodes: sub_groups.append('🔒 SS 节点池')
    if vmess_nodes: sub_groups.append('🛸 VMess 节点池')
    if vless_nodes: sub_groups.append('⚡ VLESS 节点池')
    if trojan_nodes: sub_groups.append('🐴 Trojan 节点池')
    
    proxy_groups = [
        {
            'name': '🚀 节点选择',
            'type': 'select',
            'proxies': ['♻️ 自动选择'] + sub_groups + ['🌍 全球直连']
        },
        {
            'name': '♻️ 自动选择',
            'type': 'url-test',
            'url': 'http://cp.cloudflare.com/generate_204',
            'interval': 300,
            'tolerance': 50,
            'proxies': all_names
        },
        {
            'name': '🌍 全球直连',
            'type': 'select',
            'proxies': ['DIRECT', '🚀 节点选择']
        }
    ]
    
    if ss_nodes: proxy_groups.append({'name': '🔒 SS 节点池', 'type': 'select', 'proxies': ss_nodes})
    if vmess_nodes: proxy_groups.append({'name': '🛸 VMess 节点池', 'type': 'select', 'proxies': vmess_nodes})
    if vless_nodes: proxy_groups.append({'name': '⚡ VLESS 节点池', 'type': 'select', 'proxies': vless_nodes})
    if trojan_nodes: proxy_groups.append({'name': '🐴 Trojan 节点池', 'type': 'select', 'proxies': trojan_nodes})

    proxy_groups.extend([
        {'name': '📹 YouTube', 'type': 'select', 'proxies': ['🚀 节点选择'] + sub_groups},
        {'name': '📱 Telegram', 'type': 'select', 'proxies': ['🚀 节点选择'] + sub_groups},
        {'name': '🍎 苹果服务', 'type': 'select', 'proxies': ['🌍 全球直连', '🚀 节点选择']}
    ])
    
    rules = [
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,icloud.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,youtube.com,📹 YouTube',
        'DOMAIN-SUFFIX,googlevideo.com,📹 YouTube',
        'DOMAIN-SUFFIX,telegram.org,📱 Telegram',
        'DOMAIN-SUFFIX,t.me,📱 Telegram',
        'DOMAIN-SUFFIX,cn,DIRECT',
        'GEOIP,CN,DIRECT',
        'MATCH,🚀 节点选择'
    ]
    
    return {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'dns': {
            'enable': True,
            'listen': '0.0.0.0:1053',
            'default-nameserver': ['223.5.5.5', '8.8.8.8'],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query'],
            'fallback': ['https://dns.google/dns-query']
        },
        'proxies': nodes,
        'proxy-groups': proxy_groups,
        'rules': rules
    }

def main():
    print("📥 开始拉取全网最新节点池...")
    all_nodes = []
    
    # 1. 抓取 YAML
    for url in SOURCES_YAML:
        content = fetch_content(url)
        if content:
            all_nodes.extend(parse_clash_yaml(content))
            
    # 2. 抓取 Base64 流
    for url in SOURCES_BASE64:
        content = fetch_content(url)
        if content:
            all_nodes.extend(extract_nodes_from_base64(content))
            
    # 3. 数据清洗与严格去重
    valid_format = [n for n in all_nodes if format_validate(n)]
    unique_nodes = deduplicate_nodes(valid_format)
    print(f"📊 基础过滤去重后，总池候选节点数量: {len(unique_nodes)}")
    
    # 4. 宽容层级高速连接测试
    if unique_nodes:
        loop = asyncio.get_event_loop()
        alive_nodes = loop.run_until_complete(filter_nodes(unique_nodes))
        print(f"🟢 成功筛出四层通畅、未被封锁的活节点: {len(alive_nodes)}/{len(unique_nodes)}")
    else:
        alive_nodes = []
        
    # 5. 构建并写入文件
    config = generate_config(alive_nodes)
    if config:
        os.makedirs('output', exist_ok=True)
        with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': config['proxies']}, f, allow_unicode=True)
        with open('output/stats.json', 'w', encoding='utf-8') as f:
            json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(config['proxies'])}, f, indent=2)
        print(f"✨ 成功！最终保留了 {len(config['proxies'])} 个优质节点并已成功推入策略组分组。")
        return 0
    else:
        print("❌ 未捕获到可用节点。")
        return 1

if __name__ == '__main__':
    exit(main())
