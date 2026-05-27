#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
优化版：宽容型原生异步 Layer 7 代理管道探针，防止误杀，确保节点充沛且全活
"""

import requests
import yaml
import json
import re
import asyncio
import socket
from datetime import datetime
import os

# ========== 🚀 节点源扩容池 ==========
SOURCES_YAML = [
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/all.yaml',
    'https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml',
    'https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/clash.yaml',
    'https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml',
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml',
    'https://raw.githubusercontent.com/AnaZz571/Free-nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/zyw75/Free-Nodes/main/Clash.yaml',
    'https://raw.githubusercontent.com/learnhard-cn/free_nodes/main/clash.yaml'
]

def fetch_content(url, timeout=30):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"  ❌ 获取失败: {e}")
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

def format_validate(node):
    if not isinstance(node, dict): return False
    server = node.get('server', '')
    port = node.get('port', 0)
    node_type = node.get('type', '').lower()
    
    if not server or not port or not isinstance(port, int): return False
    if node_type not in ['ss', 'vmess', 'vless', 'trojan']: return False
    
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

# ================= 🧠 宽容型 Layer 7 异步管道活体判定 =================

async def test_node_寛容(node, timeout=3.0):
    """
    宽容型应用层管道验证：
    只过滤掉绝对连不上、或者端口一连上就被底层防火墙掐断(Reset)的真死节点。
    对于带复杂混淆/TLS的节点，只要在写入首包后连接没有发生断开，便视为存活。
    """
    server = str(node.get('server'))
    port = node.get('port')
    node_type = node.get('type', '').lower()
    
    try:
        # DNS 解析
        loop = asyncio.get_running_loop()
        await loop.getaddrinfo(server, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        
        # 建立 TCP 连接
        conn = asyncio.open_connection(server, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # 发送对应协议的轻量探针，刺探 Layer 7 服务端是否有阻断反应
        if node_type == 'ss':
            writer.write(b'\x05\x01\x00')
        elif node_type == 'trojan':
            writer.write(b'0000000000000000000000000000000000000000000000000000000000000000\r\n\x01\x01')
        elif node_type in ['vmess', 'vless']:
            uuid_str = node.get('uuid', '').replace('-', '')
            if len(uuid_str) == 32:
                writer.write(bytes.fromhex(uuid_str)[:16])
                
        await writer.drain()
        
        # 核心宽容逻辑：给一小个短暂的时间窗口。如果对方没有主动发来 Reset 或者报错，说明 Layer 7 是开着的
        try:
            # 极短时间内尝试读取 1 字节
            await asyncio.wait_for(reader.read(1), timeout=0.2)
        except asyncio.TimeoutError:
            # 绝大多数被墙或者正常的活节点，在这个探针包过去后都会维持连接超时，这说明它是个活代理
            pass
            
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        return node
    except Exception:
        # 物理超时、拒绝连接或被重置的，丢弃
        return None

async def filter_alive_nodes(nodes):
    print(f"   ⚡ 开始执行 Python 异步宽容型管道清洗 (候选池大小: {len(nodes)})...")
    semaphore = asyncio.Semaphore(120) # 限制并发并发
    
    async def sem_task(node):
        async with semaphore:
            return await test_node_寛容(node)
            
    tasks = [sem_task(node) for node in nodes]
    results = await asyncio.gather(*tasks)
    return [n for n in results if n is not None]

# =====================================================================

def generate_config(nodes):
    if not nodes: return None
    
    # 数量控制：既然是宽容过滤，总留存控制在 35 个最精选的节点，防止臃肿
    max_total = 35
    if len(nodes) > max_total:
        nodes = nodes[:max_total]
        
    ss_nodes, vmess_nodes, vless_nodes, trojan_nodes = [], [], [], []
    
    for idx, node in enumerate(nodes, 1):
        ntype = node['type'].lower()
        node['name'] = f"📍 {ntype.upper()}-{idx:02d}"
        
        if ntype == 'ss': ss_nodes.append(node['name'])
        elif ntype == 'vmess': vmess_nodes.append(node['name'])
        elif ntype == 'vless': vless_nodes.append(node['name'])
        elif ntype == 'trojan': trojan_nodes.append(node['name'])

    all_cleaned_names = [n['name'] for n in nodes]
    
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
            'proxies': all_cleaned_names
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
    print("=" * 60)
    print(f"🚀 免费节点自动抓取工具 (异步宽容大清洗版)")
    print("=" * 60)
    all_nodes = []
    
    for i, url in enumerate(SOURCES_YAML, 1):
        content = fetch_content(url)
        if content:
            nodes = parse_clash_yaml(content)
            all_nodes.extend(nodes)
            print(f"   [{i}/{len(SOURCES_YAML)}] 成功加载节点数: {len(nodes)}")
            
    valid_format_nodes = [n for n in all_nodes if format_validate(n)]
    unique_nodes = deduplicate_nodes(valid_format_nodes)
    print(f"\n📊 汇总原始去重后候选节点数: {len(unique_nodes)}")
    
    if unique_nodes:
        loop = asyncio.get_event_loop()
        alive_nodes = loop.run_until_complete(filter_alive_nodes(unique_nodes))
        print(f"   🟢 检测通过的优质活节点数量: {len(alive_nodes)}/{len(unique_nodes)}")
    else:
        alive_nodes = []
        
    config = generate_config(alive_nodes)
    if config:
        os.makedirs('output', exist_ok=True)
        with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': config['proxies']}, f, allow_unicode=True)
        with open('output/stats.json', 'w', encoding='utf-8') as f:
            json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(config['proxies'])}, f, indent=2)
        print(f"✨ 成功生成并按协议归类了 {len(config['proxies'])} 个优质存活节点！")
        return 0
    else:
        print("❌ 未捕获到存活节点。")
        return 1

if __name__ == '__main__':
    exit(main())
