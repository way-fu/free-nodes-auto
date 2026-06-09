#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
【终极落盘拦截版】无论上层逻辑如何多变，在文件写入的最后一刻强行砍成 25 个
"""

import requests
import yaml
import json
import os
import re
from datetime import datetime

SOURCES_YAML = [
    'https://cdn.jsdelivr.net/gh/goer998/Free-nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/learnhard-cn/free_nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/tiamg/free-nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/V2rayShare/V2rayShare@master/clash.yaml',
    'https://cdn.jsdelivr.net/gh/baipiao-pool/baipiao@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/w1770946466/Auto_Free_Nodes@main/run/clash.yaml',
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/history.yaml',
    'https://v2rayshare.github.io/v2rayshare/clash.yaml',
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml'
]

def fetch_content(url, timeout=25):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200: return response.text
    except Exception: pass
    return None

def parse_clash_yaml(content):
    if not content: return []
    try:
        sanitized_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)
        data = yaml.safe_load(sanitized_content)
        if data and isinstance(data, dict):
            proxies = data.get('proxies', [])
            return proxies if isinstance(proxies, list) else []
    except Exception: pass
    return []

def format_validate_and_sanitize(node):
    if not isinstance(node, dict): return None
    server = node.get('server', '')
    port = node.get('port', 0)
    node_type = str(node.get('type', '')).lower()
    if not server or not port or not isinstance(port, int): return None
    if node_type not in ['ss', 'vmess', 'vless', 'trojan']: return None
    node['udp'] = True
    return node

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

def generate_config(nodes):
    if not nodes: return None
    
    # 🌟 核心防御 1：不管上层传进来了多少，在这里再次死死卡住 25 个
    if len(nodes) > 25:
        nodes = nodes[:25]
        
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
        {'name': '🚀 节点选择', 'type': 'select', 'proxies': ['♻️ 自动选择'] + sub_groups + ['🌍 全球直连']},
        {'name': '♻️ 自动选择', 'type': 'url-test', 'url': 'http://cp.cloudflare.com/generate_204', 'interval': 150, 'tolerance': 60, 'proxies': all_names},
        {'name': '🌍 全球直连', 'type': 'select', 'proxies': ['DIRECT', '🚀 节点选择']}
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
    
    return {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
        'proxies': nodes, 'proxy-groups': proxy_groups, 'rules': ['MATCH,🚀 节点选择']
    }

def main():
    print("📥 开始调度最新活性节点源...")
    all_nodes = []
    for url in SOURCES_YAML:
        content = fetch_content(url)
        if content:
            proxies = parse_clash_yaml(content)
            for p in proxies:
                sanitized = format_validate_and_sanitize(p)
                if sanitized: all_nodes.append(sanitized)
            
    unique_nodes = deduplicate_nodes(all_nodes)
    
    # 🌟 核心防御 2：元数据处切片
    if len(unique_nodes) > 25:
        unique_nodes = unique_nodes[:25]
        
    config = generate_config(unique_nodes)
    if config:
        # 🌟 核心防御 3：在写入文件的最后 0.1 秒，进行物理死锁强洗
        if 'proxies' in config and len(config['proxies']) > 25:
            config['proxies'] = config['proxies'][:25]
            
        os.makedirs('output', exist_ok=True)
        try:
            # 强制覆盖 nodes.yaml
            with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            
            # 强制覆盖 proxies.yaml
            with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
                yaml.dump({'proxies': config['proxies']}, f, allow_unicode=True)
                
            return 0
        except Exception:
            return 1
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
