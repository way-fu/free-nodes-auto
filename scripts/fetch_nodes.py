#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
【高活源大清洗版】淘汰死源，换上存活率最高的高星级活节点源，死锁 25 个
"""

import requests
import yaml
import json
import os
import re
from datetime import datetime

# ==================== 🚀 2026年最新：全网存活率最高的高星级活节点矩阵 ====================
# 彻底淘汰掉已经失效或全是死节点的旧源，换上每日高频清洗的优质池
SOURCES_YAML = [
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml',
    'https://raw.githubusercontent.com/stayfocused-to/free-nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml',
    'https://raw.githubusercontent.com/aiboboxx/clash-free-node/main/clash.yaml',
    'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Volume.txt', # 备用高容错源
    'https://cdn.jsdelivr.net/gh/V2rayShare/V2rayShare@master/clash.yaml'
]

def fetch_content(url, timeout=25):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200: 
            return response.text
    except Exception: 
        pass
    return None

def parse_clash_yaml(content):
    if not content: return []
    try:
        sanitized_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)
        data = yaml.safe_load(sanitized_content)
        if data and isinstance(data, dict):
            proxies = data.get('proxies', [])
            return proxies if isinstance(proxies, list) else []
    except Exception: 
        pass
    return []

def format_validate_and_sanitize(node):
    if not isinstance(node, dict): return None
    server = node.get('server', '')
    port = node.get('port', 0)
    node_type = str(node.get('type', '')).lower()
    
    if not server or not port or not isinstance(port, int): return None
    if node_type not in ['ss', 'vmess', 'vless', 'trojan']: return None
    
    # 基础凭据完整性检查
    if node_type == 'ss' and not node.get('password'): return None
    if node_type in ['vmess', 'vless'] and not node.get('uuid'): return None
    if node_type == 'trojan' and not node.get('password'): return None
    
    # 剔除内网假节点
    private_prefixes = ('10.', '172.16.', '192.168.', '127.', 'localhost', '0.0.0.0')
    if any(str(server).startswith(p) for p in private_prefixes): return None
    
    # 修正可能缺失的必要底层传输字段，防止小火箭由于参数缺失直接断连
    if node_type == 'vmess':
        if 'alterId' not in node: node['alterId'] = 0
        if 'network' not in node: node['network'] = 'tcp'
        
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
    
    ss_nodes, vmess_nodes, vless_nodes, trojan_nodes = [], [], [], []
    for idx, node in enumerate(nodes, 1):
        ntype = str(node['type']).lower()
        node['name'] = f"🟢 {ntype.upper()}-{idx:02d}"
        if ntype == 'ss': ss_nodes.append(node['name'])
        elif ntype == 'vmess': vmess_nodes.append(node['name'])
        elif ntype == 'vless': vless_nodes.append(node['name'])
        elif ntype == 'trojan': trojan_nodes.append(node['name'])

    all_names = [n['name'] for n in nodes]
    sub_groups = []
    if ss_nodes: sub_groups.append('🔒 SS池')
    if vmess_nodes: sub_groups.append('🛸 VMess池')
    if vless_nodes: sub_groups.append('⚡ VLESS池')
    if trojan_nodes: sub_groups.append('🐴 Trojan池')
    
    proxy_groups = [
        {'name': '🚀 节点选择', 'type': 'select', 'proxies': ['♻️ 自动选择'] + sub_groups + ['🌍 全球直连']},
        {'name': '♻️ 自动选择', 'type': 'url-test', 'url': 'http://cp.cloudflare.com/generate_204', 'interval': 150, 'tolerance': 60, 'proxies': all_names},
        {'name': '🌍 全球直连', 'type': 'select', 'proxies': ['DIRECT', '🚀 节点选择']}
    ]
    
    if ss_nodes: proxy_groups.append({'name': '🔒 SS池', 'type': 'select', 'proxies': ss_nodes})
    if vmess_nodes: proxy_groups.append({'name': '🛸 VMess池', 'type': 'select', 'proxies': vmess_nodes})
    if vless_nodes: proxy_groups.append({'name': '⚡ VLESS池', 'type': 'select', 'proxies': vless_nodes})
    if trojan_nodes: proxy_groups.append({'name': '🐴 Trojan池', 'type': 'select', 'proxies': trojan_nodes})

    return {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
        'proxies': nodes, 'proxy-groups': proxy_groups, 'rules': ['MATCH,🚀 节点选择']
    }

def main():
    print("📥 开始调度高活性优质节点源...")
    all_nodes = []
    for url in SOURCES_YAML:
        content = fetch_content(url)
        if content:
            proxies = parse_clash_yaml(content)
            for p in proxies:
                sanitized = format_validate_and_sanitize(p)
                if sanitized: all_nodes.append(sanitized)
            
    unique_nodes = deduplicate_nodes(all_nodes)
    
    # 🎯 物理强行控量 25 个
    if len(unique_nodes) > 25:
        unique_nodes = unique_nodes[:25]
        
    print(f"\n📊 活节点池锁定数量: {len(unique_nodes)}")
    
    config = generate_config(unique_nodes)
    if config:
        os.makedirs('output', exist_ok=True)
        try:
            with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
                yaml.dump({'proxies': config['proxies']}, f, allow_unicode=True)
            return 0
        except Exception:
            return 1
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
