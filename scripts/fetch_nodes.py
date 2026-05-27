#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
优化版：专注去重与结构化协议分组，CONNECT 测试交由工作流环境或客户端
"""

import requests
import yaml
import json
import re
from datetime import datetime
import os

# ========== 🚀 节点源扩容池（全网精选高频维护源） ==========
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

def generate_config(nodes):
    if not nodes:
        return None
    
    # 限制留存总数在 40 个内（防止小火箭里滑不到底）
    max_total = 40
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
    print("📥 开始多源并行爬取...")
    all_nodes = []
    for i, url in enumerate(SOURCES_YAML, 1):
        content = fetch_content(url)
        if content:
            nodes = parse_clash_yaml(content)
            all_nodes.extend(nodes)
            print(f"   [{i}/{len(SOURCES_YAML)}] 成功加载节点数: {len(nodes)}")
            
    # 基础过滤与严格去重
    valid_format_nodes = [n for n in all_nodes if format_validate(n)]
    unique_nodes = deduplicate_nodes(valid_format_nodes)
    print(f"📊 去重后可供测试的候选节点总数: {len(unique_nodes)}")
    
    # 临时将去重后的丰富样本保存为临时配置文件
    # 让下一阶段的工作流直接用专业测速工具去洗它们
    config = generate_config(unique_nodes)
    if config:
        os.makedirs('output', exist_ok=True)
        with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print("💾 临时总池已生成，准备交给测试器...")
        return 0
    return 1

if __name__ == '__main__':
    exit(main())
