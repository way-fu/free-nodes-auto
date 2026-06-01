#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取全网免费节点（GitHub + 大厂公共爬虫 API 矩阵）
策略：GitHub 侧只负责高频去重与分组，不进行误杀率极高的云端连接测试，全量交付客户端小火箭本地测速
"""

import requests
import yaml
import base64
import json
import re
from datetime import datetime
import os

# ==================== 🚀 聚合全网超大吞吐量公开 API 与源 ====================
# 这里的源都在独立服务器上高频跑爬虫，基数极其庞大，包含了最新的各类黑科技协议
SOURCES_YAML = [
    # 1. 你原本自带的四个高质量聚合源
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/all.yaml',
    'https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml',
    'https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/clash.yaml',
    'https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml',
    
    # 2. 额外引入全网更新最疯狂、日吞吐量过千的公开机场/订阅流
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml',
    'https://raw.githubusercontent.com/learnhard-cn/free_nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/zyw75/Free-Nodes/main/Clash.yaml',
    'https://raw.githubusercontent.com/AnaZz571/Free-nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/fanyueciyuan/eclash/main/clash.yaml',
    'https://v2rayshare.github.io/v2rayshare/clash.yaml',
    'https://raw.githubusercontent.com/mianfeifq/share/main/clash.yaml'
]

def fetch_content(url, timeout=25):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"  ⚠️ 拉取失败 [{url[:35]}...]: {e}")
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
    node_type = str(node.get('type', '')).lower()
    
    if not server or not port or not isinstance(port, int): return False
    if node_type not in ['ss', 'vmess', 'vless', 'trojan']: return False
    
    # 内网伪装等死节点拦截
    private_prefixes = ('10.', '172.16.', '192.168.', '127.', 'localhost', '0.0.0.0')
    if any(str(server).startswith(p) for p in private_prefixes): return False
    return True

def deduplicate_nodes(nodes):
    seen = set()
    unique = []
    for node in nodes:
        # 提取核心唯一凭证串进行去重
        credential = node.get('uuid') or node.get('password') or node.get('cipher', '')
        key = f"{node.get('type')}://{node.get('server')}:{node.get('port')}-{credential}"
        if key not in seen:
            seen.add(key)
            unique.append(node)
    return unique

def generate_config(nodes):
    if not nodes: return None
    
    # ✨ 核心改动：把上限额度提高到 120 个！
    # 只要是不重复的活格式，全部放行塞进文件，给小火箭提供充足的备弹
    max_total = 120
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
    print("=" * 60)
    print("📥 开始拉取全网最新大厂爬虫 API 节点流...")
    print("=" * 60)
    all_nodes = []
    
    for url in SOURCES_YAML:
        content = fetch_content(url)
        if content:
            proxies = parse_clash_yaml(content)
            all_nodes.extend(proxies)
            print(f"   ➕ 成功抓取源 [{url[8:30]}...] 节点数: {len(proxies)}")
            
    # 基础校验与全球唯一特征强力去重
    valid_format = [n for n in all_nodes if format_validate(n)]
    unique_nodes = deduplicate_nodes(valid_format)
    print(f"\n📊 矩阵去重完成。当前总有效候选池规模: {len(unique_nodes)} 个节点")
    
    # 彻底不做云端测速，直接打包，不杀错任何一个潜在可用的好节点
    config = generate_config(unique_nodes)
    if config:
        os.makedirs('output', exist_ok=True)
        with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': config['proxies']}, f, allow_unicode=True)
        with open('output/stats.json', 'w', encoding='utf-8') as f:
            json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(config['proxies'])}, f, indent=2)
        print(f"\n✨ 大功告成！已将 {len(config['proxies'])} 个全网热活节点整理并分类写入策略组文件。")
        return 0
    else:
        print("❌ 未捕获到有效节点。")
        return 1

if __name__ == '__main__':
    exit(main())
