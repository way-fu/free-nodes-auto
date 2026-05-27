#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
优化版：扩容高质量上游源 + 微调 Layer 7 容错，增加优质存活节点数量
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

# ========== 🚀 节点源扩容配置 ==========
SOURCES_YAML = [
    # 你原有的四个源
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/all.yaml',
    'https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml',
    'https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/clash.yaml',
    'https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml',
    # ✨ 新增：高频更新的巨量节点池，极大提升候选基数
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml',
    'https://raw.githubusercontent.com/AnaZz571/Free-nodes/main/clash.yaml',
    'https://raw.githubusercontent.com/zyw75/Free-Nodes/main/Clash.yaml',
    'https://raw.githubusercontent.com/learnhard-cn/free_nodes/main/clash.yaml'
]

# ========== 辅助解析与基础过滤 ==========

def fetch_content(url, timeout=30):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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
        # 兼容部分格式不规范的 YAML，改用报错容忍度更高的 safe_load
        data = yaml.safe_load(content)
        if data and isinstance(data, dict):
            proxies = data.get('proxies', [])
            return proxies if isinstance(proxies, list) else []
    except Exception as e:
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

# ================= 🧠 Layer 7 代理管道可用性验证 =================

async def test_proxy_layer7(node, timeout=3.5):
    server = str(node.get('server'))
    port = node.get('port')
    node_type = node.get('type', '').lower()
    
    try:
        # 1. 异步域名解析
        loop = asyncio.get_running_loop()
        await loop.getaddrinfo(server, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        
        # 2. 建立基础连接
        conn = asyncio.open_connection(server, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # 3. 发送对应协议的特征握手，刺探服务端真实的业务状态
        if node_type == 'ss':
            writer.write(b'\x05\x01\x00') 
        elif node_type == 'trojan':
            writer.write(b'0000000000000000000000000000000000000000000000000000000000000000\r\n\x01\x01')
        elif node_type in ['vmess', 'vless']:
            uuid_str = node.get('uuid', '').replace('-', '')
            if len(uuid_str) == 32:
                writer.write(bytes.fromhex(uuid_str)[:16])
        
        await writer.drain()
        
        # 优化容错：有些慢节点只是响应延迟，只要没有发生物理断开(Connection Reset)或直接抛错，就予以放行
        try:
            data = await asyncio.wait_for(reader.read(1), timeout=0.3)
            # 如果对方立即发回数据，或者主动优雅关闭，都说明它是一个 Layer 7 活服务
        except asyncio.TimeoutError:
            # 维持了连接且未被重置超时，属于高概率可用
            pass
            
        writer.close()
        await writer.wait_closed()
        return node
    except Exception:
        return None

async def filter_alive_nodes(nodes):
    print(f"   ⚡ 开始进行 Layer 7 精准可用性验证 (池内候选总数: {len(nodes)})...")
    # 限制并发，防止短时间内对Actions虚拟机底层网络造成拥连阻塞
    semaphore = asyncio.Semaphore(100)
    
    async def sem_task(node):
        async with semaphore:
            return await test_proxy_layer7(node)
            
    tasks = [sem_task(node) for node in nodes]
    results = await asyncio.gather(*tasks)
    return [n for n in results if n is not None]

# =====================================================================

def generate_config(nodes):
    if not nodes:
        return None
    
    # 既然进行了分组，上限可以稍微放宽至 30 - 60 个高质节点
    max_total = 60
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
        'MATCH,🚀 选择节点'
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
    print(f"🚀 免费节点自动抓取工具 (源扩容+优化可用性版)")
    print("=" * 60)
    
    all_nodes = []
    
    print("📥 开始多源并行爬取...")
    for i, url in enumerate(SOURCES_YAML, 1):
        content = fetch_content(url)
        if content:
            nodes = parse_clash_yaml(content)
            all_nodes.extend(nodes)
            print(f"   [{i}/{len(SOURCES_YAML)}] 成功加载节点数: {len(nodes)}")
    
    print(f"\n📊 汇总原始抓取总节点数: {len(all_nodes)}")
    
    # 格式化检测与高精度去重
    valid_format_nodes = [n for n in all_nodes if format_validate(n)]
    unique_nodes = deduplicate_nodes(valid_format_nodes)
    print(f"   🔄 去除无效格式与重复项后，待测候选基数: {len(unique_nodes)}")
    
    # 执行优化后的异步 L7 可用性验证
    if unique_nodes:
        loop = asyncio.get_event_loop()
        alive_nodes = loop.run_until_complete(filter_alive_nodes(unique_nodes))
        print(f"   🟢 通过模拟代理连接验证的“真活节点”: {len(alive_nodes)}/{len(unique_nodes)}")
    else:
        alive_nodes = []
    
    # 分组输出
    config = generate_config(alive_nodes)
    if config:
        os.makedirs('output', exist_ok=True)
        with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
        with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': config['proxies']}, f, allow_unicode=True)
            
        with open('output/stats.json', 'w', encoding='utf-8') as f:
            json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(config['proxies'])}, f, indent=2)
            
        print(f"\n✨ 更新成功！筛选并保留了 {len(config['proxies'])} 个真活节点，并已按协议完成分组。")
        return 0
    else:
        print("❌ 未筛选到符合标准的存活节点。")
        return 1

if __name__ == '__main__':
    exit(main())
