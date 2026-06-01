#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取全网免费节点（GitHub + Telegram 频道 + 独立 API + 匿名剪贴板）
升级版：多维全网爬虫引擎 + 宽容型 L7 异步管道验证 + 智能协议分组
"""

import requests
import yaml
import base64
import json
import re
import asyncio
import socket
from datetime import datetime
from urllib.parse import unquote, urlparse
import os

# ==================== 🚀 全网节点源多维矩阵 ====================

# 1. 传统的 Clash YAML 订阅源
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

# 2. 匿名剪贴板与独立博客提供的 Base64/纯文本订阅（非 GitHub）
SOURCES_TEXT = [
    'https://freeclash.org/feed/clash.yaml',
    'https://raw.githubusercontent.com/v2ray-links/v2ray-free-links/master/v2ray' # base64流
]

# 3. ✨ Telegram 高频更新公开频道（利用 Web Snapshot 绕过登录直接爬取野生节点）
TELEGRAM_CHANNELS = [
    'https://t.me/s/v2ray_free_xyz',
    'https://t.me/s/free_nodes',
    'https://t.me/s/SSR_VMESS_VLESS_Trojan_clash',
    'https://t.me/s/clashnode123'
]

# ================================================================

def fetch_content(url, timeout=20):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"  ❌ 抓取失败 [{url[:35]}...]: {e}")
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

def extract_nodes_from_text(text):
    """
    万能文本节点提取器：
    专门应对 Telegram 网页、匿名剪贴板里杂乱无章的纯文本。
    通过正则表达式，强行将隐藏在 HTML 或文本里的标准链接抠出来，并转化为 Clash 识别的字典。
    """
    extracted = []
    if not text: return extracted
    
    # 判定是否是整体 base64 加密订阅
    if text.startswith('ss://') or text.startswith('vmess://') or text.startswith('vless://') or text.startswith('trojan://'):
        lines = text.split('\n')
    else:
        decoded = safe_b64decode(text)
        if decoded and ('://' in decoded):
            lines = decoded.split('\n')
        else:
            # 说明是混杂了 HTML 的原生网页文本（如 Telegram 快照）
            lines = re.findall(r'(ss://[a-zA-Z0-9_\-\+\=\%\&\?\.\:\#\/]+|vmess://[a-zA-Z0-9_\-\+\=\%\&\?\.\:\#\/]+|vless://[a-zA-Z0-9_\-\+\=\%\&\?\.\:\#\/]+|trojan://[a-zA-Z0-9_\-\+\=\%\&\?\.\:\#\/]+)', text)

    for line in lines:
        line = line.strip()
        if not line: continue
        try:
            if line.startswith('ss://'):
                # 简单解析 SS 链接，转换为极简字典
                raw = line[5:]
                if '#' in raw: raw, name = raw.split('#', 1)
                else: name = "Wild-SS"
                if '@' in raw:
                    part1, part2 = raw.split('@', 1)
                    if ':' in part1: cipher_pwd = safe_b64decode(part1)
                    else: cipher_pwd = safe_b64decode(part1) # 兼容
                    server_port = part2
                    # 粗暴切割
                    if cipher_pwd and ':' in cipher_pwd:
                        cipher, pwd = cipher_pwd.split(':', 1)
                        server, port = server_port.split(':', 1)
                        extracted.append({'type': 'ss', 'server': server.split('?')[0], 'port': int(port.split('?')[0]), 'cipher': cipher, 'password': pwd, 'name': unquote(name)})
            elif line.startswith('trojan://'):
                match = re.match(r'trojan://([^@]+)@([^:]+):([0-9]+)', line)
                if match:
                    pwd, server, port = match.groups()
                    name = line.split('#')[1] if '#' in line else "Wild-Trojan"
                    extracted.append({'type': 'trojan', 'server': server, 'port': int(port), 'password': pwd, 'name': unquote(name)})
            elif line.startswith('vmess://'):
                # VMess 通常是 Base64 的 JSON
                raw_json = safe_b64decode(line[8:].split('#')[0])
                if raw_json:
                    j = json.loads(raw_json)
                    extracted.append({'type': 'vmess', 'server': j.get('add'), 'port': int(j.get('port', 0)), 'uuid': j.get('id'), 'cipher': 'auto', 'alterId': int(j.get('aid', 0)), 'name': j.get('ps', 'Wild-VMess')})
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

# ==================== 🧠 异步 L7 管道活体拦截器 ====================

async def test_node_l7(node, timeout=3.5):
    server = str(node.get('server'))
    port = node.get('port')
    node_type = node.get('type', '').lower()
    
    try:
        # 1. DNS 预检
        loop = asyncio.get_running_loop()
        await loop.getaddrinfo(server, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        
        # 2. 建立真实连接管道
        conn = asyncio.open_connection(server, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # 3. 发送对应代理协议最底层的首包刺探
        if node_type == 'ss':
            writer.write(b'\x05\x01\x00')
        elif node_type == 'trojan':
            writer.write(b'0000000000000000000000000000000000000000000000000000000000000000\r\n\x01\x01')
        elif node_type in ['vmess', 'vless']:
            uuid_str = str(node.get('uuid', '')).replace('-', '')
            if len(uuid_str) == 32:
                writer.write(bytes.fromhex(uuid_str)[:16])
                
        await writer.drain()
        
        # 4. 观察是否有重置信号
        try:
            await asyncio.wait_for(reader.read(1), timeout=0.25)
        except asyncio.TimeoutError:
            pass # 没断开说明应用层通畅
            
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return node
    except Exception:
        return None

async def filter_alive_nodes(nodes):
    print(f"   ⚡ 开始进行多维全网节点 L7 效能清洗 (待测池基数: {len(nodes)})...")
    semaphore = asyncio.Semaphore(150) # 提高并发处理野生高吞吐节点
    
    async def sem_task(node):
        async with semaphore:
            return await test_node_l7(node)
            
    tasks = [sem_task(node) for node in nodes]
    results = await asyncio.gather(*tasks)
    return [n for n in results if n is not None]

# ==================== 📝 策略组自适应生成 ====================

def generate_config(nodes):
    if not nodes: return None
    
    # 既然源扩大了，总保留数提升至 50 个高通透率节点
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
    print(f"🚀 矩阵全网节点扫描引擎 (GitHub + Telegram + Web API)")
    print("=" * 60)
    all_nodes = []
    
    # 维度1: 传统 YAML 源
    for url in SOURCES_YAML:
        content = fetch_content(url)
        if content:
            nodes = parse_clash_yaml(content)
            all_nodes.extend(nodes)
            
    # 维度2: 独立文本/订阅流源
    for url in SOURCES_TEXT:
        content = fetch_content(url)
        if content:
            if 'proxies:' in content: # 也是YAML
                all_nodes.extend(parse_clash_yaml(content))
            else:
                all_nodes.extend(extract_nodes_from_text(content))
                
    # 维度3: Telegram 实时电报快照爬虫
    print("📥 正在向 Telegram 开放频道注入文本爬虫...")
    for url in TELEGRAM_CHANNELS:
        content = fetch_content(url)
        if content:
            t_nodes = extract_nodes_from_text(content)
            all_nodes.extend(t_nodes)
            print(f"   🔹 从 [{url.split('/')[-1]}] 抠出野生节点数: {len(t_nodes)}")
            
    # 清理、格式化、强力去重
    valid_format_nodes = [n for n in all_nodes if format_validate(n)]
    unique_nodes = deduplicate_nodes(valid_format_nodes)
    print(f"\n📊 全网汇总去重完毕。待测总候选池基数: {len(unique_nodes)}")
    
    # 连接测试
    if unique_nodes:
        loop = asyncio.get_event_loop()
        alive_nodes = loop.run_until_complete(filter_alive_nodes(unique_nodes))
        print(f"   🟢 最终通过 Connect 级别过滤的真活节点: {len(alive_nodes)}/{len(unique_nodes)}")
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
        print(f"\n✨ 更新大功告成！当前已将最新的 {len(config['proxies'])} 个优质活节点打包分类。")
        return 0
    else:
        print("❌ 今日全网洗牌，未捕获到符合连接率的节点。")
        return 1

if __name__ == '__main__':
    exit(main())
