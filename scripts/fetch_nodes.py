#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成小火箭专属的无外壳纯净 YAML 配置
彻底根除小火箭只认 1 个节点的硬伤，且严格锁死在 25 个节点以内
"""

import requests
import yaml
import json
import os
import re
from datetime import datetime

# ==================== 🚀 质量最高的全网免翻墙大池矩阵 ====================
SOURCES_YAML = [
    'https://cdn.jsdelivr.net/gh/goer998/Free-nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/learnhard-cn/free_nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/tiamg/free-nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/V2rayShare/V2rayShare@master/clash.yaml',
    'https://cdn.jsdelivr.net/gh/baipiao-pool/baipiao@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/w1770946466/Auto_Free_Nodes@main/run/clash.yaml'
]

def fetch_content(url, timeout=25):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            return response.text
        return None
    except Exception:
        return None

def parse_clash_yaml(content):
    if not content:
        return []
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
    
    if node_type == 'ss' and not node.get('password'): return None
    if node_type in ['vmess', 'vless'] and not node.get('uuid'): return None
    if node_type == 'trojan' and not node.get('password'): return None
    
    private_prefixes = ('10.', '172.16.', '192.168.', '127.', 'localhost', '0.0.0.0')
    if any(str(server).startswith(p) for p in private_prefixes): return None
    
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

def main():
    print("📥 开始调度最新高活性节点源...")
    all_nodes = []
    
    for url in SOURCES_YAML:
        content = fetch_content(url)
        if content:
            proxies = parse_clash_yaml(content)
            for p in proxies:
                sanitized = format_validate_and_sanitize(p)
                if sanitized:
                    all_nodes.append(sanitized)
            
    unique_nodes = deduplicate_nodes(all_nodes)
    
    # 🎯【核心控量】严格缩死在 25 个节点以内！绝不多给，秒测速
    if len(unique_nodes) > 25:
        unique_nodes = unique_nodes[:25]
        
    print(f"\n📊 精简控量完毕。最终保留的节点规模: {len(unique_nodes)}")
    
    if unique_nodes:
        # 统一规范化重命名，防止小火箭重名合并
        for idx, node in enumerate(unique_nodes, 1):
            ntype = str(node['type']).lower()
            node['name'] = f"{ntype.upper()}_{idx:02d}"

        os.makedirs('output', exist_ok=True)
        try:
            # ✨【极其关键】直接 dump 列表本身（unique_nodes），删掉顶层的 {'proxies': ...} 外壳！
            # 这样输出的文件开头直接是 `- name: ...`，小火箭可以 100% 毫无障碍地全部识别
            with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(unique_nodes, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
                
            with open('output/stats.json', 'w', encoding='utf-8') as f:
                json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(unique_nodes)}, f, indent=2)
                
            print(f"✨ [SUCCESS] 成功写入纯净 proxies.yaml，当前包含 {len(unique_nodes)} 个节点。")
            return 0
        except Exception as e:
            print(f"❌ 写入文件失败: {e}")
            return 1
    else:
        print("⚠️ 未抓取到有效节点。")
        return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
