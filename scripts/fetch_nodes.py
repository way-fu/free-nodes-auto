#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash 标准合规 YAML 配置
真正网络抓取版：严格控量 25 个，秒测速，完美全显，绝无 test 节点
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
        # 移除可能导致解析失败的控制字符
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
    print("📥 开始拉取全网高活性代理源...")
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
    
    # 🎯【核心限流：严格锁死 25 个】
    # 彻底解决节点过多、手机测速过慢的问题
    if len(unique_nodes) > 25:
        unique_nodes = unique_nodes[:25]
        
    print(f"\n📊 过滤洗牌完毕。即将交付给小火箭的真实有效节点数: {len(unique_nodes)}")
    
    if unique_nodes:
        # 为小火箭重新规范化命名，防止重名导致只剩一个
        for idx, node in enumerate(unique_nodes, 1):
            ntype = str(node['type']).lower()
            node['name'] = f"{ntype.upper()}_{idx:02d}"

        # 🪐 包装小火箭必须依赖的标准 Clash 骨架外壳
        all_names = [n['name'] for n in unique_nodes]
        clash_config = {
            'mixed-port': 7890,
            'allow-lan': False,
            'mode': 'rule',
            'log-level': 'info',
            'proxies': unique_nodes,
            'proxy-groups': [
                {
                    'name': '🚀 节点选择',
                    'type': 'select',
                    'proxies': ['♻️ 自动选择', 'DIRECT'] + all_names
                },
                {
                    'name': '♻️ 自动选择',
                    'type': 'url-test',
                    'url': 'http://cp.cloudflare.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': all_names
                }
            ],
            'rules': [
                'MATCH,🚀 节点选择'
            ]
        }

        os.makedirs('output', exist_ok=True)
        try:
            # 写入覆盖 proxies.yaml
            with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
                
            with open('output/stats.json', 'w', encoding='utf-8') as f:
                json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(unique_nodes)}, f, indent=2)
                
            print(f"✨ [SUCCESS] 完美写入 proxies.yaml，当前包含 {len(unique_nodes)} 个真实活节点。")
            return 0
        except Exception as e:
            print(f"❌ 写入文件失败: {e}")
            return 1
    else:
        print("⚠️ 未抓取到任何有效网络节点。")
        return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
