#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成小火箭专属的 Base64 订阅流文件
严格控制在 30 个节点以内，秒测速，彻底解决解析误区
"""

import requests
import yaml
import json
import os
import re
import base64
from urllib.parse import quote

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

def convert_to_rocket_link(node, remark):
    """转换 Clash 配置为小火箭原生 Base64 节点串"""
    try:
        ntype = str(node['type']).lower()
        server = node['server']
        port = node['port']
        remark_encoded = quote(remark)
        
        if ntype == 'ss':
            cipher = node.get('cipher', 'aes-256-gcm')
            password = node.get('password', '')
            userinfo = base64.b64encode(f"{cipher}:{password}".encode('utf-8')).decode('utf-8')
            return f"ss://{userinfo}@{server}:{port}#{remark_encoded}"
            
        elif ntype == 'vmess':
            v_config = {
                "v": "2", "ps": remark, "add": str(server), "port": str(port),
                "id": node.get('uuid', ''), "aid": str(node.get('alterId', 0)),
                "scy": "auto", "net": node.get('network', 'tcp'), "type": "none",
                "host": node.get('ws-opts', {}).get('headers', {}).get('Host', '') or node.get('servername', ''),
                "path": node.get('ws-opts', {}).get('path', ''), "tls": "tls" if node.get('tls') else ""
            }
            v_json = json.dumps(v_config, ensure_ascii=False)
            v_b64 = base64.b64encode(v_json.encode('utf-8')).decode('utf-8')
            return f"vmess://{v_b64}"
            
        elif ntype == 'vless':
            uuid = node.get('uuid', '')
            link = f"vless://{uuid}@{server}:{port}?type={node.get('network','tcp')}"
            if node.get('tls'): link += "&security=tls"
            if node.get('servername'): link += f"&sni={node.get('servername')}"
            link += f"#{remark_encoded}"
            return link
            
        elif ntype == 'trojan':
            password = node.get('password', '')
            link = f"trojan://{password}@{server}:{port}?"
            if node.get('sni'): link += f"sni={node.get('sni')}"
            link += f"#{remark_encoded}"
            return link
    except Exception:
        pass
    return None

def main():
    print("📥 开始拉取镜像加速节点源...")
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
    
    # 🎯 核心控制：锁定最大 25 个节点！测速只需 1-2 秒
    if len(unique_nodes) > 25:
        unique_nodes = unique_nodes[:25]
        
    print(f"📊 洗牌精简完毕。准备写入小火箭的核心节点数: {len(unique_nodes)}")
    
    raw_links = []
    for idx, node in enumerate(unique_nodes, 1):
        ntype = str(node['type']).lower()
        remark = f"⚡_{ntype.upper()}_{idx:02d}"
        link = convert_to_rocket_link(node, remark)
        if link:
            raw_links.append(link)
            
    if raw_links:
        payload = "\n".join(raw_links)
        b64_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        
        os.makedirs('output', exist_ok=True)
        try:
            # 专门输出给小火箭原生 Subscribe 识别的纯净 Base64 文件
            with open('output/mixed_nodes.txt', 'w', encoding='utf-8') as f:
                f.write(b64_payload)
                
            # 同时保留一个 25 节点的 proxies.yaml 给备用
            with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
                yaml.dump({'proxies': unique_nodes}, f, allow_unicode=True)
                
            with open('output/stats.json', 'w', encoding='utf-8') as f:
                json.dump({'updated_at': datetime.now().isoformat(), 'total_nodes': len(raw_links)}, f, indent=2)
                
            print(f"✨ [SUCCESS] 转换成功！已输出 25 个精简版原生小火箭标准节点流。")
            return 0
        except Exception as e:
            print(f"❌ 写入失败: {e}")
            return 1
    else:
        print("⚠️ 未能生成任何有效节点。")
        return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
