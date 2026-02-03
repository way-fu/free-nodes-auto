#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
更新频率：每周一
支持协议：SS, VMess, Trojan, VLESS
"""

import requests
import yaml
import base64
import json
import re
from datetime import datetime
from urllib.parse import unquote
import os

# ========== 节点源配置 ==========
# YAML格式源（直接解析）
SOURCES_YAML = [
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/all.yaml',
    'https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml',
    'https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/clash.yaml',
    'https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml',
]

# Base64订阅源（需要解码）
SOURCES_BASE64 = [
    # 可添加base64格式的订阅链接
    # 'https://example.com/subscribe?token=xxx',
]

# 节点池API
SOURCES_JSON = [
    # 可添加JSON格式的API
]

# ========== 辅助函数 ==========

def fetch_content(url, timeout=30):
    """获取远程内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"  ❌ 获取失败: {e}")
        return None

def parse_clash_yaml(content):
    """解析 Clash YAML 格式"""
    try:
        data = yaml.safe_load(content)
        if data and isinstance(data, dict):
            proxies = data.get('proxies', [])
            if proxies:
                return proxies
    except Exception as e:
        print(f"  ⚠️ YAML解析错误: {e}")
    return []

def decode_base64(content):
    """解码Base64内容"""
    try:
        # 自动补全padding
        padding = 4 - len(content) % 4
        if padding != 4:
            content += '=' * padding
        return base64.b64decode(content).decode('utf-8', errors='ignore')
    except:
        return None

def parse_base64_nodes(content):
    """解析Base64格式的节点链接"""
    nodes = []
    decoded = decode_base64(content)
    if not decoded:
        return nodes
    
    for line in decoded.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
            
        try:
            if line.startswith('ss://'):
                node = parse_ss_link(line)
                if node:
                    nodes.append(node)
            elif line.startswith('vmess://'):
                node = parse_vmess_link(line)
                if node:
                    nodes.append(node)
            elif line.startswith('trojan://'):
                node = parse_trojan_link(line)
                if node:
                    nodes.append(node)
            elif line.startswith('vless://'):
                node = parse_vless_link(line)
                if node:
                    nodes.append(node)
        except Exception as e:
            print(f"  ⚠️ 解析链接失败: {e}")
            continue
    
    return nodes

def parse_ss_link(link):
    """解析 Shadowsocks 链接"""
    try:
        # ss://method:password@server:port#name
        # 或 ss://base64(method:password)@server:port#name
        link = link[5:]  # 移除 ss://
        
        # 分离名称
        name = 'SS-Node'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        # 解析认证信息
        if '@' not in link:
            return None
            
        auth, server_part = link.rsplit('@', 1)
        
        # 判断auth是base64还是明文
        if ':' in auth:
            method, password = auth.split(':', 1)
        else:
            decoded_auth = decode_base64(auth)
            if not decoded_auth or ':' not in decoded_auth:
                return None
            method, password = decoded_auth.split(':', 1)
        
        # 解析服务器和端口
        if ':' not in server_part:
            return None
            
        # 处理可能包含插件的情况
        server_port = server_part
        if '?' in server_port:
            server_port = server_port.split('?')[0]
        
        server, port_str = server_port.rsplit(':', 1)
        port = int(port_str)
        
        return {
            'name': clean_name(name),
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password
        }
    except Exception as e:
        return None

def parse_vmess_link(link):
    """解析 VMess 链接"""
    try:
        # vmess://base64(json)
        b64_data = link[8:]  # 移除 vmess://
        json_str = decode_base64(b64_data)
        if not json_str:
            return None
            
        data = json.loads(json_str)
        
        node = {
            'name': clean_name(data.get('ps', 'VMess-Node')),
            'type': 'vmess',
            'server': data.get('add', ''),
            'port': int(data.get('port', 0)),
            'uuid': data.get('id', ''),
            'alterId': int(data.get('aid', 0)),
            'cipher': 'auto',
            'network': data.get('net', 'tcp'),
            'tls': data.get('tls', '') == 'tls',
        }
        
        # WebSocket配置
        if node['network'] == 'ws':
            node['ws-opts'] = {
                'path': data.get('path', '/'),
                'headers': {
                    'Host': data.get('host', node['server'])
                }
            }
        
        # 跳过证书验证（免费节点常见）
        node['skip-cert-verify'] = True
        
        return node
    except Exception as e:
        return None

def parse_trojan_link(link):
    """解析 Trojan 链接"""
    try:
        # trojan://password@server:port?sni=xxx#name
        link = link[9:]  # 移除 trojan://
        
        name = 'Trojan-Node'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        # 分离参数
        params = {}
        if '?' in link:
            link, param_str = link.split('?', 1)
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        if '@' not in link:
            return None
            
        password, server_part = link.split('@', 1)
        
        if ':' not in server_part:
            return None
            
        server, port_str = server_part.rsplit(':', 1)
        port = int(port_str)
        
        node = {
            'name': clean_name(name),
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': params.get('sni', server),
            'skip-cert-verify': params.get('allowInsecure') == '1' or True
        }
        
        return node
    except Exception as e:
        return None

def parse_vless_link(link):
    """解析 VLESS 链接"""
    try:
        # vless://uuid@server:port?encryption=none&type=tcp#name
        link = link[8:]  # 移除 vless://
        
        name = 'VLESS-Node'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        # 分离参数
        params = {}
        if '?' in link:
            link, param_str = link.split('?', 1)
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        if '@' not in link:
            return None
            
        uuid, server_part = link.split('@', 1)
        
        if ':' not in server_part:
            return None
            
        server, port_str = server_part.rsplit(':', 1)
        port = int(port_str)
        
        node = {
            'name': clean_name(name),
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'encryption': params.get('encryption', 'none'),
            'flow': params.get('flow', ''),
            'network': params.get('type', 'tcp'),
            'tls': params.get('security', '') == 'tls' or params.get('security', '') == 'xtls',
            'sni': params.get('sni', ''),
            'skip-cert-verify': True
        }
        
        # XTLS特殊配置
        if params.get('security') == 'xtls':
            node['flow'] = params.get('flow', 'xtls-rprx-direct')
        
        return node
    except Exception as e:
        return None

def clean_name(name):
    """清理节点名称"""
    if not name:
        return 'Unknown'
    
    # 移除emoji和特殊字符，保留中英文、数字、横线、下划线
    name = re.sub(r'[^\w\s\u4e00-\u9fff\-]', '', name)
    # 移除多余空格
    name = ' '.join(name.split())
    # 限制长度
    name = name[:50].strip()
    
    # 如果为空，使用默认名称
    if not name:
        return f"Node-{datetime.now().strftime('%H%M%S')}"
    
    return name

def validate_node(node):
    """验证节点有效性"""
    if not isinstance(node, dict):
        return False
    
    node_type = node.get('type', '').lower()
    server = node.get('server', '')
    port = node.get('port', 0)
    
    # 基本检查
    if not server or not port or not isinstance(port, int):
        return False
    
    # 排除内网IP和本地地址
    private_prefixes = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                       '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                       '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                       '172.30.', '172.31.', '192.168.', '127.', 'localhost', '0.0.0.0')
    
    if any(server.startswith(p) for p in private_prefixes):
        return False
    
    # 协议特定检查
    if node_type == 'ss':
        if not node.get('password') or not node.get('cipher'):
            return False
    elif node_type == 'vmess':
        if not node.get('uuid'):
            return False
    elif node_type == 'trojan':
        if not node.get('password'):
            return False
    elif node_type == 'vless':
        if not node.get('uuid'):
            return False
    
    return True

def deduplicate_nodes(nodes):
    """基于server:port去重"""
    seen = set()
    unique = []
    
    for node in nodes:
        key = f"{node.get('type')}://{node.get('server')}:{node.get('port')}"
        if key not in seen:
            seen.add(key)
            unique.append(node)
    
    return unique

def generate_config(nodes):
    """生成 Shadowrocket/Clash 配置"""
    if not nodes:
        return None
    
    # 限制节点数量（性能考虑）
    max_nodes = 100
    if len(nodes) > max_nodes:
        print(f"⚠️ 节点过多({len(nodes)})，只保留前 {max_nodes} 个")
        nodes = nodes[:max_nodes]
    
    proxy_names = [n['name'] for n in nodes]
    
    # 策略组配置
    proxy_groups = [
        {
            'name': '🚀 节点选择',
            'type': 'select',
            'proxies': ['♻️ 自动选择', '♻️ 负载均衡', '🌍 全球直连'] + proxy_names
        },
        {
            'name': '♻️ 自动选择',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'tolerance': 50,
            'proxies': proxy_names
        },
        {
            'name': '♻️ 负载均衡',
            'type': 'load-balance',
            'strategy': 'consistent-hashing',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'proxies': proxy_names
        },
        {
            'name': '🌍 全球直连',
            'type': 'select',
            'proxies': ['DIRECT', '🚀 节点选择']
        },
        {
            'name': '📹 YouTube',
            'type': 'select',
            'proxies': ['🚀 节点选择', '♻️ 自动选择'] + proxy_names[:10]
        },
        {
            'name': '🎥 Netflix',
            'type': 'select',
            'proxies': ['🚀 节点选择', '♻️ 自动选择'] + proxy_names[:10]
        },
        {
            'name': '📱 Telegram',
            'type': 'select',
            'proxies': ['🚀 节点选择', '♻️ 自动选择'] + proxy_names[:10]
        },
        {
            'name': 'Ⓜ️ 微软服务',
            'type': 'select',
            'proxies': ['🌍 全球直连', '🚀 节点选择']
        },
        {
            'name': '🍎 苹果服务',
            'type': 'select',
            'proxies': ['🌍 全球直连', '🚀 节点选择']
        }
    ]
    
    # 规则配置
    rules = [
        # 局域网
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'IP-CIDR,100.64.0.0/10,DIRECT',
        
        # 微软服务
        'DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务',
        'DOMAIN-SUFFIX,windows.net,Ⓜ️ 微软服务',
        'DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务',
        'DOMAIN-SUFFIX,outlook.com,Ⓜ️ 微软服务',
        'DOMAIN-SUFFIX,live.com,Ⓜ️ 微软服务',
        'DOMAIN-SUFFIX,msn.com,Ⓜ️ 微软服务',
        'DOMAIN-KEYWORD,microsoft,Ⓜ️ 微软服务',
        
        # 苹果服务
        'DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,icloud.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,appstore.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,itunes.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,me.com,🍎 苹果服务',
        'DOMAIN-SUFFIX,mzstatic.com,🍎 苹果服务',
        
        # YouTube
        'DOMAIN-SUFFIX,youtube.com,📹 YouTube',
        'DOMAIN-SUFFIX,ytimg.com,📹 YouTube',
        'DOMAIN-SUFFIX,googlevideo.com,📹 YouTube',
        'DOMAIN-SUFFIX,youtu.be,📹 YouTube',
        'DOMAIN-KEYWORD,youtube,📹 YouTube',
        
        # Netflix
        'DOMAIN-SUFFIX,netflix.com,🎥 Netflix',
        'DOMAIN-SUFFIX,netflix.net,🎥 Netflix',
        'DOMAIN-SUFFIX,nflxvideo.net,🎥 Netflix',
        'DOMAIN-SUFFIX,nflximg.com,🎥 Netflix',
        'DOMAIN-SUFFIX,nflxext.com,🎥 Netflix',
        'DOMAIN-KEYWORD,netflix,🎥 Netflix',
        
        # Telegram
        'DOMAIN-SUFFIX,telegram.org,📱 Telegram',
        'DOMAIN-SUFFIX,telegram.me,📱 Telegram',
        'DOMAIN-SUFFIX,t.me,📱 Telegram',
        'DOMAIN-SUFFIX,tdesktop.com,📱 Telegram',
        'DOMAIN-SUFFIX,telegra.ph,📱 Telegram',
        'IP-CIDR,149.154.160.0/20,📱 Telegram',
        'IP-CIDR,67.198.55.0/24,📱 Telegram',
        'IP-CIDR,91.108.4.0/22,📱 Telegram',
        'IP-CIDR,91.108.8.0/22,📱 Telegram',
        'IP-CIDR,91.108.12.0/22,📱 Telegram',
        'IP-CIDR,91.108.16.0/22,📱 Telegram',
        'IP-CIDR,91.108.56.0/22,📱 Telegram',
        
        # Google
        'DOMAIN-SUFFIX,google.com,🚀 节点选择',
        'DOMAIN-SUFFIX,googleapis.com,🚀 节点选择',
        'DOMAIN-SUFFIX,gstatic.com,🚀 节点选择',
        'DOMAIN-SUFFIX,gmail.com,🚀 节点选择',
        'DOMAIN-SUFFIX,youtube.com,🚀 节点选择',
        'DOMAIN-KEYWORD,google,🚀 节点选择',
        
        # 国内直连
        'DOMAIN-SUFFIX,cn,DIRECT',
        'DOMAIN-SUFFIX,alibaba.com,DIRECT',
        'DOMAIN-SUFFIX,alicdn.com,DIRECT',
        'DOMAIN-SUFFIX,aliyun.com,DIRECT',
        'DOMAIN-SUFFIX,baidu.com,DIRECT',
        'DOMAIN-SUFFIX,bdstatic.com,DIRECT',
        'DOMAIN-SUFFIX,qq.com,DIRECT',
        'DOMAIN-SUFFIX,wechat.com,DIRECT',
        'DOMAIN-SUFFIX,taobao.com,DIRECT',
        'DOMAIN-SUFFIX,tmall.com,DIRECT',
        'DOMAIN-SUFFIX,jd.com,DIRECT',
        'DOMAIN-SUFFIX,bilibili.com,DIRECT',
        'DOMAIN-SUFFIX,zhihu.com,DIRECT',
        'DOMAIN-SUFFIX,weibo.com,DIRECT',
        
        # GEOIP
        'GEOIP,CN,DIRECT',
        
        # 兜底
        'MATCH,🚀 节点选择'
    ]
    
    config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'bind-address': '*',
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '0.0.0.0:9090',
        'secret': '',
        'dns': {
            'enable': True,
            'listen': '0.0.0.0:1053',
            'default-nameserver': ['223.5.5.5', '119.29.29.29', '8.8.8.8'],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': [
                'https://doh.pub/dns-query',
                'https://dns.alidns.com/dns-query'
            ],
            'fallback': [
                'https://1.1.1.1/dns-query',
                'https://dns.google/dns-query'
            ],
            'fallback-filter': {
                'geoip': True,
                'geoip-code': 'CN',
                'ipcidr': ['240.0.0.0/4']
            }
        },
        'proxies': nodes,
        'proxy-groups': proxy_groups,
        'rules': rules
    }
    
    return config

def main():
    print("=" * 60)
    print(f"🚀 免费节点自动抓取工具")
    print(f"⏰ 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    all_nodes = []
    
    # 1. 抓取YAML源
    print("\n📥 正在抓取 YAML 格式源...")
    for i, url in enumerate(SOURCES_YAML, 1):
        print(f"\n[{i}/{len(SOURCES_YAML)}] {url[:60]}...")
        content = fetch_content(url)
        if content:
            nodes = parse_clash_yaml(content)
            print(f"   ✅ 成功获取 {len(nodes)} 个节点")
            all_nodes.extend(nodes)
        else:
            print("   ❌ 获取失败")
    
    # 2. 抓取Base64源
    if SOURCES_BASE64:
        print("\n📥 正在抓取 Base64 格式源...")
        for i, url in enumerate(SOURCES_BASE64, 1):
            print(f"\n[{i}/{len(SOURCES_BASE64)}] {url[:60]}...")
            content = fetch_content(url)
            if content:
                nodes = parse_base64_nodes(content)
                print(f"   ✅ 成功获取 {len(nodes)} 个节点")
                all_nodes.extend(nodes)
    
    print(f"\n📊 原始节点总数: {len(all_nodes)}")
    
    # 3. 清理和验证
    print("\n🔧 正在清理和验证节点...")
    for node in all_nodes:
        node['name'] = clean_name(node.get('name', ''))
    
    valid_nodes = [n for n in all_nodes if validate_node(n)]
    print(f"   ✅ 有效节点: {len(valid_nodes)}/{len(all_nodes)}")
    
    # 4. 去重
    print("\n🔄 正在去重...")
    unique_nodes = deduplicate_nodes(valid_nodes)
    print(f"   ✅ 去重后: {len(unique_nodes)}/{len(valid_nodes)}")
    
    # 5. 生成配置
    print("\n📝 正在生成配置文件...")
    config = generate_config(unique_nodes)
    
    if config:
        # 保存完整配置
        with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False, 
                     default_flow_style=False)
        print("   💾 已保存: output/nodes.yaml")
        
        # 保存仅节点配置
        minimal = {'proxies': config['proxies']}
        with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(minimal, f, allow_unicode=True)
        print("   💾 已保存: output/proxies.yaml")
        
        # 保存统计信息
        stats = {
            'updated_at': datetime.now().isoformat(),
            'total_nodes': len(unique_nodes),
            'sources': len(SOURCES_YAML) + len(SOURCES_BASE64)
        }
        with open('output/stats.json', 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        
        print(f"\n✨ 完成！共 {len(unique_nodes)} 个可用节点")
        return 0
    else:
        print("❌ 配置生成失败")
        return 1

if __name__ == '__main__':
    exit(main())
