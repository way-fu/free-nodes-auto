#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
优化版自动抓取免费节点并生成 Shadowrocket/Clash YAML 配置
改进内容：
1. 扩充源列表（包含多个备用镜像和新源）
2. 增强网络容错和重试机制
3. 放宽验证条件，避免误杀有效节点
4. 改进 YAML 解析容错性
"""

import requests
import yaml
import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse

# ==================== 📡 扩充的全球高可用节点源矩阵 ====================
SOURCES_YAML = [
    # ===== Jsdelivr 加速源 =====
    'https://cdn.jsdelivr.net/gh/goer998/Free-nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/learnhard-cn/free_nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/tiamg/free-nodes@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/V2rayShare/V2rayShare@master/clash.yaml',
    'https://cdn.jsdelivr.net/gh/baipiao-pool/baipiao@main/clash.yaml',
    'https://cdn.jsdelivr.net/gh/w1770946466/Auto_Free_Nodes@main/run/clash.yaml',
    
    # ===== 直接源（作为备份） =====
    'https://raw.githubusercontent.com/w1770946466/Auto_Free_Nodes/main/run/clash.yaml',
    'https://v2rayshare.github.io/v2rayshare/clash.yaml',
    
    # ===== Ghproxy 镜像加速（突破 GFW 限制） =====
    'https://ghproxy.com/https://raw.githubusercontent.com/goer998/Free-nodes/main/clash.yaml',
    'https://ghproxy.com/https://raw.githubusercontent.com/learnhard-cn/free_nodes/main/clash.yaml',
    
    # ===== 其他多源备份 =====
    'https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/history.yaml',
    'https://raw.fastgit.org/goer998/Free-nodes/main/clash.yaml',
]

# ===== 单节点订阅源（txt 格式） =====
SOURCES_SUBSCRIBE = [
    'https://raw.githubusercontent.com/YJLLQ/V2rayDomain/main/v2ray',
    'https://ghproxy.com/https://raw.githubusercontent.com/YJLLQ/V2rayDomain/main/v2ray',
]

def fetch_content(url, timeout=30, retries=2):
    """增强版请求机制，含重试和超时控制"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
    }
    
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                return response.text
            else:
                if attempt < retries - 1:
                    print(f"  ⚠️ [{response.status_code}] 重试中... {url[:50]}...")
                    time.sleep(2 ** attempt)  # 指数退避
                else:
                    print(f"  ❌ 最终失败 [{response.status_code}]: {url[:50]}...")
        except requests.Timeout:
            if attempt < retries - 1:
                print(f"  ⏱️ 超时，重试中... {url[:50]}...")
                time.sleep(2 ** attempt)
            else:
                print(f"  ❌ 超时失败: {url[:50]}...")
        except Exception as e:
            if attempt < retries - 1:
                print(f"  🔄 异常，重试中... ({str(e)[:30]})")
                time.sleep(2 ** attempt)
            else:
                print(f"  ❌ 异常失败: {str(e)[:50]}...")
    
    return None

def parse_clash_yaml(content):
    """改进的 YAML 解析，更容错"""
    if not content:
        return []
    
    try:
        # 清洗控制字符但保留有效的 YAML 内容
        sanitized_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)
        
        # 尝试标准解析
        data = yaml.safe_load(sanitized_content)
        
        if data and isinstance(data, dict):
            proxies = data.get('proxies', [])
            if isinstance(proxies, list):
                return proxies
        
        return []
    except yaml.YAMLError as e:
        print(f"  ⚠️ YAML 解析失败: {str(e)[:60]}...")
        return []
    except Exception as e:
        print(f"  ⚠️ 未知解析错误: {str(e)[:60]}...")
        return []

def parse_v2ray_subscription(content):
    """解析 V2Ray 订阅格式（base64 编码的链接列表）"""
    if not content:
        return []
    
    try:
        import base64
        try:
            decoded = base64.b64decode(content).decode('utf-8')
        except:
            decoded = content
        
        # 提取所有 vmess:// 和 vless:// 链接
        vmess_pattern = r'vmess://[A-Za-z0-9+/=]+'
        vless_pattern = r'vless://[A-Za-z0-9+/=\-._~:/?#\[\]@!$&\'()*+,;=]+'
        
        vmess_links = re.findall(vmess_pattern, decoded)
        vless_links = re.findall(vless_pattern, decoded)
        
        nodes = []
        
        # 解析 VMess 链接
        for link in vmess_links:
            try:
                payload = base64.b64decode(link.replace('vmess://', '')).decode('utf-8')
                node = json.loads(payload)
                node['type'] = 'vmess'
                nodes.append(node)
            except:
                pass
        
        return nodes
    except Exception as e:
        print(f"  ⚠️ V2Ray 订阅解析失败: {str(e)[:50]}...")
        return []

def format_validate_and_sanitize(node):
    """放宽验证条件，避免误杀有效节点"""
    if not isinstance(node, dict):
        return None
    
    server = node.get('server', '')
    port = node.get('port')
    node_type = str(node.get('type', '')).lower()
    
    # 更宽松的端口验证
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None
    
    if not server or port <= 0 or port > 65535:
        return None
    
    # 支持更多代理类型
    if node_type not in ['ss', 'vmess', 'vless', 'trojan', 'shadowsocks']:
        return None
    
    # 统一 shadowsocks 为 ss
    if node_type == 'shadowsocks':
        node['type'] = 'ss'
    
    # 更宽松的凭证验证：可以没有某些字段，但要有最基本的识别信息
    if node_type == 'ss':
        if not node.get('password') and not node.get('cipher'):
            return None
    elif node_type == 'vmess':
        if not node.get('uuid') and not node.get('id'):
            return None
    elif node_type == 'vless':
        if not node.get('uuid') and not node.get('id'):
            return None
    elif node_type == 'trojan':
        if not node.get('password'):
            return None
    
    # 过滤私有 IP
    private_prefixes = ('10.', '172.16.', '192.168.', '127.', 'localhost', '0.0.0.0')
    if any(str(server).startswith(p) for p in private_prefixes):
        return None
    
    # 确保必要字段
    if 'name' not in node:
        node['name'] = f"{node_type.upper()}-{server[:20]}"
    
    # 设置 UDP 支持
    if 'udp' not in node:
        node['udp'] = True
    
    return node

def deduplicate_nodes(nodes):
    """去重逻辑，基于关键特征"""
    seen = set()
    unique = []
    
    for node in nodes:
        server = str(node.get('server', '')).strip()
        port = node.get('port', 0)
        node_type = str(node.get('type', '')).lower()
        
        # 为了安全，不用凭证作为 key（某些公开节点可能凭证相同）
        key = f"{node_type}://{server}:{port}"
        
        if key not in seen:
            seen.add(key)
            unique.append(node)
    
    return unique

def generate_config(nodes):
    """生成 Clash 配置"""
    if not nodes:
        return None
    
    # 限制最大节点数
    max_total = 200
    if len(nodes) > max_total:
        nodes = nodes[:max_total]
    
    # 分类
    ss_nodes, vmess_nodes, vless_nodes, trojan_nodes = [], [], [], []
    
    for idx, node in enumerate(nodes, 1):
        ntype = str(node.get('type', '')).lower()
        
        # 生成友好名称
        name = node.get('name', f"{ntype}-{idx}")
        # 清理名称中的特殊字符
        name = re.sub(r'[^\w\-\u4e00-\u9fa5]', ' ', name)[:50]
        name = f"📍 {ntype.upper()}-{idx:03d}"
        
        node['name'] = name
        
        if ntype == 'ss':
            ss_nodes.append(name)
        elif ntype == 'vmess':
            vmess_nodes.append(name)
        elif ntype == 'vless':
            vless_nodes.append(name)
        elif ntype == 'trojan':
            trojan_nodes.append(name)
    
    all_names = [n['name'] for n in nodes]
    sub_groups = []
    
    if ss_nodes:
        sub_groups.append('🔒 SS 节点池')
    if vmess_nodes:
        sub_groups.append('🛸 VMess 节点池')
    if vless_nodes:
        sub_groups.append('⚡ VLESS 节点池')
    if trojan_nodes:
        sub_groups.append('🐴 Trojan 节点池')
    
    # 代理组配置
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
            'tolerance': 100,
            'proxies': all_names[:100] if len(all_names) > 100 else all_names
        },
        {
            'name': '🌍 全球直连',
            'type': 'select',
            'proxies': ['DIRECT', '🚀 节点选择']
        }
    ]
    
    # 添加分类节点池
    if ss_nodes:
        proxy_groups.append({
            'name': '🔒 SS 节点池',
            'type': 'url-test',
            'url': 'http://cp.cloudflare.com/generate_204',
            'interval': 300,
            'proxies': ss_nodes
        })
    
    if vmess_nodes:
        proxy_groups.append({
            'name': '🛸 VMess 节点池',
            'type': 'url-test',
            'url': 'http://cp.cloudflare.com/generate_204',
            'interval': 300,
            'proxies': vmess_nodes
        })
    
    if vless_nodes:
        proxy_groups.append({
            'name': '⚡ VLESS 节点池',
            'type': 'url-test',
            'url': 'http://cp.cloudflare.com/generate_204',
            'interval': 300,
            'proxies': vless_nodes
        })
    
    if trojan_nodes:
        proxy_groups.append({
            'name': '🐴 Trojan 节点池',
            'type': 'url-test',
            'url': 'http://cp.cloudflare.com/generate_204',
            'interval': 300,
            'proxies': trojan_nodes
        })
    
    # 应用代理规则
    proxy_groups.extend([
        {
            'name': '📹 YouTube',
            'type': 'select',
            'proxies': ['🚀 节点选择'] + sub_groups
        },
        {
            'name': '📱 Telegram',
            'type': 'select',
            'proxies': ['🚀 节点选择'] + sub_groups
        },
        {
            'name': '🍎 苹果服务',
            'type': 'select',
            'proxies': ['🌍 全球直连', '🚀 节点选择']
        }
    ])
    
    # 规则配置
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
            'default-nameserver': ['223.5.5.5', '8.8.8.8', '1.1.1.1'],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', 'https://dns.google/dns-query'],
            'fallback': ['https://dns.cloudflare.com/dns-query']
        },
        'proxies': nodes,
        'proxy-groups': proxy_groups,
        'rules': rules
    }

def main():
    print("=" * 60)
    print("🚀 优化版免费节点爬虫启动")
    print("=" * 60)
    
    all_nodes = []
    
    # ===== 第一阶段：抓取 YAML 格式源 =====
    print("\n📥 [阶段1] 从 YAML 源抓取节点...")
    print(f"   共 {len(SOURCES_YAML)} 个源待处理\n")
    
    success_count = 0
    for idx, url in enumerate(SOURCES_YAML, 1):
        print(f"   [{idx}/{len(SOURCES_YAML)}] {url[:55]}...")
        content = fetch_content(url, timeout=30, retries=2)
        
        if content:
            proxies = parse_clash_yaml(content)
            valid_count = 0
            
            for p in proxies:
                sanitized = format_validate_and_sanitize(p)
                if sanitized:
                    all_nodes.append(sanitized)
                    valid_count += 1
            
            if valid_count > 0:
                print(f"      ✅ 成功获取 {valid_count} 个节点 (累计: {len(all_nodes)})")
                success_count += 1
            else:
                print(f"      ⚠️ 源中无有效节点")
        else:
            print(f"      ❌ 获取失败")
    
    print(f"\n   ✅ YAML 阶段完成: {success_count}/{len(SOURCES_YAML)} 源成功")
    
    # ===== 第二阶段：抓取订阅格式源 =====
    print("\n📥 [阶段2] 从订阅源抓取节点...")
    print(f"   共 {len(SOURCES_SUBSCRIBE)} 个源待处理\n")
    
    for idx, url in enumerate(SOURCES_SUBSCRIBE, 1):
        print(f"   [{idx}/{len(SOURCES_SUBSCRIBE)}] {url[:55]}...")
        content = fetch_content(url, timeout=30, retries=2)
        
        if content:
            v2ray_nodes = parse_v2ray_subscription(content)
            if v2ray_nodes:
                for node in v2ray_nodes:
                    sanitized = format_validate_and_sanitize(node)
                    if sanitized:
                        all_nodes.append(sanitized)
                
                print(f"      ✅ 成功获取 {len(v2ray_nodes)} 个节点 (累计: {len(all_nodes)})")
    
    # ===== 数据清理 =====
    print("\n🧹 开始数据去重和清理...")
    unique_nodes = deduplicate_nodes(all_nodes)
    print(f"   去重前: {len(all_nodes)} 节点")
    print(f"   去重后: {len(unique_nodes)} 节点")
    
    if not unique_nodes:
        print("\n⚠️ 警告：未获取到任何有效节点！")
        print("   可能原因:")
        print("   1. 网络连接不稳定或被限流")
        print("   2. 所有源都已失效")
        print("   3. 节点验证规则过于严格")
        return 1
    
    # ===== 生成配置 =====
    print("\n📝 生成 Clash 配置文件...")
    config = generate_config(unique_nodes)
    
    if config:
        os.makedirs('output', exist_ok=True)
        
        try:
            # 写入完整配置
            with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(
                    config,
                    f,
                    allow_unicode=True,
                    sort_keys=False,
                    default_flow_style=False,
                    width=200
                )
            
            # 写入纯代理列表（用于其他工具）
            with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(
                    {'proxies': config['proxies']},
                    f,
                    allow_unicode=True,
                    sort_keys=False,
                    default_flow_style=False,
                    width=200
                )
            
            # 写入统计信息
            stats = {
                'updated_at': datetime.now().isoformat(),
                'total_nodes': len(config['proxies']),
                'ss_nodes': len([n for n in config['proxies'] if n.get('type') == 'ss']),
                'vmess_nodes': len([n for n in config['proxies'] if n.get('type') == 'vmess']),
                'vless_nodes': len([n for n in config['proxies'] if n.get('type') == 'vless']),
                'trojan_nodes': len([n for n in config['proxies'] if n.get('type') == 'trojan']),
            }
            
            with open('output/stats.json', 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            
            print("\n" + "=" * 60)
            print("✅ 成功！配置文件已生成")
            print("=" * 60)
            print(f"📊 统计信息:")
            print(f"   总节点数: {stats['total_nodes']}")
            print(f"   SS 节点: {stats['ss_nodes']}")
            print(f"   VMess 节点: {stats['vmess_nodes']}")
            print(f"   VLESS 节点: {stats['vless_nodes']}")
            print(f"   Trojan 节点: {stats['trojan_nodes']}")
            print(f"\n📁 输出文件:")
            print(f"   • output/nodes.yaml      (完整配置)")
            print(f"   • output/proxies.yaml    (纯代理列表)")
            print(f"   • output/stats.json      (统计信息)")
            print("=" * 60)
            
            return 0
        
        except Exception as e:
            print(f"\n❌ 文件写入失败: {e}")
            return 1
    
    else:
        print("❌ 配置生成失败")
        return 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
