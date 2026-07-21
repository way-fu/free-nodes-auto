#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadowrocket 节点爬虫优化版
✨ 正确处理 Base64 订阅格式 + 多源备份 + 基础节点验证
"""

import requests
import base64
import json
import os
import re
import socket
import time
import threading
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== 📡 高可用节点源配置 ====================
SOURCES = [
    # 主源（高活性）
    'https://raw.githubusercontent.com/free18/v2ray/main/v.txt',
    'https://raw.githubusercontent.com/freefq/free/master/v2',
    'https://raw.githubusercontent.com/v2ray-links/v2ray-free-node/main/v2ray',
    'https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash.yml',
    # 备用源
    'https://raw.githubusercontent.com/Jsnzkpg/Jsnzkpg/Jsnzkpg/1',
]

def fetch_with_retry(url, timeout=15, retries=2):
    """带重试的网络请求"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                return response.text.strip()
        except Exception as e:
            if attempt < retries - 1:
                continue
    return ""

def parse_nodes(content):
    """
    解析内容中的所有有效节点
    支持格式：vmess:// ss:// vless:// trojan:// 
    """
    nodes = []
    if not content:
        return nodes
    
    # 方案 1：尝试 Base64 解码（如果内容本身是 Base64 编码的订阅）
    decoded_content = content
    try:
        # 补齐 Base64 填充
        missing_padding = len(content) % 4
        if missing_padding:
            test_content = content + '=' * (4 - missing_padding)
        else:
            test_content = content
            
        decoded_text = base64.b64decode(test_content).decode('utf-8', errors='ignore')
        # 如果解码成功且包含节点链接，使用解码后的内容
        if any(proto in decoded_text for proto in ['vmess://', 'ss://', 'vless://', 'trojan://']):
            decoded_content = decoded_text
    except:
        pass
    
    # 方案 2：正则提取所有节点链接
    node_patterns = [
        r'(vmess://[A-Za-z0-9+/=\-_]+)',
        r'(ss://[A-Za-z0-9+/=\-_]+)',
        r'(vless://[A-Za-z0-9+/=\-_:@\.]+)',
        r'(trojan://[A-Za-z0-9+/=\-_:@\.]+)',
    ]
    
    for pattern in node_patterns:
        matches = re.findall(pattern, decoded_content)
        nodes.extend(matches)
    
    # 去重
    nodes = list(set(nodes))
    return nodes

def validate_node(node_str):
    """
    基础节点格式验证
    """
    try:
        # 检查是否以支持的协议开头
        if not any(node_str.startswith(proto) for proto in ['vmess://', 'ss://', 'vless://', 'trojan://']):
            return False
        
        # vmess 节点需要能解码
        if node_str.startswith('vmess://'):
            payload = node_str.replace('vmess://', '')
            missing_padding = len(payload) % 4
            if missing_padding:
                payload += '=' * (4 - missing_padding)
            base64.b64decode(payload)
            return True
        
        # 其他格式基础检查（不深度验证）
        return len(node_str) > 30  # 最少长度检查
    except:
        return False

class NodeTester:
    """节点延迟测试器"""
    
    def __init__(self, timeout=5, max_workers=10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = {}
    
    def parse_vmess(self, node_str):
        """解析 vmess 节点获取 host 和 port"""
        try:
            payload = node_str.replace('vmess://', '')
            missing_padding = len(payload) % 4
            if missing_padding:
                payload += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(payload).decode('utf-8')
            data = json.loads(decoded)
            
            host = data.get('add') or data.get('server')
            port = data.get('port', 80)
            return host, int(port)
        except:
            return None, None
    
    def parse_ss(self, node_str):
        """解析 ss 节点获取 host 和 port"""
        try:
            # ss://method:password@host:port/?...
            content = node_str.replace('ss://', '')
            
            # 处理可能的路径参数
            if '/?#' in content or '/#' in content:
                content = content.split('/?')[0].split('/#')[0]
            
            # 分离认证部分和地址部分
            if '@' in content:
                auth, addr = content.rsplit('@', 1)
            else:
                return None, None
            
            # 解析地址和端口
            if ':' in addr:
                host, port = addr.rsplit(':', 1)
                try:
                    return host, int(port)
                except:
                    return None, None
        except:
            pass
        return None, None
    
    def parse_vless(self, node_str):
        """解析 vless 节点获取 host 和 port"""
        try:
            # vless://uuid@host:port/?...
            content = node_str.replace('vless://', '')
            
            if '@' in content:
                _, addr_part = content.split('@', 1)
                # 移除查询参数
                if '?' in addr_part:
                    addr_part = addr_part.split('?')[0]
                
                if ':' in addr_part:
                    host, port = addr_part.rsplit(':', 1)
                    try:
                        return host, int(port)
                    except:
                        return None, None
        except:
            pass
        return None, None
    
    def parse_trojan(self, node_str):
        """解析 trojan 节点获取 host 和 port"""
        try:
            # trojan://password@host:port/?...
            content = node_str.replace('trojan://', '')
            
            if '@' in content:
                _, addr_part = content.split('@', 1)
                # 移除查询参数
                if '?' in addr_part:
                    addr_part = addr_part.split('?')[0]
                
                if ':' in addr_part:
                    host, port = addr_part.rsplit(':', 1)
                    try:
                        return host, int(port)
                    except:
                        return None, None
        except:
            pass
        return None, None
    
    def extract_host_port(self, node_str):
        """从节点字符串提取 host 和 port"""
        if node_str.startswith('vmess://'):
            return self.parse_vmess(node_str)
        elif node_str.startswith('ss://'):
            return self.parse_ss(node_str)
        elif node_str.startswith('vless://'):
            return self.parse_vless(node_str)
        elif node_str.startswith('trojan://'):
            return self.parse_trojan(node_str)
        return None, None
    
    def tcp_ping(self, host, port):
        """TCP 连接测试 (最可靠)"""
        if not host or not port:
            return None
        
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.close()
            
            latency = (time.time() - start_time) * 1000  # 转换为毫秒
            return latency
        except socket.timeout:
            return None
        except Exception:
            return None
    
    def test_single_node(self, node_str, index):
        """测试单个节点"""
        protocol = node_str.split('://')[0] if '://' in node_str else 'unknown'
        
        try:
            host, port = self.extract_host_port(node_str)
            
            if not host or not port:
                return {
                    'node': node_str,
                    'protocol': protocol,
                    'latency': None,
                    'status': '❌ 解析失败',
                    'host': None,
                    'port': None
                }
            
            latency = self.tcp_ping(host, port)
            
            if latency is not None:
                status = '✅ 可用'
                if latency > 500:
                    status = '⚠️ 延迟高'
            else:
                status = '❌ 不可达'
                latency = 9999
            
            return {
                'node': node_str,
                'protocol': protocol,
                'latency': latency,
                'status': status,
                'host': host,
                'port': port
            }
        
        except Exception as e:
            return {
                'node': node_str,
                'protocol': protocol,
                'latency': None,
                'status': f'❌ 错误: {str(e)[:20]}',
                'host': None,
                'port': None
            }
    
    def test_nodes(self, nodes, show_progress=True):
        """并发测试多个节点"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.test_single_node, node, idx): idx 
                for idx, node in enumerate(nodes)
            }
            
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1
                
                if show_progress:
                    latency_str = f"{result['latency']:.0f}ms" if result['latency'] and result['latency'] < 9999 else "∞"
                    print(f"  [{completed:2d}/{len(nodes)}] {result['protocol']:8s} → {latency_str:8s} {result['status']}")
        
        # 按延迟排序
        results.sort(key=lambda x: x['latency'] if x['latency'] else 9999)
        
        return results

def main():
    print("🚀 Shadowrocket 节点爬虫 v2 启动...\n")
    
    all_nodes = []
    
    # 🔄 从多个源并行采集
    print("📥 从多个源采集节点...")
    for idx, url in enumerate(SOURCES, 1):
        print(f"  [{idx}/{len(SOURCES)}] 正在拉取: {url.split('/')[-1]}...", end=' ')
        content = fetch_with_retry(url)
        
        if content:
            nodes = parse_nodes(content)
            all_nodes.extend(nodes)
            print(f"✅ 获取 {len(nodes)} 个节点")
        else:
            print("⚠️ 超时或失败")
    
    # 🧹 去重
    unique_nodes = list(set(all_nodes))
    print(f"\n📊 去重后总计: {len(unique_nodes)} 个节点")
    
    # ✅ 验证节点格式
    print("🔍 验证节点格式...", end=' ')
    valid_nodes = [n for n in unique_nodes if validate_node(n)]
    print(f"✅ 有效节点: {len(valid_nodes)} 个")
    
    # 🎯 限制在 25 个（测试前先截断，节省时间）
    if len(valid_nodes) > 25:
        valid_nodes = valid_nodes[:25]
        print(f"📍 截断到 25 个节点（测试前）")
    
    # ⚡ 节点延迟测试
    print("\n⚡ 开始延迟测试（TCP 连接）...\n")
    tester = NodeTester(timeout=5, max_workers=10)
    test_results = tester.test_nodes(valid_nodes)
    
    # 🟢 筛选可用节点（延迟 < 5000ms）
    available_nodes = [r for r in test_results if r['latency'] and r['latency'] < 5000]
    
    print(f"\n📊 测试完成:")
    print(f"  ✅ 可用节点: {len(available_nodes)} 个")
    print(f"  ❌ 不可用: {len(test_results) - len(available_nodes)} 个")
    
    if available_nodes:
        avg_latency = sum(r['latency'] for r in available_nodes) / len(available_nodes)
        min_latency = min(r['latency'] for r in available_nodes)
        max_latency = max(r['latency'] for r in available_nodes)
        print(f"  📈 延迟统计: 最低={min_latency:.0f}ms, 平均={avg_latency:.0f}ms, 最高={max_latency:.0f}ms")
    
    # 提取可用节点的链接
    valid_nodes = [r['node'] for r in available_nodes]
    
    if not valid_nodes:
        print("❌ 没有获取到任何有效节点！")
        return 1
    
    # 💾 生成输出
    os.makedirs('output', exist_ok=True)
    
    print("\n💾 生成输出文件...\n")
    
    # 方案 A：Base64 订阅格式（直接导入 Shadowrocket）
    # ✨ 这是 Shadowrocket 最认可的格式
    base64_content = base64.b64encode('\n'.join(valid_nodes).encode('utf-8')).decode('utf-8')
    
    with open('output/nodes_base64.txt', 'w', encoding='utf-8') as f:
        f.write(base64_content)
    print(f"✅ output/nodes_base64.txt - Base64 订阅链接")
    print(f"   💡 在 Shadowrocket 中用「添加」→「粘贴 URL」导入此内容的 Base64")
    
    # 方案 B：明文节点格式（每行一个）
    with open('output/nodes_plain.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_nodes))
    print(f"✅ output/nodes_plain.txt - 明文节点列表")
    
    # 方案 C：标准 YAML 格式（兼容 Clash/Shadowrocket）
    yaml_content = "proxies:\n"
    for i, node in enumerate(valid_nodes, 1):
        yaml_content += f"  # Node {i}\n  - {node}\n"
    
    with open('output/nodes.yaml', 'w', encoding='utf-8') as f:
        f.write(yaml_content)
    print(f"✅ output/nodes.yaml - Clash/YAML 格式")
    
    # 方案 D：详细的测试结果报告
    test_report = []
    for idx, result in enumerate(test_results, 1):
        latency_str = f"{result['latency']:.0f}ms" if result['latency'] and result['latency'] < 9999 else "超时"
        test_report.append({
            'rank': idx,
            'protocol': result['protocol'],
            'host': result['host'],
            'port': result['port'],
            'latency_ms': result['latency'],
            'status': result['status'],
        })
    
    with open('output/test_results.json', 'w', encoding='utf-8') as f:
        json.dump(test_report, f, ensure_ascii=False, indent=2)
    print(f"✅ output/test_results.json - 详细测试结果")
    
    # 方案 E：统计信息
    stats = {
        'updated_at': datetime.now().isoformat(),
        'total_nodes_collected': len(unique_nodes),
        'total_nodes_valid': len(test_results),
        'total_nodes_available': len(available_nodes),
        'protocols': {
            'vmess': sum(1 for n in valid_nodes if n.startswith('vmess://')),
            'ss': sum(1 for n in valid_nodes if n.startswith('ss://')),
            'vless': sum(1 for n in valid_nodes if n.startswith('vless://')),
            'trojan': sum(1 for n in valid_nodes if n.startswith('trojan://')),
        },
        'latency_stats': {
            'min_ms': min((r['latency'] for r in available_nodes if r['latency']), default=None),
            'max_ms': max((r['latency'] for r in available_nodes if r['latency']), default=None),
            'avg_ms': sum(r['latency'] for r in available_nodes if r['latency']) / len(available_nodes) if available_nodes else None,
        },
        'sources_tried': len(SOURCES),
    }
    
    with open('output/stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"✅ output/stats.json - 统计信息")
    
    # 📋 显示统计
    print(f"\n📊 最终统计:")
    print(f"  采集总数: {stats['total_nodes_collected']} 个")
    print(f"  格式有效: {stats['total_nodes_valid']} 个")
    print(f"  测试可用: {stats['total_nodes_available']} 个")
    print(f"\n  协议分布: vmess={stats['protocols']['vmess']} ss={stats['protocols']['ss']} "
          f"vless={stats['protocols']['vless']} trojan={stats['protocols']['trojan']}")
    
    if stats['latency_stats']['avg_ms']:
        print(f"\n  延迟分布: 最低={stats['latency_stats']['min_ms']:.0f}ms, "
              f"平均={stats['latency_stats']['avg_ms']:.0f}ms, "
              f"最高={stats['latency_stats']['max_ms']:.0f}ms")
    
    print(f"\n✨ 任务完成！所有文件已生成到 ./output/ 目录\n")
    print(f"📁 输出文件列表:")
    print(f"  • nodes_base64.txt      - Base64 订阅格式（推荐导入）")
    print(f"  • nodes_plain.txt       - 明文节点列表")
    print(f"  • nodes.yaml            - YAML 配置格式")
    print(f"  • test_results.json     - 详细测试结果（包含延迟和状态）")
    print(f"  • stats.json            - 汇总统计信息")
    
    print(f"\n💡 使用建议:")
    print(f"  1️⃣  复制 output/nodes_base64.txt 的全部内容")
    print(f"  2️⃣  在 Shadowrocket: 设置 → 添加 → 粘贴 URL")
    print(f"  3️⃣  只导入已测试可用的节点（延迟 < 5000ms）")
    print(f"  4️⃣  查看 test_results.json 了解各节点详情")
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
