#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import yaml

def main():
    print("🚀 正在执行从头开始的绝对控制变量测试...")
    
    # 🎯 纯手工写死 3 个没有任何外部网络依赖的测试节点
    test_proxies = [
        {
            "name": "TEST_SS_01",
            "type": "ss",
            "server": "1.1.1.1",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "testpassword123",
            "udp": True
        },
        {
            "name": "TEST_SS_02",
            "type": "ss",
            "server": "8.8.8.8",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "testpassword456",
            "udp": True
        }
    ]
    
    os.makedirs('output', exist_ok=True)
    
    # 💾 直接导出不带任何大 Key 外壳的纯数组
    with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(test_proxies, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
    print(f"✨ 测试文件完美写入，当前强制锁死节点数：{len(test_proxies)}")
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
