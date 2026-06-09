#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import yaml

def main():
    print("🚀 正在执行控制变量测试第二步：注入 Clash 标准外壳...")
    
    # 保持这 2 个手写测试节点不变
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
    
    # ✨ 核心注入：构建小火箭 Clash 解析内核所必须的基础骨架
    clash_config = {
        'mixed-port': 7890,
        'mode': 'rule',
        'log-level': 'info',
        'proxies': test_proxies,  # 注入节点
        'proxy-groups': [         # 注入基础策略组
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['TEST_SS_01', 'TEST_SS_02']
            }
        ],
        'rules': [
            'MATCH,🚀 节点选择'
        ]
    }
    
    os.makedirs('output', exist_ok=True)
    
    # 保存覆盖原来的 proxies.yaml
    with open('output/proxies.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
    print("✨ 标准 Clash 配置文件外壳已完美生成。")
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
