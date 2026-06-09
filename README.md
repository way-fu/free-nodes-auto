# 小火箭节点爬虫优化说明

## 🔧 主要改进点

### 1. **扩充源列表** ⭐

- 添加了 **Ghproxy 镜像源**（突破 GFW 限制）
- 添加了 **V2Ray 订阅格式源**（支持更多节点类型）
- 每个源都配备了多个备用镜像地址
- 总共 11 个 YAML 源 + 2 个订阅源

```python
# 新增 Ghproxy 镜像加速
'https://ghproxy.com/https://raw.githubusercontent.com/goer998/Free-nodes/main/clash.yaml'

# 新增 V2Ray 订阅源
'https://raw.githubusercontent.com/YJLLQ/V2rayDomain/main/v2ray'
```

### 2. **增强网络容错** ⭐

- 添加了 **指数退避重试机制**（自动延迟后重试）
- 单个源失败不影响其他源
- 超时时间调整为 30 秒（给予更长的容错空间）
- 重试次数：2 次

```python
def fetch_content(url, timeout=30, retries=2):
    for attempt in range(retries):
        try:
            # ... 请求逻辑
            time.sleep(2 ** attempt)  # 指数延迟：2s, 4s...
```

### 3. **放宽验证条件** ⭐

**问题**：原脚本过度验证导致很多有效节点被过滤

**改进**：

- 允许 `uuid` 或 `id` 字段存在即可（不强制某一个）
- 允许没有 `password` 但有 `cipher` 的 SS 节点
- 支持 `shadowsocks` 类型（自动转换为 `ss`）
- 端口范围验证：`1-65535`（更灵活）

```python
# 原代码：必须同时有 uuid 和 password
if node_type == 'vmess' and not node.get('uuid'): 
    return None

# 优化后：uuid 或 id 其中之一即可
if node_type == 'vmess':
    if not node.get('uuid') and not node.get('id'):
        return None
```

### 4. **改进 YAML 解析容错** ⭐

- 支持多种异常处理（YAMLError, ValueError 等）
- 详细的错误日志提示
- 不会因为一个 YAML 源格式错误就中止

```python
try:
    data = yaml.safe_load(sanitized_content)
except yaml.YAMLError as e:
    print(f"⚠️ YAML 解析失败: {str(e)[:60]}...")
    return []
```

### 5. **新增 V2Ray 订阅解析** ⭐

支持解析 Base64 编码的 V2Ray 订阅格式

```python
# 可以解析 vmess:// 和 vless:// 链接
vmess_pattern = r'vmess://[A-Za-z0-9+/=]+'
vless_pattern = r'vless://[A-Za-z0-9+/=\-._~:/?#\[\]@!$&\'()*+,;=]+'
```

### 6. **更好的日志反馈**

- 阶段化输出（YAML 源 → 订阅源 → 去重 → 生成）
- 详细的成功/失败计数
- 最终统计按节点类型分类

```
📥 [阶段1] 从 YAML 源抓取节点...
   [1/13] https://cdn.jsdelivr.net/...
      ✅ 成功获取 12 个节点 (累计: 12)
   ✅ YAML 阶段完成: 8/13 源成功

📥 [阶段2] 从订阅源抓取节点...
   ✅ 成功获取 5 个节点 (累计: 17)

📊 统计信息:
   总节点数: 42
   SS 节点: 15
   VMess 节点: 12
   VLESS 节点: 8
   Trojan 节点: 7
```

### 7. **去重逻辑改进**

- 原本用凭证参与去重（存在泄露风险）
- 现在仅用 `type://server:port` 去重（安全且高效）

```python
# 安全的去重 key
key = f"{node_type}://{server}:{port}"
```

### 8. **DNS 配置优化**

添加了更多可靠的 DNS：

- 223.5.5.5 (阿里云)
- 8.8.8.8 (Google)
- 1.1.1.1 (Cloudflare) ✨ 新增
- DNS-over-HTTPS 支持

### 9. **节点数量限制调整**

- 原来：最多 120 个
- 优化后：最多 200 个（给小火箭更多选择）
- 自动选择测试仅取前 100 个（性能平衡）

-----

## 🚀 使用方法

### 安装依赖

```bash
pip install requests pyyaml
```

### 运行脚本

```bash
python optimized_nodes_crawler.py
```

### 输出文件

脚本会在 `output/` 目录下生成：

1. **nodes.yaml** - 完整的 Clash 配置
- 包含所有代理规则
- 包含节点分组和自动选择
- 可直接导入小火箭
1. **proxies.yaml** - 纯代理列表
- 只包含代理信息
- 可用于其他工具
1. **stats.json** - 统计信息
- 更新时间戳
- 各类型节点数量

-----

## 📋 源列表说明

### 为什么有多个源？

- **容错**：某个源失效时，其他源仍能工作
- **多样性**：不同源的节点集合不同
- **地理分布**：加快访问速度

### 源的优先级

1. **Jsdelivr** - CDN 加速，速度最快，国内可用性最好
1. **Ghproxy** - 镜像加速，突破 GFW，次选
1. **FastGit** - 备用加速源
1. **直接源** - 兜底方案，速度可能较慢

-----

## ⚡ 常见问题

### Q: 仍然没有获取到节点？

**尝试以下步骤：**

1. **检查网络连接**
   
   ```bash
   ping cdn.jsdelivr.net
   ```
1. **检查源是否可访问**
   在浏览器打开这个 URL：
   
   ```
   https://cdn.jsdelivr.net/gh/goer998/Free-nodes@main/clash.yaml
   ```
   
   如果能看到 YAML 内容，说明网络没问题
1. **调整超时时间**
   
   ```python
   # 在脚本中修改
   content = fetch_content(url, timeout=45, retries=3)  # 增加超时和重试
   ```
1. **手动测试源**
   
   ```python
   import requests
   resp = requests.get('https://cdn.jsdelivr.net/gh/goer998/Free-nodes@main/clash.yaml', timeout=30)
   print(resp.status_code)
   print(resp.text[:500])
   ```

### Q: 怎样添加自己的节点源？

在源列表中添加新的 URL：

```python
SOURCES_YAML = [
    # ... 现有源
    'https://你的源地址/clash.yaml',  # 新增
]
```

### Q: 如何只保留某个类型的节点？

修改 `deduplicate_nodes()` 后添加筛选：

```python
# 只保留 VMess 节点
unique_nodes = [n for n in deduplicate_nodes(all_nodes) if n.get('type') == 'vmess']
```

### Q: 小火箭无法识别节点？

常见原因：

- 节点格式不标准
- 缺少必要字段（server, port, uuid/password）
- 特殊字符未正确编码

**排查方法**：
打开 `output/stats.json` 检查节点数量是否正常，然后在小火箭中手动添加一个测试节点，观察错误提示。

-----

## 🔐 安全提示

⚠️ **重要**：免费节点来自开放源，可能存在风险：

- 不要用于传输敏感信息（银行账户、密码等）
- 定期更新节点列表
- 建议配合 DNS 加密使用
- 考虑付费的商业 VPN 以获得更好的隐私保护

-----

## 📈 性能优化建议

1. **自动测试间隔**
   
   ```yaml
   interval: 300  # 5 分钟测试一次
   tolerance: 100  # 延迟波动 100ms 以内才切换
   ```
1. **分类节点池**
   使用不同节点类型的独立测试组，以便根据网络环境灵活选择
1. **缓存策略**
- 每周运行一次爬虫
- 保留上次的配置作为备份

-----

## 🔄 推荐的自动化方案

### GitHub Actions 定时运行（免费）

创建 `.github/workflows/crawler.yml`：

```yaml
name: Update Free Nodes

on:
  schedule:
    - cron: '0 */6 * * *'  # 每 6 小时运行一次
  workflow_dispatch:

jobs:
  crawl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install requests pyyaml
      - run: python optimized_nodes_crawler.py
      - uses: actions/upload-artifact@v3
        with:
          name: nodes
          path: output/
```

-----

## 📞 故障排查清单

- [ ] 网络连接正常
- [ ] 源 URL 可访问
- [ ] Python 环本版本 >= 3.7
- [ ] 已安装 `requests` 和 `pyyaml`
- [ ] `output/` 目录可写入
- [ ] 检查日志输出中的错误信息
- [ ] 尝试使用代理工具运行脚本（如果被限流）

-----

**祝您使用愉快！如有问题，请检查错误日志并参考以上解决方案。**