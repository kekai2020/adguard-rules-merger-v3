# V2 → V3 迁移指南

## 快速迁移

### 1. 安装新依赖

```bash
pip install -r requirements.txt
# 新增依赖：aiohttp, pydantic, pydantic-settings, typer, rich, structlog
```

### 2. CLI 用法变化

**V2 用法：**
```bash
python merge_rules.py --config config/sources.yaml -o output.txt
python merge_rules.py -s URL1 URL2 -o output.txt
```

**V3 用法：**
```bash
python merge_rules.py merge --config config/sources.yaml --output output.txt
python merge_rules.py merge --sources URL1 --sources URL2 --output output.txt
```

> 注意：V3 使用子命令结构，`merge` 是合并命令。多值选项需要多次指定 `--sources`。

### 3. 配置文件变化

V3 配置文件新增了以下字段（均为可选，有默认值）：

```yaml
# 新增：全局设置
timeout: 60
max_concurrency: 50              # 原 max_workers
allow_overrides_block: true
enable_normalized_dedup: false   # 新增：模糊去重
strip_www: false                 # 新增：www 等价

# 新增：缓存设置
cache:
  enabled: true
  directory: cache
  ttl_seconds: 0
  max_size_mb: 500

# 新增：输出设置
output:
  directory: output
  filename: merged_rules.txt
  formats: [adguard]
  compress: false

# 源配置新增字段
sources:
  - name: "Example"
    url: "https://example.com/filter.txt"
    enabled: true
    category: "ads"          # 新增：分类标签
    reputation: 0.95         # 新增：信誉度评分
```

### 4. 作为库使用的变化

**V2：**
```python
from merger import RuleEngine

engine = RuleEngine(timeout=60, max_workers=10)
result = engine.merge(sources, return_stats=True)
```

**V3（完全兼容 V2 API）：**
```python
from merger import RuleEngine

# V2 兼容模式（同步）
engine = RuleEngine(timeout=60, max_workers=10)
result = engine.merge(sources, return_stats=True)

# V3 异步模式（推荐）
from merger import AsyncRuleEngine
import asyncio

async def main():
    engine = AsyncRuleEngine(
        timeout=60,
        max_concurrency=50,      # 更高并发
        cache_dir="cache",        # 启用增量缓存
        enable_normalized_dedup=True,  # 启用模糊去重
    )
    async with engine:
        result = await engine.merge(sources, return_stats=True)

asyncio.run(main())
```

## 新增功能详解

### 增量缓存

```bash
# 启用缓存（默认启用）
python merge_rules.py merge --config config/sources.yaml --cache-dir cache

# 禁用缓存
python merge_rules.py merge --config config/sources.yaml --no-cache

# 查看缓存统计
python merge_rules.py cache-stats --cache-dir cache

# 清除缓存
python merge_rules.py cache-clear --yes
```

缓存机制：
- 首次运行：下载全部内容，存储 ETag / Last-Modified / SHA-256 哈希
- 后续运行：发送条件请求，304 响应直接使用缓存
- 内容未变化时：即使返回 200，也通过哈希比较标记为缓存命中
- 网络异常时：自动回退到缓存内容

### 模糊去重（归一化）

```bash
# 启用 www 等价去重
python merge_rules.py merge --config config/sources.yaml \
  --normalized-dedup --strip-www
```

支持的归一化：
- 大小写归一：`EXAMPLE.COM` ↔ `example.com`
- 尾部点号去除：`example.com.` ↔ `example.com`
- www 前缀等价（可选）：`www.example.com` ↔ `example.com`

### 多格式输出

```bash
# 同时输出 gzip 压缩版
python merge_rules.py merge --config config/sources.yaml --compress

# 输出文件：
# output/merged_rules.txt      — AdGuard 格式
# output/merged_rules.txt.gz   — gzip 压缩
# output/stats.json            — 详细统计
```

### 规则分类

V3 为每条规则添加了 `category` 字段，支持以下分类：
- `ads` — 广告
- `malware` — 恶意软件
- `phishing` — 钓鱼
- `tracking` — 跟踪
- `mining` — 挖矿
- `other` — 其他
- `comment` — 注释

在配置文件中为每个源指定分类，解析时会自动传播到该源的所有规则。

## 性能对比

| 场景 | V2 | V3（冷启动） | V3（缓存命中） |
|------|-----|-------------|---------------|
| 14 源合并时间 | ~23s | ~15s | <5s |
| 峰值内存 | ~500MB | ~100MB | ~50MB |
| 并发连接数 | 10 | 50 | 50 |

## 向后兼容性

- ✅ `RuleEngine` 类完全兼容 V2 构造函数和 `merge()` 方法
- ✅ `Rule` 数据模型兼容（新增字段均有默认值）
- ✅ `RuleParser.parse_text()` 方法签名不变
- ✅ 三阶段去重算法逻辑不变（新增第四阶段可选）
- ✅ 配置文件格式向后兼容（新增字段均可选）
- ⚠️ CLI 从 `argparse` 改为 `typer`，命令行参数有变化
- ⚠️ 依赖从 `requests` 改为 `aiohttp`（异步）

## 常见问题

**Q: V3 可以直接替换 V2 吗？**
A: 作为库使用时可以直接替换（`RuleEngine` API 兼容）。CLI 使用时需要调整命令行参数格式。

**Q: 缓存会占用多少空间？**
A: 默认无上限，可通过 `cache.max_size_mb` 配置。14 个源约 54MB 输出，缓存总量通常在 100-200MB。

**Q: 模糊去重会误删规则吗？**
A: 默认不启用模糊去重。启用 `--strip-www` 时，`www.example.com` 和 `example.com` 会被视为等价。这在大多数情况下是安全的，但某些网站 www 和非 www 可能指向不同服务。

**Q: 如何回退到 V2？**
A: V3 的 `RuleEngine` 类提供与 V2 完全相同的同步 API。如果需要完全回退，保留 V2 代码目录即可，两者互不干扰。
