# AdGuard Rules Merger V3

> 高性能 AdGuard 过滤规则合并工具 — 异步 IO、流式处理、增量缓存

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-purple.svg)](merger/__init__.py)

## 相比 V2 的核心改进

| 特性 | V2 | V3 |
|------|-----|-----|
| **HTTP 客户端** | `requests` + 线程池 | `aiohttp` + `asyncio`（真正异步） |
| **并发数** | 10 线程 | 50-100 协程 |
| **内存占用** | ~500MB（全量加载） | ~50MB（流式处理） |
| **增量更新** | 每次全量下载 | ETag / Last-Modified / 内容哈希缓存 |
| **常规运行时间** | ~23 秒 | <5 秒（缓存命中时） |
| **去重阶段** | 3 阶段 | 4 阶段（新增归一化/模糊去重） |
| **CLI** | `argparse` | `typer` + `rich`（进度条、彩色表格） |
| **配置校验** | 手动 YAML 解析 | `pydantic` v2 模型 + JSON Schema |
| **类型注解** | 部分 | 全量（目标 >95%） |
| **规则分类** | 无 | 内置分类标签（ads/malware/phishing/...） |
| **质量评分** | 无 | 基础设施就绪（Phase 2） |
| **输出格式** | AdGuard | AdGuard + stats.json + 可选 gzip |

## 快速开始

### 安装

```bash
git clone https://github.com/kekai2020/adguard-rules-merger-v2.git
cd adguard-rules-merger-v2  # V3 代码在 v3 分支或独立目录
pip install -r requirements.txt
```

### 基本用法

```bash
# 使用配置文件合并
python merge_rules.py merge --config config/sources.yaml

# 指定源 URL
python merge_rules.py merge -s https://example.com/filter1.txt https://example.com/filter2.txt

# 生成报告 + 压缩输出
python merge_rules.py merge --config config/sources.yaml --report --compress

# 试运行（不写文件）
python merge_rules.py merge --config config/sources.yaml --dry-run

# 启用模糊去重（www 等价）
python merge_rules.py merge --config config/sources.yaml --normalized-dedup --strip-www
```

### 实用命令

```bash
# 生成默认配置
python merge_rules.py init --output config/sources.yaml

# 校验配置文件
python merge_rules.py validate config/sources.yaml

# 查看缓存统计
python merge_rules.py cache-stats

# 清除缓存
python merge_rules.py cache-clear --yes

# 查看版本
python merge_rules.py version
```

## 架构设计

### 四阶段去重算法

```
Phase 0: 归一化去重（可选）
  ├─ www 等价：www.example.com ↔ example.com
  ├─ 大小写归一
  └─ 尾部点号去除

Phase 1: 精确去重
  ├─ Key = (normalized_domain, rule_type, wildcard)
  ├─ 冲突时合并来源集合
  └─ *.a.com ≠ a.com（语义不同，均保留）

Phase 2: 通配符覆盖
  ├─ 构建 DomainTrie（TLD 优先）
  └─ *.a.com 覆盖 ads.a.com，但不覆盖 a.com

Phase 3: Allow 覆盖 Block（可选）
  └─ 同域名同时有 block 和 allow 时，保留 allow
```

### 异步流水线

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│  Source 1   │────▶│              │     │              │     │          │
├─────────────┤     │  aiohttp     │     │  Streaming   │     │  4-Phase │
│  Source 2   │────▶│  asyncio     │────▶│  Parser      │────▶│  Dedup   │
├─────────────┤     │  (50-100     │     │  (generator) │     │          │
│    ...      │     │   concurrent) │     │              │     │          │
├─────────────┤     │              │     │              │     │          │
│ Source N    │────▶│              │     │              │     │          │
└─────────────┘     └──────┬───────┘     └──────────────┘     └────┬─────┘
                            │                                            │
                     ┌──────▼──────┐                              ┌─────▼─────┐
                     │  Incremental │                              │  Output   │
                     │    Cache     │                              │  Writer   │
                     │ (ETag/304)   │                              │ (txt/gz)  │
                     └─────────────┘                              └───────────┘
```

### 增量缓存机制

```
首次运行:
  GET /filter.txt → 200 OK (ETag: "abc123")
  → 存储内容 + ETag + Last-Modified + SHA-256 哈希

后续运行:
  GET /filter.txt (If-None-Match: "abc123")
  → 304 Not Modified → 直接使用缓存内容（跳过下载和解析）
  → 200 OK → 比较内容哈希，未变则标记为缓存命中

网络异常时:
  → 自动回退到缓存内容（如果存在）
```

## 配置文件

```yaml
# 全局设置
timeout: 60
max_concurrency: 50
allow_overrides_block: true
enable_normalized_dedup: false
strip_www: false

# 缓存设置
cache:
  enabled: true
  directory: cache
  ttl_seconds: 0          # 0 = 永不过期
  max_size_mb: 500        # 0 = 无限制

# 输出设置
output:
  directory: output
  filename: merged_rules.txt
  formats: [adguard]
  compress: false
  include_stats: true

# 规则源
sources:
  - name: "AdGuard DNS filter"
    url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
    enabled: true
    category: "ads"           # ads / malware / phishing / tracking / mining / other
    reputation: 0.95          # 0.0-1.0，用于质量评分（Phase 2）
```

## 作为库使用

```python
import asyncio
from merger import AsyncRuleEngine, RuleParser, SourceMeta

# 异步用法
async def main():
    engine = AsyncRuleEngine(
        timeout=60,
        max_concurrency=50,
        cache_dir="cache",
    )
    async with engine:
        result = await engine.merge(
            ["https://example.com/filter.txt"],
            return_stats=True,
        )
        print(f"Merged {len(result['rules'])} rules")

asyncio.run(main())

# 同步用法（V2 兼容）
from merger import RuleEngine

engine = RuleEngine(timeout=60, max_workers=10)
result = engine.merge(["https://example.com/filter.txt"], return_stats=True)
```

## 测试

```bash
# 运行全部测试
pytest tests/test_core.py -v

# 运行性能基准
pytest tests/benchmark.py --benchmark-only

# 生成 JSON Schema
python -c "from config_loader import generate_json_schema; generate_json_schema()"
```

## CI/CD

GitHub Actions 工作流（`.github/workflows/merge.yml`）：

- **定时合并**：每 6 小时自动运行
- **增量缓存**：使用 `actions/cache` 持久化规则缓存
- **智能提交**：仅在规则实质变化时 commit
- **测试验证**：每次 push 运行单元测试
- **产物上传**：合并结果作为 artifact 保留 30 天

## 路线图

- [x] **Phase 1**：异步 IO + 流式处理 + 增量更新
- [ ] **Phase 2**：规则分级输出 + 质量评分 + 多格式输出（Hosts/Domains/Clash/Surge/SmartDNS）
- [ ] **Phase 3**：结构化日志（structlog）+ Prometheus 指标 + 配置热重载
- [ ] **Phase 4**：nightly/stable 分支 + 失败自动回滚 + 通知集成

## 性能对比（预估）

| 指标 | V2 | V3（冷启动） | V3（缓存命中） |
|------|-----|-------------|---------------|
| 14 源合并时间 | ~23s | ~15s | <5s |
| 峰值内存 | ~500MB | ~100MB | ~50MB |
| 并发连接数 | 10 | 50 | 50 |
| 带宽消耗 | 全量 | 全量 | 仅变化源 |

## License

MIT
