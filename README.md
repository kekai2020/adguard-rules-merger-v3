# AdGuard Rules Merger V3

自动合并多个 AdGuard Home 拦截规则订阅源，实现智能去重和优化。

## V3 新特性

- **异步 IO** — `aiohttp` + `asyncio` 真正并发获取，20 并发协程
- **流式处理** — 生成器逐行解析，内存占用低
- **增量缓存** — ETag / Last-Modified 缓存，未变化的源跳过下载
- **现代 CLI** — `typer` + `rich` 进度条和彩色表格
- **三阶段去重** — 精确去重 + 通配符覆盖 + Allow 覆盖 Block
- **来源追踪** — 每条规则记录所有贡献源

## 快速开始

```bash
pip install -r requirements.txt

# 基本合并
python merge_rules.py merge -c config/sources.yaml

# 带报告和验证
python merge_rules.py merge -c config/sources.yaml --report --verify

# 禁用缓存（全量下载）
python merge_rules.py merge -c config/sources.yaml --no-cache

# 查看缓存状态
python merge_rules.py cache-stats

# 清除缓存
python merge_rules.py cache-clear
```

## 去重算法

```
Phase 1: 精确去重 — key=(domain, type, wildcard), 合并来源集合
Phase 2: 通配符覆盖 — DomainTrie 移除子域名 (*.a.com 移除 sub.a.com)
Phase 3: Allow 覆盖 Block — 同域名 block+allow → 保留 allow
```

## 项目结构

```
merger/
  __init__.py       v3.0.0
  core.py           异步 RuleEngine + DomainTrie + DedupReport
  models.py         Rule 数据模型
  parser.py         流式 RuleParser (生成器)
  reporter.py       MergeReporter
  cache.py          ETag/Last-Modified 增量缓存 🆕
config/
  sources.yaml      订阅源配置
tests/
  test_core.py      47 个测试
merge_rules.py      typer CLI (merge/cache-stats/cache-clear)
validate_output.py  独立验证工具
config_loader.py    配置加载
```

## 缓存机制

首次运行全量下载，后续运行：
- 发送 `If-None-Match` / `If-Modified-Since` 请求头
- 源返回 304 → 直接用缓存，跳过解析
- 缓存 TTL 默认 3600 秒，可通过 `--cache-ttl` 调整
- GitHub Actions 中用 `actions/cache` 持久化缓存目录

## 测试

```bash
pytest tests/ -v
```

## License

MIT
