---
name: semantic-search-news
description: 语义搜索新闻（market.ft.tech）。用户问语义搜新闻、按关键词搜新闻、搜索相关新闻时使用。数据仅支持当年、最近半个月。
---

# 语义搜索新闻

## 1. 接口描述

| 项目 | 说明 |
|------|------|
| 接口名称 | 语义搜索新闻 |
| 外部接口 | `GET /data/api/v1/market/data/semantic-search-news` |
| 请求方式 | GET |
| 适用场景 | 根据搜索文字进行语义搜索，返回相关新闻列表；数据仅支持查询**当年**、**最近半个月**内的新闻 |

## 2. 请求参数

| 参数名 | 类型 | 是否必填 | 描述 | 取值示例 | 备注 |
|--------|------|----------|------|----------|------|
| query | string | 是 | 搜索文字 | 人工智能 | - |
| limit | int | 否 | 返回条数 | 10 | 默认 10 |
| year | int | 否 | 年份 | 2026 | 仅支持**当年**；数据仅保留最近半个月，用于限定搜索范围 |

## 3. 响应说明

返回 `SearchResult` 数组，按相关度排序。

```json
[
  {
    "news_id": 556106924001595392,
    "source_site": "21经济网_要闻",
    "article_url": "https://...",
    "publish_time": "2026-03-15T21:00:00",
    "fetch_time": "2026-03-15T21:19:49",
    "title": "越是AI，越需人文",
    "media_name": "21世纪经济",
    "summary": null,
    "content": "...",
    "is_truncated": 0,
    "is_reviewed": 1,
    "score": 0.6933832764625549
  }
]
```

### SearchResult 结构

| 字段名 | 类型 | 是否可为空 | 说明 |
|--------|------|------------|------|
| news_id | long | 否 | 新闻 ID |
| source_site | string | 否 | 来源站点 |
| article_url | string | 是 | 文章链接 |
| publish_time | string | 是 | 发布时间，ISO 8601 格式 |
| fetch_time | string | 否 | 抓取时间，ISO 8601 格式 |
| title | string | 是 | 标题 |
| media_name | string | 是 | 媒体名称 |
| summary | string | 是 | 摘要 |
| content | string | 否 | 正文内容 |
| is_truncated | int | 否 | 是否被截断：0=否 1=是 |
| is_reviewed | int | 否 | 是否已审核：0=否 1=是 |
| score | float | 否 | 搜索匹配分数 |

## 4. 用法

通过主目录 `run.py` 调用（必填 `--query`，可选 `--limit`、`--year`）：

```bash
python <RUN_PY> semantic-search-news --query 人工智能
python <RUN_PY> semantic-search-news --query 人工智能 --limit 10 --year 2026
```

`<RUN_PY>` 为主 SKILL.md 同级的 `run.py` 绝对路径。脚本输出 JSON；本接口无需额外请求头。

## 5. 请求示例

```
GET https://market.ft.tech/data/api/v1/market/data/semantic-search-news?query=人工智能&limit=10&year=2026
```

## 6. 数据范围与更新

- 数据仅支持**当年**、**最近半个月**内的新闻；`year` 用于限定搜索范围，仅支持当年。
- 具体可查时间范围与更新频率以接口返回为准。

## 7. 展示与用户提示

向用户展示结果时**必须**：

1. **每条新闻展示原站与链接**：列出**来源**（`source_site`：来源站点）以及**文章链接**（`article_url`），便于用户跳转原文。
2. **数据范围提示**：在结果前或结果后向用户明确提示：**「以下结果仅展示当年、最近半个月以内的新闻。」**
