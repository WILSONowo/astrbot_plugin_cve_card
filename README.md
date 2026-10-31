# CVE 漏洞卡片

AstrBot 插件：识别 CVE 编号和网址，生成漏洞长图，并订阅 CISA KEV 新增记录。支持 QQ/OneBot 合并转发。

## 致谢与来源

本项目的 KEV 增量预警设计参考了 [imdecimo（decimo）](https://github.com/imdecimo) 的 [astrbot_plugin_cve_warning](https://github.com/imdecimo/astrbot_plugin_cve_warning)。感谢原作者的工作。

本仓库为独立插件实现，使用不同的插件名称与配置；并非原项目的官方版本。采用 [GPL-3.0](LICENSE) 许可。

## 安装

AstrBot 插件管理中通过仓库地址安装：

https://github.com/WILSONowo/astrbot_plugin_cve_card

要求 Python 3.11+、AstrBot 4.29.1+，并配置可用的 HTML/T2I 渲染服务。

## 使用

- 发送 CVE 编号或 CVE 官方记录网址，自动解析。
- /cve CVE-2024-3094：主动查询，支持多个编号。
- /获取推送：管理员获取最新一批 KEV，回复当前会话，不改变定时推送基线。
- /cve推送状态：查看推送状态。
- /cve推送刷新：立即检查新增并尝试补发。

QQ/OneBot 超过两条才合并转发；一至两条普通图文。文字和链接位于图片前。

## 定时推送

默认关闭。开启 push_enabled，将 /sid 返回的完整会话标识加入 target_sessions。支持纯标识以及 UMO 提示包装。

首次建立基线，不发送历史记录；之后推送新收录的 KEV。默认每六小时检查、每批最多五条。队列按会话持久化，发送失败保留到后续重试。新增目标不补发历史；移除目标会删除其待发送队列。

KEV 是已知被利用漏洞目录，并不涵盖全部新发布 CVE。本插件不提供 AI 摘要或 NVD 二次评分。

## 数据与回退

优先读取 CVE Services 官方 JSON，支持官方 GitHub 数据备用源。完整长图包括 CNA/ADP、描述、CVSS、受影响版本和参考链接等。

官方状态明确时按其状态展示。404 或网络失败不能证明 RESERVED，此时若 KEV 有记录则以 UNKNOWN 状态渲染，并标明 CISA KEV 来源。明确 RESERVED 但无 KEV 内容时生成简洁状态卡。未实现官网网页状态提取。

缺失评分和日期显示 N/A。渲染失败保留简短文字与原文链接。

查询用 KEV 内存缓存默认一小时，kev_cache_ttl 可设 60–86400 秒；支持 ETag、并发复用和失败冷却。过期数据获取失败不继续使用旧数据，重载后清空。此缓存不修改推送基线。

## 主要配置

| 配置 | 默认 | 说明 |
|---|---|---|
| auto_detect / auto_private | true | 群消息及私聊自动识别 |
| auto_groups / disabled_groups | [] | 自动识别白名单 / 黑名单 |
| max_ids | 3 | 每条最多查询编号数，1–5 |
| cooldown_seconds / dedupe_seconds | 15 / 120 | 自动识别冷却与重复编号去重 |
| query_forward / push_forward | true | QQ 多条结果合并转发 |
| push_enabled | false | 定时推送开关 |
| target_sessions | [] | 完整目标会话标识 |
| push_interval_hours | 6 | 检查间隔 |
| max_items_per_message | 5 | 推送及手动获取批量上限 |
| admin_users | [] | 额外管理员，AstrBot 管理员始终有权限 |
| failure_notify_sessions | [] | 失败及恢复通知目标 |
| proxy / trust_env | 空 / false | HTTP(S) 代理及是否读取环境代理 |
| kev_cache_ttl | 3600 | 查询回退 KEV 缓存秒数 |

全部设置见 _conf_schema.json。proxy 控制 CVE/KEV 请求，T2I 使用 AstrBot 的配置。

## 开发与验证

安装 requirements-dev.txt 后运行 python -m pytest -q。当前 103 项测试通过。
事件与消息组件测试使用接口替身；测试通过不等于 QQ 客户端最终展示验收。发送成功判定以适配器是否报错为准。

## 数据来源

- [CVE Program](https://www.cve.org/)
- [CVE 官方数据仓库](https://github.com/CVEProject/cvelistV5)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVE 数据使用条款](https://www.cve.org/Legal/TermsOfUse)
