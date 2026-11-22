# sre-escalation-policy-conflict-analyzer

分析值班升级策略、静默和依赖告警冲突。

> **注意：本工具只计算通知计划，从不发送真实通知。** 输出是纯粹的 JSON 分析结果，
> 用于离线评估升级策略、复盘告警风暴和验证静默/抑制配置。

## 环境

- Node.js >= 24.16.0（开发版本 24.16.0）
- 无第三方依赖

## 使用

```bash
node bin/analyze.js examples/scenario.json
```

输入为一个 JSON 场景文件：

- `events`：告警事件，含 `fingerprint`、`source`（metric / log / business）、
  `severity`、`labels`、`startsAt`、`endsAt`
- `rootCauses`：根因关系边 `{ upstream, downstream }`（按 fingerprint 关联）
- `silences`：静默窗口，含 `matchers` 与起止时间
- `escalationPolicies`：升级策略，`match` 匹配条件 + `levels`（`afterMinutes` 后通知哪些值班组）
- `oncall`：值班表，每个值班组的排班区间与值班人
- `raceWindowMinutes`：升级竞争判定窗口（默认 5 分钟）

## 分析规则

- **去重**：仅按完全相同的 fingerprint 合并；标签相似但 fingerprint 不同的
  独立故障绝不合并、绝不互相抑制
- **合并**：通过根因边连通的事件共享原因，合并为一个通知组，
  以最高 severity 的事件为代表
- **抑制**：上游根因被静默时，下游告警在静默窗口内被抑制；
  静默解除后通知时钟从解除时刻重新计时
- **升级**：按策略层级在 `notifyFrom + afterMinutes` 触发，
  通知对象按触发时刻的值班表解析；事件关闭后未触发的层级被跳过
- **关闭**：事件恢复（`endsAt`）时向最后一级值班组发送关闭通知

## 输出

- `notificationPlan`：每个事件组应通知谁、何时升级、何时关闭
- `suppressionChains`：抑制链（被抑制者 ← 上游根因 ← 静默窗口）
- `conflicts`：升级冲突，包括 `policy-overlap`（多策略命中）、
  `no-oncall-coverage`（值班表空窗）、`escalation-race`（独立故障同时竞争同一值班组）
- `evidence`：每个 fingerprint 的判定证据（去重、合并、静默、抑制、跳过的层级）

## 测试

```bash
node --test
```

覆盖多源告警（metric / log / business 不同 severity 升级到同一值班组）、
静默解除后重新计时、独立故障不被误抑制、升级竞争、重复事件去重、
恢复关闭与值班表轮换。
