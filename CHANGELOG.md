# 更新日志

本文件记录本项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中

- WebSocket / GraphQL 支持
- 参数值自动变形（同身份的横向越权检测）
- 命中项导出为可复现的验证脚本（方便在报告里附证据）

---

## [0.1.0] - 2026-09-18

首个可用版本。

### 新增

**越权（IDOR）自动检测**

基于**三态对比**的检测模型：

```
① 基准请求（受害者身份，id=X）      → R0
② 换第二身份重放（攻击者，id=X）    → R1
③ 对照请求（攻击者，id=不存在的值） → R2

R1 ≈ R0 且 R2 ≉ R0  →  疑似越权
R1 ≈ R0 且 R2 ≈ R0  →  通配响应，判为误报丢弃
R1 ≉ R0             →  权限校验有效
```

第 ③ 步是核心：它排除了「该接口对任何 ID 都返回固定内容」这类假阳性，
而这正是同类工具（Autorize / AuthMatrix 等）误报的主要来源。

**ID 参数识别**（`core/ParamHeuristics`）

- 命名模式 + 值形态双维度判断
- 含噪声排除表（分页 / 排序 / 时间戳 / 版本号 / 鉴权 token）
- **每个判定都带理由** —— 使用者能看到「为什么我认为这是个 ID 参数」，
  而不是只拿到一个结论

**响应相似度**（`core/ResponseComparator`）

- 先标准化（去 CSRF token / 会话 ID / 时间戳 / traceId / 长十六进制串）
- 再算 5-gram Jaccard 相似度，与状态码（权重 0.3）、Content-Type（0.1）加权
- 状态码权重高是有原因的：302 跳转和 200 正常响应即使正文都为空，
  语义也完全不同 —— 前者通常意味着「被踢到登录页了」，
  那其实是权限校验在起作用

**配置面板**（`ui/ConfigPanel`）

- Swing 界面，含**实时状态提示** —— 明确显示当前会不会发请求

### 安全设计

- **默认不发送任何请求**：装上后只做被动观察，
  必须显式配置第二身份并勾选启用才会开始检测
- 仅对 GET / HEAD / OPTIONS 生效（避免误改业务数据）
- 限速 100ms + 单 host 候选上限 50
- 凭据脱敏（日志与 Issue 详情里只显示 `JSESSI****cdef` 形式）

### 工程化

- Java 21 + Burp Montoya API 2026.7，**零第三方运行时依赖**
- Maven 构建；先用 `javap` 确认全部接口签名，核心代码**一次编译通过**
- **81 个单元测试**（JUnit 5）——
  `core/` 层不依赖 Burp 运行时，所以能脱离 Burp 单独跑
- GitHub Actions CI：编译 + 测试 + jar 产物校验
  （含一条「Montoya API 不得被打进 jar」的检查 ——
  打进去会与 Burp 自带的 API 冲突）

### 修复

开发过程中抓到两个真实 bug，都写进了代码注释：

- **`Set.of()` 不允许重复元素**：`ID_KEYWORDS` 里 `"uid"` 写了两次，
  导致类静态初始化抛异常 → `ExceptionInInitializerError` → 整个类不可用，
  32 个测试全部报 `NoClassDefFound`。
  **编译期发现不了** —— 重复检查是运行时的，只有测试能抓到

- **`URI.getRawPath()` 对无路径 URL 返回空串而非 null**：
  `new URI("https://example.com").getRawPath()` 返回 `""`，
  只判 `== null` 会得到空路径，而 `withPath("")` 会构造出一个非法请求。
  同一个错误在 `pathAndQueryOf` 和 `ParsedRequest.parse` 里各有一处

---

[Unreleased]: https://github.com/hediwen831-star/burp-idor-detector/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hediwen831-star/burp-idor-detector/releases/tag/v0.1.0
