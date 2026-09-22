# 更新日志

本文件记录本项目所有值得注意的变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 修复

- 相似度计算中 Content-Type 一档与注释描述的语义不一致。两侧都没有
  Content-Type 头时给 0.05 分而非满分 0.1，导致两个逐字节相同的响应相似度
  上限为 0.95。默认阈值 0.85 下不影响判定，但阈值调到 0.95 以上时，
  相同的响应会被判为不相似，真实的越权发现会被降级为「权限校验有效」。
  现按四种情形分别计分：两侧都有且相同 0.1，两侧都没有 0.1（缺失不构成
  「不同」的证据），只有一侧有 0.05，两侧都有但不同 0。

### 新增

- `ResponseComparatorBoundaryTest`，13 条边界用例：空正文、null 正文、
  正文短于 shingle 长度、2MB 正文（含耗时断言）、二进制与控制字符、
  带 charset 的 Content-Type、头大小写差异、空正文下 302 与 200 的区分、
  同一状态码类的部分给分、阈值比较包含等号、三态输入完全相同须判为通配响应。

## [0.1.0] - 2026-09-18

### 新增

**越权（IDOR）检测**

基于三态对比的检测模型：

```
① 基准请求（受害者身份，id=X）       → R0
② 换第二身份重放（攻击者，id=X）     → R1
③ 对照请求（攻击者，id=不存在的值）  → R2

R1 ≈ R0 且 R2 ≉ R0  →  疑似越权
R1 ≈ R0 且 R2 ≈ R0  →  通配响应，判为误报丢弃
R1 ≉ R0             →  权限校验有效
```

第 ③ 步是本插件与 Autorize、AuthMatrix 等交互式工具的区别所在：
它排除了「对任意标识符都返回固定内容」的接口，这类假阳性是同类工具误报的
主要来源。

**参数识别**（`core/ParamHeuristics`）

- 以参数名与值的形态两个维度判断标识符参数
- 噪声排除表覆盖分页、排序、时间戳、版本号与鉴权 token
- 每项判定附带理由，使用者可以看到某个参数为何被判定为标识符

**响应相似度**（`core/ResponseComparator`）

- 先做标准化，去除 CSRF token、会话 ID、时间戳、traceId 与长十六进制串
- 计算 5-gram Jaccard 相似度，与状态码（权重 0.3）、Content-Type（0.1）加权
- 状态码权重较高，是因为 302 与 200 即使正文都为空，语义也完全不同：
  前者通常意味着请求被跳转到登录页，说明权限校验在起作用

**配置面板**（`ui/ConfigPanel`）

- Swing 面板，显示当前状态，含是否会发送请求的提示

**安全设计**

- 默认不发送任何请求。装上后仅做被动观察，必须配置第二身份并显式启用后
  才开始检测
- 仅对 GET、HEAD、OPTIONS 生效，避免修改业务数据
- 限速 100ms，单 host 候选上限 50
- 凭据脱敏，日志与 Issue 详情中只显示 `JSESSI****cdef` 形式

**构建与工具**

- Java 21 + Burp Montoya API 2026.7，无第三方运行时依赖
- Maven 构建；全部 Montoya API 签名均先经 `javap` 确认后实现
- 81 个单元测试（JUnit 5，参数化展开后计数）。`core/` 包不依赖 Burp 运行时，
  可脱离 Burp 单独运行
- GitHub Actions CI 执行编译、测试，并校验 Montoya API 未被打进 jar

### 修复

- `Set.of()` 不允许重复元素。`ID_KEYWORDS` 中 `"uid"` 写入了两次，导致类静态
  初始化抛出 `ExceptionInInitializerError`，整个类不可用，32 个测试报
  `NoClassDefFoundError`。重复仅在运行时检测，编译器无法发现。
- `URI.getRawPath()` 对无路径的 URL 返回空串而非 null。仅判 null 会得到空路径，
  而 `withPath("")` 会构造出非法请求。同一错误在 `pathAndQueryOf` 与
  `ParsedRequest.parse` 中各有一处。

[Unreleased]: https://github.com/hediwen831-star/burp-idor-detector/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hediwen831-star/burp-idor-detector/releases/tag/v0.1.0
