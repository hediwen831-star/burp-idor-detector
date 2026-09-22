# 贡献指南

## 开发环境

```bash
git clone https://github.com/hediwen831-star/burp-idor-detector.git
cd burp-idor-detector
mvn -s maven-settings.xml clean package
# 产物：target/idor-detector-0.1.0.jar
```

需要 **JDK 21+**。

`maven-settings.xml` 配了阿里云镜像，因为国内直连 Maven Central 很慢。
如果网络环境直连够快，用默认设置即可：`mvn clean package`。

该文件不能用于 CI，它写死了本机的 `localRepository` 路径。

## 提交前必须跑

```bash
mvn -s maven-settings.xml clean verify     # 编译 + 测试
```

---

## 硬性约定

### 1. 动手写代码前，先用 javap 确认接口签名

**这是最重要的一条。**

Montoya API 的接口签名**不能凭记忆写** —— 参数个数、顺序、类型经常和直觉不符：

```java
// AuditIssue.auditIssue() 有【10 个】参数，不是 5 个
AuditIssue.auditIssue(name, detail, remediation, severity, severityEnum,
                      confidence, background, remediationBackground,
                      typicalSeverity, requestResponses...)

// registerPassiveScanCheck 需要【2 个】参数，第二个是 ScanCheckType
api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST);
```

正确做法是先拿到 API jar，用 `javap` 逐个确认：

```bash
curl -o montoya-api.jar \
  "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar"

javap -cp montoya-api.jar burp.api.montoya.scanner.audit.issues.AuditIssue
javap -cp montoya-api.jar burp.api.montoya.scanner.Scanner
javap -cp montoya-api.jar burp.api.montoya.scanner.scancheck.PassiveScanCheck
```

**凭记忆写 Java 接口必然编译失败。** 先花十分钟确认签名，
比反复试错编译快得多 —— 这个插件的核心代码就是这样做到一次编译通过的。

### 2. Montoya API 必须是 provided scope

```xml
<dependency>
  <groupId>net.portswigger.burp.extensions</groupId>
  <artifactId>montoya-api</artifactId>
  <scope>provided</scope>       <!-- 不能省 -->
</dependency>
```

打进 jar 会与 Burp 自带的 API 冲突。**CI 里有专门一条检查守这个。**

### 3. 不要引入新的运行时依赖

Burp 扩展跑在使用者的 Burp 进程里 —— 多一个依赖就多一份版本冲突和体积负担。
JSON 解析、HTTP 客户端这些 Burp 都提供了，其余用 JDK 标准库足够。

目前是零第三方运行时依赖，请保持。

### 4. core/ 层必须能脱离 Burp 单测

`core/ParamHeuristics` 和 `core/ResponseComparator` 是**纯逻辑**，
不依赖任何 Burp 类型 —— 所以能单独跑 JUnit。

**这条是有意设计的**：插件的行为如果只能在 Burp 里手工验证，
就等于没有回归保护。加新逻辑时优先放进 `core/` 并配单测。

### 5. 安全默认值不能改

| 默认值 | 不要改成 |
|---|---|
| 主动重放**关闭** | ❌ 默认开启 |
| 方法白名单 GET / HEAD / OPTIONS | ❌ 加上 POST |
| 限速 100ms | ❌ 去掉限速 |
| 单 host 上限 50 | ❌ 去掉配额 |
| 凭据脱敏 | ❌ 打印完整值 |

**理由**：一个在后台自动发请求的安全插件，最大的风险是
「使用者以为它没在工作，实际它在发请求」。

这些默认值是对那个风险的回应。**改动前请先开 issue 讨论。**

### 6. 新逻辑要配单测

```bash
mvn test
```

测试放在 `src/test/java/` 对应的包下。

参考 `ResponseComparatorTest` —— 其中「通配响应被识别为误报」那条
守的是整个插件最核心的误报控制逻辑，是这类逻辑该有的测试强度。

---

## 提交规范

用 [Conventional Commits](https://www.conventionalcommits.org/)：

| 前缀 | 用途 |
|---|---|
| `feat:` | 新功能 |
| `fix:` | 修复 |
| `docs:` | 文档 |
| `test:` | 测试 |
| `refactor:` | 重构 |
| `chore:` | 构建 / 工具 |

---

## 在 Burp 里测试插件

```bash
mvn -s maven-settings.xml clean package
```

然后 Burp → **Extensions** → **Add** → 选 `target/idor-detector-0.1.0.jar`
（Extension type 选 **Java**）。

加载后看 Burp 的 **Output** 面板 —— 插件会打印一段状态说明，确认：

- 当前是否处于「仅被动观察」状态
- 配置面板在哪个标签页

---

## Pull Request

- 一个 PR 只做一件事
- 描述里写清楚：做了什么、为什么、怎么验证的
- `mvn verify` 必须通过
- 涉及行为变更的要同步更新 README / `docs/DESIGN.md`

---

## 报告问题

- **Bug / 功能建议** → [开 issue](.github/ISSUE_TEMPLATE/)
- **安全漏洞**（凭据泄漏、未授权请求等）→ 见 [SECURITY.md](SECURITY.md)，**不要开公开 issue**
