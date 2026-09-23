package com.hediwen.burp.idor.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.hediwen.burp.idor.config.CredentialProfile;
import com.hediwen.burp.idor.config.DetectorConfig;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 越权（IDOR）被动检测。
 *
 * <h2>检测流程</h2>
 *
 * <pre>
 *   Burp 流量 ──▶ 提取候选参数 ──▶ 检查前置条件 ──▶ 换身份重放 ──▶ 对照请求 ──▶ 判定
 *                     │                                │              │
 *                     │                                │              └─ 排除通配响应
 *                     │                                └─ 用第二身份替换请求头
 *                     └─ 参数名 + 值形态双重判断
 * </pre>
 *
 * <h2>为什么挂在 PassiveScanCheck 上</h2>
 *
 * 我们不需要 Burp 帮我们「构造 payload」（那是主动扫描做的事），
 * 我们要的是**观察用户已经产生的真实流量**，挑出其中的 ID 参数，
 * 然后自己发起一次受控的重放。
 *
 * <p>挂在被动扫描上有两个好处：</p>
 * <ol>
 *   <li>拿到的是用户真实业务场景的请求 —— 带完整上下文、真实参数组合，
 *       比主动爬虫生成的请求质量高得多</li>
 *   <li>不干扰 Burp 自己的主动扫描（两者独立运行）</li>
 * </ol>
 *
 * <h2>前置条件（任一不满足就直接返回空结果）</h2>
 *
 * <ol>
 *   <li>用户已配置第二身份</li>
 *   <li>用户已显式启用主动重放</li>
 *   <li>请求方法在安全方法白名单内</li>
 *   <li>目标 host 在检测范围内</li>
 *   <li>该 host 未超出候选配额</li>
 *   <li>该请求未被检测过（去重）</li>
 * </ol>
 *
 * <p>前两条是安全设计（见 {@link DetectorConfig} 的类注释），
 * 后四条是流量控制 —— <b>一个安全插件把目标扫挂了，比漏检更难交代。</b></p>
 */
public class IdorScanCheck implements PassiveScanCheck {

    private final MontoyaApi api;
    private final DetectorConfig config;

    /** 每个 host 上次发请求的时间戳，用于限速。 */
    private final Map<String, Long> lastRequestAt = new ConcurrentHashMap<>();

    /** 「检测未启用」只提示一次，避免未开启时把日志刷满。 */
    private final AtomicBoolean loggedNotReady = new AtomicBoolean(false);

    public IdorScanCheck(MontoyaApi api, DetectorConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override
    public String checkName() {
        return "IDOR Detector";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        try {
            return check(baseRequestResponse);
        } catch (Exception e) {
            // 被动扫描里抛异常会污染 Burp 的错误日志，
            // 但更糟的是让一次未捕获的异常中断整条扫描。
            // 所以这里兜底捕获，只记录，不影响其他检查。
            api.logging().logToError("[IDOR Detector] 检测过程异常: " + e.getMessage());
            return AuditResult.auditResult();
        }
    }

    private AuditResult check(HttpRequestResponse base) {
        // ── 前置条件 1、2：配置是否就绪 ─────────────────────────────
        if (!config.canDetect()) {
            // 只在第一次提示，避免未启用时刷屏
            if (loggedNotReady.compareAndSet(false, true)) {
                api.logging().logToOutput(
                        "[IDOR Detector] 检测未启用 —— 需要同时满足「已启用主动重放」与"
                                + "「第二身份已配置」。当前所有请求只做观察，不会重放。");
            }
            return AuditResult.auditResult();
        }
        if (base == null || !base.hasResponse()) {
            return AuditResult.auditResult();
        }

        HttpRequest request = base.request();
        HttpResponse response = base.response();

        // ── 前置条件 3：只处理安全方法 ──────────────────────────────
        String method = request.method() == null ? "" : request.method().toUpperCase();
        if (!DetectorConfig.SAFE_METHODS.contains(method)) {
            return AuditResult.auditResult();
        }

        // ── 前置条件 4：host 范围 ──────────────────────────────────
        String host = request.httpService() == null ? "" : request.httpService().host();
        if (!config.isHostInScope(host)) {
            api.logging().logToOutput(String.format(
                    "[IDOR Detector] 跳过 %s —— host %s 不在检测范围内（检查「范围控制」配置）。",
                    request.url(), host));
            return AuditResult.auditResult();
        }

        // ── 提取候选参数 ───────────────────────────────────────────
        ParsedRequest parsed = ParsedRequest.parse(request.url(), request.bodyToString());
        if (parsed.candidates().isEmpty()) {
            api.logging().logToOutput(String.format(
                    "[IDOR Detector] 跳过 %s %s —— 未识别出「像资源标识」的参数"
                            + "（本次解析到的参数: %s）。只有名字像 ID（id/uid/order_id…）"
                            + "且值形态为数字/UUID/短标识符的参数才会被重放。",
                    method, parsed.path(),
                    parsed.parameters().isEmpty() ? "无" : String.join(", ", parsed.parameters().keySet())));
            return AuditResult.auditResult();
        }

        // 一个请求里可能有多个候选，先取可信度最高的一个（值形态明确的优先）
        ParamHeuristics.Candidate candidate = parsed.candidates().get(0);

        // ── 前置条件 6：去重 ───────────────────────────────────────
        String dedupeKey = method + " " + host + parsed.path() + ":" + candidate.name() + "=" + candidate.value();
        if (!config.markSeen(dedupeKey)) {
            return AuditResult.auditResult();
        }

        // ── 前置条件 5：配额 ───────────────────────────────────────
        if (!config.registerCandidate(host)) {
            api.logging().logToOutput(String.format(
                    "[IDOR Detector] %s 已达单 host 候选上限（%d），跳过后续检测。"
                            + "如需继续请调整配置或缩小范围。",
                    host, config.getMaxCandidatesPerHost()));
            return AuditResult.auditResult();
        }

        // ── 开始实际检测 ───────────────────────────────────────────
        return performReplay(base, request, response, parsed, candidate, host);
    }

    private AuditResult performReplay(
            HttpRequestResponse base,
            HttpRequest request,
            HttpResponse response,
            ParsedRequest parsed,
            ParamHeuristics.Candidate candidate,
            String host) {

        CredentialProfile second = config.getSecondIdentity();

        int maxBytes = config.getMaxResponseBytes();
        var baseFp = ResponseComparator.fingerprint(
                response.statusCode(), response.headerValue("Content-Type"), truncate(response.bodyToString(), maxBytes));

        // ── 换身份重放 ─────────────────────────────────────────────
        throttle(host);
        HttpRequest replayRequest = second.applyTo(request);
        HttpRequestResponse replayResponse = api.http().sendRequest(replayRequest);

        if (replayResponse == null || !replayResponse.hasResponse()) {
            api.logging().logToOutput(
                    "[IDOR Detector] 换身份请求未拿到响应，跳过：" + request.url());
            return AuditResult.auditResult();
        }

        HttpResponse replayHttpResponse = replayResponse.response();
        var replayFp = ResponseComparator.fingerprint(
                replayHttpResponse.statusCode(),
                replayHttpResponse.headerValue("Content-Type"),
                truncate(replayHttpResponse.bodyToString(), maxBytes));

        // ── 对照请求：把 ID 换成一个几乎不可能存在的值 ──────────────
        ResponseComparator.Fingerprint controlFp;
        if (config.isSendControlRequest()) {
            String controlValue = nonExistentValueLike(candidate.value());
            String controlUrl = parsed.withReplace(candidate.name(), controlValue);

            throttle(host);
            HttpRequest controlRequest = second.applyTo(request.withPath(pathAndQueryOf(controlUrl)));
            HttpRequestResponse controlResponse = api.http().sendRequest(controlRequest);

            if (controlResponse != null && controlResponse.hasResponse()) {
                HttpResponse cr = controlResponse.response();
                controlFp = ResponseComparator.fingerprint(
                        cr.statusCode(), cr.headerValue("Content-Type"),
                        truncate(cr.bodyToString(), maxBytes));
            } else {
                // 对照请求失败：无法排除通配响应，保守起见不放行判定
                api.logging().logToOutput(
                        "[IDOR Detector] 对照请求失败，无法排除通配响应，本次不判定：" + controlUrl);
                return AuditResult.auditResult();
            }
        } else {
            // 用户关掉了对照请求：只能退化成「换身份后相似 = 可疑」，
            // 误报率会显著上升，所以降低置信度并在描述里说明。
            controlFp = ResponseComparator.fingerprint(0, "", "");
            if (ResponseComparator.similarity(baseFp, replayFp) >= config.getSimilarityThreshold()) {
                return AuditResult.auditResult(
                        buildIssue(base, replayResponse, candidate, new ResponseComparator.Comparison(
                                ResponseComparator.Verdict.SUSPECTED_IDOR,
                                ResponseComparator.similarity(baseFp, replayFp),
                                -1,
                                "未启用对照请求，无法排除通配响应，置信度较低"), true));
            }
            return AuditResult.auditResult();
        }

        var comparison = ResponseComparator.compare(
                baseFp, replayFp, controlFp, config.getSimilarityThreshold());

        api.logging().logToOutput(String.format(
                "[IDOR Detector] %s %s → %s（相似度 换身份=%.2f 对照=%.2f）",
                candidate.name(), candidate.value(), comparison.verdict().label(),
                comparison.baseVsReplay(), comparison.baseVsControl()));

        if (!comparison.isSuspected()) {
            return AuditResult.auditResult();
        }

        return AuditResult.auditResult(buildIssue(base, replayResponse, candidate, comparison, false));
    }

    /**
     * 构造 Burp 的审计问题。
     *
     * <p>描述里必须写清楚三件事，否则用户无法复核：</p>
     * <ol>
     *   <li>检测了哪个参数的哪个值</li>
     *   <li>两次响应的相似度是多少（数字化，而不是「很相似」）</li>
     *   <li>对照请求的结果是什么（证明为什么排除了误报）</li>
     * </ol>
     */
    private AuditIssue buildIssue(
            HttpRequestResponse base,
            HttpRequestResponse replayResponses,
            ParamHeuristics.Candidate candidate,
            ResponseComparator.Comparison comparison,
            boolean lowConfidence) {

        String name = String.format("疑似越权访问（IDOR）：参数 %s", candidate.name());

        String detail = """
                在参数 %s 上检测到疑似越权访问。

                检测方式：
                  ① 以当前会话（受害者身份）请求一次，作为基准响应
                  ② 替换为第二身份后重放同一请求
                  ③ 把参数值换成一个几乎不可能存在的值，再请求一次作为对照

                判定依据：%s

                参数值：%s
                参数名判定理由：%s

                参数值本身没有出现在 URL 的其他位置 —— 这是一个「猜测型」越权：
                攻击者不需要知道目标的真实 ID，只需要遍历 ID 空间就能批量读取数据。

                注意：本结论由自动化检测得出，请人工确认后再上报。
                自动化无法判断「该资源是否本就对第二身份开放」这类业务语义。
                """.formatted(
                candidate.name(),
                comparison.note(),
                candidate.value(),
                candidate.reason());

        String remediation = """
                1. 在服务端对每一次资源访问做归属校验 —— 不能只依赖「前端不显示」或
                   「ID 猜不到」。ID 不可预测性（如 UUID）只能降低被遍历的概率，
                   不构成访问控制。

                2. 校验逻辑应该是「当前登录用户是否拥有该资源的访问权」，
                   而不是「该资源是否存在」。两者混用是越权最常见的原因。

                3. 建议抽象出统一的鉴权层（如基于资源归属的授权中间件），
                   避免每个接口各写一遍导致漏掉某个。越权漏洞往往是
                   「绝大多数接口都做了，就漏了一个」。

                4. 对批量接口（列表、导出、搜索）也要做归属过滤，
                   这类接口因为「返回值本来就是一组数据」更容易被忽视。
                """;

        return AuditIssue.auditIssue(
                name,
                detail,
                remediation,
                lowConfidence ? "Medium" : "High",
                lowConfidence ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.HIGH,
                lowConfidence ? AuditIssueConfidence.TENTATIVE : AuditIssueConfidence.FIRM,
                "应用未对资源归属做校验，导致可以用低权限身份读取他人的资源。",
                "越权（IDOR / Broken Object Level Authorization）长期位居 OWASP API 安全风险榜首，"
                        + "在真实数据泄露事件中是最高频的成因之一。",
                AuditIssueSeverity.HIGH,
                base,
                replayResponses
        );
    }

    /**
     * 限速：保证两次请求之间有最小间隔。
     *
     * <p>不限速的自动重放等同于对目标发起压力测试 ——
     * 这是插件类工具最容易造成的事故。</p>
     */
    private void throttle(String host) {
        int interval = config.getMinRequestIntervalMs();
        if (interval <= 0) {
            return;
        }
        long now = System.currentTimeMillis();
        Long last = lastRequestAt.put(host, now);
        if (last != null) {
            long wait = interval - (now - last);
            if (wait > 0) {
                try {
                    Thread.sleep(wait);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private static String truncate(String text, int maxBytes) {
        if (text == null) {
            return "";
        }
        return text.length() <= maxBytes ? text : text.substring(0, maxBytes);
    }

    /**
     * 为一个 ID 生成「几乎不可能存在」的对照值。
     *
     * <p>策略按值形态区分：</p>
     * <ul>
     *   <li>数字：取一个远超正常范围的数（如 999999999）。不用「原值 +1」——
     *       相邻 ID 很可能真实存在，那就不是有效对照了</li>
     *   <li>UUID：生成一个随机 UUID（碰撞概率可忽略）</li>
     *   <li>其他：拼一个明显异常的字符串</li>
     * </ul>
     */
    static String nonExistentValueLike(String original) {
        ParamHeuristics.ValueShape shape = ParamHeuristics.classifyValue(original);
        return switch (shape) {
            case NUMERIC -> {
                // 保留符号，避免因为「负数/正数」改变服务端分支
                boolean negative = original.trim().startsWith("-");
                yield negative ? "-999999999999" : "999999999999";
            }
            case UUID -> UUID.randomUUID().toString();
            case TOKEN -> "zzz_not_exists_" + System.nanoTime() % 100000;
            case UNKNOWN -> original + "_nonexistent";
        };
    }

    /**
     * 从完整 URL 里取出 path + query（Montoya 的 withPath 需要这个形式）。
     *
     * <p>⚠️ 踩过的坑：不能只判断 {@code getRawPath() == null}。
     * 对 {@code https://example.com}（无路径部分）这种 URL，
     * Java 的 URI 返回的是**空字符串而不是 null** —— 只判 null 会得到空路径，
     * 而 {@code withPath("")} 会构造出一个非法请求。</p>
     *
     * <p>这类「空串 vs null」的区别在 Java 里到处都是，
     * 单测里专门留了一条针对它的断言。</p>
     */
    static String pathAndQueryOf(String url) {
        try {
            URI uri = new URI(url);

            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }

            String query = uri.getRawQuery();
            return query == null || query.isEmpty() ? path : path + "?" + query;
        } catch (URISyntaxException e) {
            return "/";
        }
    }

    /**
     * 解析后的请求信息：路径 + 候选参数 + 改写能力。
     *
     * @param path       不带 query 的路径
     * @param parameters 参数顺序表（保留原始顺序，便于还原 URL）
     * @param candidates 判定为候选的参数
     */
    record ParsedRequest(
            String path,
            LinkedHashMap<String, String> parameters,
            List<ParamHeuristics.Candidate> candidates) {

        static ParsedRequest parse(String url, String body) {
            LinkedHashMap<String, String> params = new LinkedHashMap<>();
            String path = "/";

            try {
                URI uri = new URI(url);
                String rawPath = uri.getRawPath();
                // 同样注意空串与 null 的区别（见 pathAndQueryOf 的注释）
                path = (rawPath == null || rawPath.isEmpty()) ? "/" : rawPath;

                String query = uri.getRawQuery();
                if (query != null && !query.isEmpty()) {
                    parsePairs(query, params);
                }
            } catch (URISyntaxException ignored) {
                // URL 解析失败就用默认路径，后续会因为拿不到参数而跳过
            }

            // 表单类型 body 也解析一遍（application/x-www-form-urlencoded）
            if (body != null && !body.isBlank() && body.contains("=") && !body.trim().startsWith("{")) {
                parsePairs(body, params);
            }

            List<ParamHeuristics.Candidate> candidates = new ArrayList<>();
            for (Map.Entry<String, String> entry : params.entrySet()) {
                Optional<ParamHeuristics.Candidate> candidate =
                        ParamHeuristics.classify(entry.getKey(), entry.getValue());
                candidate.ifPresent(candidates::add);
            }

            return new ParsedRequest(path, params, candidates);
        }

        private static void parsePairs(String raw, Map<String, String> target) {
            for (String pair : raw.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String key = eq < 0 ? pair : pair.substring(0, eq);
                String value = eq < 0 ? "" : pair.substring(eq + 1);
                if (!key.isEmpty()) {
                    target.putIfAbsent(decode(key), decode(value));
                }
            }
        }

        /** 极简的百分号解码 —— 只处理插件需要的场景，不追求完备。 */
        private static String decode(String value) {
            try {
                return java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                return value;
            }
        }

        /** 把某个参数替换成新值，返回完整 URL（path + query）。 */
        String withReplace(String name, String newValue) {
            StringBuilder sb = new StringBuilder(path).append('?');
            boolean first = true;
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (!first) {
                    sb.append('&');
                }
                first = false;
                sb.append(encode(entry.getKey())).append('=');
                sb.append(encode(entry.getKey().equals(name) ? newValue : entry.getValue()));
            }
            return sb.toString();
        }

        private static String encode(String value) {
            return java.net.URLEncoder.encode(value == null ? "" : value,
                    java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}
