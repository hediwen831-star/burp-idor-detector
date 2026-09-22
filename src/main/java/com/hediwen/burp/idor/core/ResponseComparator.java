package com.hediwen.burp.idor.core;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 响应指纹与相似度对比。
 *
 * <h2>为什么不能直接比字符串</h2>
 *
 * 同一个接口两次请求，即使返回的是「同一份数据」，正文也几乎不会完全一致：
 *
 * <ul>
 *   <li>CSRF token / 会话标识 —— 每次请求都变</li>
 *   <li>时间戳 / 耗时 —— 每次请求都变</li>
 *   <li>随机数 / 追踪 ID（traceId、requestId）—— 每次请求都变</li>
 *   <li>JSON 字段顺序 —— 某些框架不保证稳定</li>
 * </ul>
 *
 * 如果直接做字符串相等判断，结果是**全部判定为不相似**，
 * 于是所有越权都被漏掉。反过来，如果忽略长度和内容做宽松判断，
 * 又会把「两个不同的错误页」判成相似，产生大量误报。
 *
 * <p>所以流程是：**先标准化去掉动态内容，再做结构化比较**。</p>
 *
 * <h2>三态对比（误报控制的核心）</h2>
 *
 * 光有「换身份后响应相似」还不足以判定越权 —— 因为**公开资源**换谁访问都一样。
 * 比如商品详情页，用任何账号访问同一个商品 ID 都会返回相同内容，
 * 这不是漏洞。
 *
 * <p>所以引入第三个请求做对照：把 ID 换成一个**几乎不可能存在**的值。</p>
 *
 * <pre>
 *   ① 原始请求（身份 A，ID=1001）        → 基准响应 R0
 *   ② 换身份重放（身份 B，ID=1001）      → 响应 R1
 *   ③ 对照请求（身份 B，ID=不存在的值）  → 响应 R2
 *
 *   判定 R1 ≈ R0（身份 B 拿到了同样的数据）且 R2 ≉ R0（不存在的 ID 确实返回不同内容）
 *   → 说明 ID 是真实有效的，且服务端没校验归属 → 越权成立
 *
 *   若 R2 ≈ R0 → 说明这个接口对任何 ID 都返回同样的内容（通配响应），
 *   此时 R1 ≈ R0 毫无意义 → 判为误报，丢弃
 * </pre>
 *
 * <p>这个「负向对照」的思路与 ASP 项目里 PoC 引擎的做法完全一致：
 * <b>结论要能排除「检测特征被检测行为本身制造出来」的可能。</b></p>
 */
public final class ResponseComparator {

    /** 动态内容模式：匹配到就替换成占位符，避免影响相似度。 */
    private static final Pattern[] DYNAMIC_PATTERNS = {
            // HTML 表单里的隐藏字段：<input name="csrf_token" ... value="随机串">
            // 放在最前面，避免被后面的通用规则拆得只剩一半
            Pattern.compile("(?i)name=\"[^\"]*(?:csrf|token|nonce|authenticity)[^\"]*\"[^>]{0,80}?value=\"[^\"]*\""),
            // 各种 token / 密钥字段（JSON 形式）
            Pattern.compile("(?i)\"(csrf|csrftoken|csrf_token|token|nonce|_token|authenticity_token)\"\\s*:\\s*\"[^\"]*\""),
            // 各种 token（表单/查询串形式）
            Pattern.compile("(?i)(csrf|csrftoken|csrf_token|token|nonce|_token)=[^&\\s\"'>]+"),
            // 会话标识
            Pattern.compile("(?i)\"(sessionid|session_id|jsessionid|phpsessid)\"\\s*:\\s*\"[^\"]*\""),
            // 请求追踪 ID
            Pattern.compile("(?i)\"(traceid|trace_id|requestid|request_id|spanid|correlationid)\"\\s*:\\s*\"[^\"]*\""),
            // ISO 时间戳
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?"),
            // 10 位或 13 位 Unix 时间戳（单独出现的数字，避免误伤普通 ID）
            Pattern.compile("(?<![\\d.])\\d{10}(?:\\d{3})?(?![\\d.])"),
            // 长十六进制串（哈希、随机 ID）
            Pattern.compile("(?<![0-9a-fA-F])[0-9a-fA-F]{16,}(?![0-9a-fA-F])"),
    };

    /** 标准化时替换动态内容的占位符。 */
    private static final String PLACEHOLDER = "<DYNAMIC>";

    /** 判定结论。 */
    public enum Verdict {
        /** 疑似越权：换身份仍能看到同样内容，且对照请求证明 ID 是有效的 */
        SUSPECTED_IDOR,
        /** 通配响应：该接口对任何 ID 都返回相同内容，此前的相似性无意义 */
        WILDCARD_RESPONSE,
        /** 权限已正确校验：换身份后响应明显不同 */
        ACCESS_DENIED,
        /** 无法判定：缺少必要数据 */
        INCONCLUSIVE;

        public String label() {
            return switch (this) {
                case SUSPECTED_IDOR -> "疑似越权";
                case WILDCARD_RESPONSE -> "通配响应（疑似误报）";
                case ACCESS_DENIED -> "权限校验有效";
                case INCONCLUSIVE -> "无法判定";
            };
        }
    }

    /**
     * 一次对比的完整结论。
     *
     * @param verdict         判定
     * @param baseVsReplay    基准响应与换身份响应的相似度
     * @param baseVsControl   基准响应与对照响应的相似度
     * @param note            说明（会展示给用户）
     */
    public record Comparison(
            Verdict verdict,
            double baseVsReplay,
            double baseVsControl,
            String note
    ) {
        public boolean isSuspected() {
            return verdict == Verdict.SUSPECTED_IDOR;
        }
    }

    /**
     * 响应的结构化摘要。
     *
     * @param statusCode  状态码
     * @param contentType Content-Type（已截断到分号前）
     * @param bodyLength  正文长度
     * @param normalized  标准化后的正文
     * @param shingles    正文的 n-gram 集合（用于相似度计算）
     */
    public record Fingerprint(
            int statusCode,
            String contentType,
            int bodyLength,
            String normalized,
            Set<String> shingles
    ) {
        /** 正文长度分桶 —— 长度差异小于一档的视为同一量级。 */
        public int lengthBucket() {
            if (bodyLength == 0) {
                return 0;
            }
            // 按数量级分桶：0-99 / 100-999 / 1000-9999 ...
            return (int) Math.floor(Math.log10(bodyLength));
        }
    }

    /** n-gram 的窗口大小。5 是经验值：太短区分度不足，太长对局部改动过于敏感。 */
    private static final int SHINGLE_SIZE = 5;

    /** 相似度判定阈值（默认）。 */
    public static final double DEFAULT_SIMILARITY_THRESHOLD = 0.85;

    private ResponseComparator() {
        // 工具类
    }

    /**
     * 从原始响应构建指纹。
     *
     * @param statusCode  状态码
     * @param contentType Content-Type 头（可为 null）
     * @param body        响应正文（可为 null）
     */
    public static Fingerprint fingerprint(int statusCode, String contentType, String body) {
        String safeBody = body == null ? "" : body;
        String normalized = normalize(safeBody);
        String mime = contentType == null ? "" : contentType.split(";")[0].trim().toLowerCase(Locale.ROOT);
        return new Fingerprint(statusCode, mime, safeBody.length(), normalized, shingles(normalized));
    }

    /**
     * 标准化正文：把动态内容替换成占位符。
     *
     * <p>这是相似度计算能work的前提。不做这一步的话，
     * 任何带 CSRF token 的页面都会因为 token 不同而被判为不相似。</p>
     */
    public static String normalize(String body) {
        if (body == null || body.isEmpty()) {
            return "";
        }
        String result = body;
        for (Pattern pattern : DYNAMIC_PATTERNS) {
            result = pattern.matcher(result).replaceAll(PLACEHOLDER);
        }
        // 压缩空白：JSON 缩进、HTML 格式化的差异不该影响相似度
        result = result.replaceAll("\\s+", " ").trim();
        return result;
    }

    /**
     * 计算两个指纹的相似度（0~1）。
     *
     * <p>加权组合三个维度：</p>
     * <ul>
     *   <li><b>状态码</b>（权重 0.3）：状态码不同，结论就没有可比性</li>
     *   <li><b>内容类型</b>（权重 0.1）：JSON 和 HTML 是两种完全不同的响应</li>
     *   <li><b>正文 n-gram 相似度</b>（权重 0.6）：主要依据</li>
     * </ul>
     *
     * <p>为什么给状态码这么高的权重：302 跳转和 200 正常响应
     * 即使正文都为空，语义也完全不同 —— 前者通常意味着「被踢到登录页了」，
     * 那其实是权限校验在起作用。</p>
     */
    public static double similarity(Fingerprint a, Fingerprint b) {
        double score = 0.0;

        if (a.statusCode() == b.statusCode()) {
            score += 0.3;
        } else if (a.statusCode() / 100 == b.statusCode() / 100) {
            // 同属一个状态码类别（如都是 2xx），给一半分
            score += 0.15;
        }

        if (!a.contentType().isEmpty() && a.contentType().equals(b.contentType())) {
            // 两边都有且相同 —— 满分
            score += 0.1;
        } else if (a.contentType().isEmpty() && b.contentType().isEmpty()) {
            // 两边都没有 Content-Type：无法比较，但**这也不构成"不同"的证据**。
            //
            // 这里曾经给 0.05（一半分），与"不因此扣分"的注释自相矛盾。
            // 后果很实在：两个**完全相同**的响应（都是裸体 API）相似度上限
            // 只有 0.95，永远到不了 1.0。默认阈值 0.85 时看不出来，
            // 但阈值一旦调到 0.95 以上，就会出现「完全相同的响应被判为不相似」。
            //
            // 边界测试 test_nullBodyIsSafe 抓到了这个不一致。
            score += 0.1;
        } else if (a.contentType().isEmpty() || b.contentType().isEmpty()) {
            // 只有一方有 Content-Type —— 信息不足，给一半分。
            // 既不像"两边都有且相同"那样确定，也不像"两边不同"那样构成反证。
            score += 0.05;
        }

        score += 0.6 * jaccard(a.shingles(), b.shingles());

        return Math.min(1.0, score);
    }

    /**
     * 三态对比判定。
     *
     * @param base    原始请求（身份 A）的响应指纹
     * @param replay  换身份重放（身份 B）的响应指纹
     * @param control 对照请求（不存在的 ID）的响应指纹
     * @param threshold 相似度阈值
     * @return 判定结论
     */
    public static Comparison compare(
            Fingerprint base, Fingerprint replay, Fingerprint control, double threshold) {

        double baseVsReplay = similarity(base, replay);
        double baseVsControl = similarity(base, control);

        // ① 换身份后响应本来就不一样 → 权限校验有效
        if (baseVsReplay < threshold) {
            return new Comparison(
                    Verdict.ACCESS_DENIED, baseVsReplay, baseVsControl,
                    String.format("换身份后响应差异明显（相似度 %.2f < %.2f），权限校验有效",
                            baseVsReplay, threshold));
        }

        // ② 换身份后相似，但对照请求也相似 → 该接口对任何 ID 都返回同样内容
        if (baseVsControl >= threshold) {
            return new Comparison(
                    Verdict.WILDCARD_RESPONSE, baseVsReplay, baseVsControl,
                    String.format("对照请求（不存在的 ID）返回了同样内容（相似度 %.2f），"
                            + "说明该接口对任意 ID 都返回固定响应，此前的相似性无意义",
                            baseVsControl));
        }

        // ③ 换身份相似 + 对照不相似 → 越权
        return new Comparison(
                Verdict.SUSPECTED_IDOR, baseVsReplay, baseVsControl,
                String.format("换身份后仍返回相同内容（相似度 %.2f），"
                        + "且不存在的 ID 返回不同内容（相似度 %.2f）—— 说明资源真实存在且未校验归属",
                        baseVsReplay, baseVsControl));
    }

    /**
     * 计算两个字符串的 n-gram 集合。
     *
     * <p>用集合而不是原始串，是为了让相似度对「局部插入/删除」不敏感 ——
     * 这正是我们想要的：一次请求多返回一个字段，不该让相似度崩掉。</p>
     */
    static Set<String> shingles(String text) {
        Set<String> result = new LinkedHashSet<>();
        if (text == null || text.length() < SHINGLE_SIZE) {
            if (text != null && !text.isEmpty()) {
                result.add(text);
            }
            return result;
        }
        for (int i = 0; i + SHINGLE_SIZE <= text.length(); i++) {
            result.add(text.substring(i, i + SHINGLE_SIZE));
        }
        return result;
    }

    /**
     * Jaccard 相似度：交集大小 / 并集大小。
     *
     * <p>空集处理：两边都为空视为完全相似（两个空响应确实是"一样的"），
     * 一边为空一边不为空视为完全不相似。</p>
     */
    static double jaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() && b.isEmpty()) {
            return 1.0;
        }
        if (a.isEmpty() || b.isEmpty()) {
            return 0.0;
        }
        int intersection = 0;
        for (String item : a) {
            if (b.contains(item)) {
                intersection++;
            }
        }
        int union = a.size() + b.size() - intersection;
        return union == 0 ? 1.0 : (double) intersection / union;
    }
}
