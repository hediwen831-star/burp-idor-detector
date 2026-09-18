package com.hediwen.burp.idor.core;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * ID 类参数的启发式识别。
 *
 * <p>越权检测的第一步是「找到值得换身份重放的那个参数」。
 * 这一步的准确率直接决定后面会不会满屏误报 ——
 * 如果把 {@code page=1}、{@code timestamp=1699999999} 这类参数也当成 ID 去重放，
 * 结果就是给用户刷出一堆无意义的「疑似越权」。</p>
 *
 * <h2>为什么用启发式而不是配置清单</h2>
 *
 * 参数命名没有标准。同一个业务字段在不同项目里可能叫
 * {@code id} / {@code uid} / {@code userId} / {@code user_id} / {@code memberId} /
 * {@code account} / {@code no} / {@code code}……
 * 让用户逐个填清单不现实，而漏填就意味着漏检。
 *
 * <p>所以这里用「命名模式 + 值形态」双重判断，
 * 并且**把判定理由一起返回** —— 用户在结果里能看到「为什么我认为这是个 ID 参数」，
 * 而不是只看到一个结论。这一点和 ASP 项目里的 PoC 引擎是同一个思路：
 * 结论必须可追溯。</p>
 *
 * <h2>判定维度</h2>
 *
 * <ol>
 *   <li><b>参数名</b>：命中 ID 命名模式（{@code id} / {@code uid} / {@code *_id} 等）</li>
 *   <li><b>参数值</b>：形态像标识符（纯数字 / UUID / 短 token），而不是日期、布尔、枚举</li>
 *   <li><b>排除项</b>：分页、排序、时间戳、版本号等高频噪声参数</li>
 * </ol>
 *
 * <p>三个维度都满足才判定为候选。宁可少报也不要多报 ——
 * 这与 ASP 里「宁可多留不可漏掉」的取舍相反，因为两者的代价不同：
 * 资产漏报会漏掉真实攻击面，而越权重放会产生**主动请求**，
 * 误报意味着对目标发起无意义的额外流量。</p>
 */
public final class ParamHeuristics {

    /**
     * 明确的 ID 命名关键词（全部小写比较）。
     *
     * <p>⚠️ 注意 {@code Set.of()} 的语义：**它不允许重复元素，重复会在类初始化时抛
     * {@code IllegalArgumentException}**。而这个异常发生在静态初始化块里，
     * 表现为 {@code ExceptionInInitializerError} —— 整个类直接不可用。</p>
     *
     * <p>这个坑是真踩过的：最初 "uid" 写了两次，编译完全正常（重复检查是运行时的），
     * 一跑测试就整个类挂掉。32 个测试全报 {@code NoClassDefFound}。</p>
     *
     * <p>教训：{@code Set.of()} 的重复检查其实是好事（能抓出笔误），
     * 但前提是**有测试覆盖** —— 否则这个错误会一直潜伏到用户加载插件时才暴露。</p>
     */
    private static final Set<String> ID_KEYWORDS = Set.of(
            "id", "uid", "gid", "pid", "sid", "rid", "tid",
            "userid", "user_id", "user",
            "memberid", "member_id", "account",
            "accountid", "account_id", "customer", "customerid",
            "orderid", "order_id", "productid", "product_id",
            "itemid", "item_id", "docid", "doc_id", "fileid", "file_id",
            "recordid", "record_id", "objectid", "object_id",
            "tenantid", "tenant_id", "orgid", "org_id", "groupid", "group_id",
            "roleid", "role_id", "deptid", "dept_id", "projectid", "project_id"
    );

    /** 命名后缀模式：以 _id / Id 结尾，或 xx_no / xx_code 这类业务编号。 */
    private static final List<Pattern> ID_NAME_PATTERNS = List.of(
            Pattern.compile("(?i).*[_-]?id$"),          // user_id / userId / uid
            Pattern.compile("(?i)^(no|code|sn|number)$"), // 业务编号
            Pattern.compile("(?i).*[_-]?(no|code|sn)$")   // order_no / orderCode
    );

    /**
     * 明确排除的参数名 —— 这些是高频噪声。
     *
     * <p>它们看起来「像标识符」（常常也是数字），但换身份重放没有任何意义：
     * 分页参数跟身份无关，时间戳每次都不一样，版本号更不是资源标识。</p>
     */
    private static final Set<String> EXCLUDED_NAMES = Set.of(
            "page", "pagesize", "page_size", "pageindex", "page_index",
            "limit", "offset", "size", "count", "total", "start", "end",
            "sort", "order", "orderby", "order_by", "sortby", "sort_by",
            "direction", "asc", "desc", "index", "rows",
            "timestamp", "ts", "time", "date", "datetime", "starttime", "endtime",
            "version", "ver", "revision", "build", "cache", "rand", "random",
            "nonce", "_", "callback", "jsonp", "format", "lang", "locale",
            "token", "csrf", "csrftoken", "csrf_token", "sign", "signature"
    );

    /** UUID 形态。 */
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    );

    /** 纯数字形态（含负数，业务 ID 有时会出现负数）。 */
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^-?\\d{1,19}$");

    /** 短的不含空白的 token，例如 MongoDB ObjectId、短哈希。 */
    private static final Pattern SHORT_TOKEN_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{6,40}$");

    /** 值可能的形态，用于在报告里描述。 */
    public enum ValueShape {
        /** 纯数字，最常见的主键形式 */
        NUMERIC("数字"),
        /** UUID，分布式系统常见 */
        UUID("UUID"),
        /** 其他短标识符 */
        TOKEN("短标识符"),
        /** 不像标识符 */
        UNKNOWN("未知");

        private final String label;

        ValueShape(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /**
     * 一个被判定为「值得重放」的候选参数。
     *
     * @param name   参数名
     * @param value  观测到的参数值
     * @param shape  值形态
     * @param reason 判定理由（会展示给用户）
     */
    public record Candidate(String name, String value, ValueShape shape, String reason) {

        /** 供报告使用的简短描述。 */
        public String describe() {
            return name + "=" + value + "（" + shape.label() + "，" + reason + "）";
        }
    }

    private ParamHeuristics() {
        // 工具类，不允许实例化
    }

    /**
     * 判断一个参数是否值得作为越权检测的候选。
     *
     * @param name  参数名
     * @param value 参数值
     * @return 命中时返回候选（含判定理由），否则返回空
     */
    public static Optional<Candidate> classify(String name, String value) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }

        String normalized = name.trim().toLowerCase(Locale.ROOT);
        if (EXCLUDED_NAMES.contains(normalized)) {
            return Optional.empty();
        }

        boolean nameLooksLikeId = ID_KEYWORDS.contains(normalized) || matchesAnyPattern(normalized);
        if (!nameLooksLikeId) {
            return Optional.empty();
        }

        ValueShape shape = classifyValue(value);
        if (shape == ValueShape.UNKNOWN) {
            // 名字像 ID 但值不像 —— 可能是个枚举或空值，重放没有意义
            return Optional.empty();
        }

        String reason = buildReason(normalized, shape);
        return Optional.of(new Candidate(name, value, shape, reason));
    }

    /**
     * 判断参数值的形态。
     *
     * <p>注意：空值直接返回 {@code UNKNOWN}。空参数换身份重放往往触发的是
     * 「参数缺失」的另一条代码路径，结果不可比。</p>
     */
    public static ValueShape classifyValue(String value) {
        if (value == null || value.isBlank()) {
            return ValueShape.UNKNOWN;
        }
        String trimmed = value.trim();

        if (NUMERIC_PATTERN.matcher(trimmed).matches()) {
            return ValueShape.NUMERIC;
        }
        if (UUID_PATTERN.matcher(trimmed).matches()) {
            return ValueShape.UUID;
        }
        if (SHORT_TOKEN_PATTERN.matcher(trimmed).matches()) {
            // 纯字母且很短的，多半是枚举值（如 status=active），不是标识符
            if (trimmed.length() <= 5 && trimmed.chars().allMatch(Character::isLetter)) {
                return ValueShape.UNKNOWN;
            }
            return ValueShape.TOKEN;
        }
        return ValueShape.UNKNOWN;
    }

    private static boolean matchesAnyPattern(String normalized) {
        return ID_NAME_PATTERNS.stream().anyMatch(p -> p.matcher(normalized).matches());
    }

    private static String buildReason(String normalized, ValueShape shape) {
        String base;
        if (ID_KEYWORDS.contains(normalized)) {
            base = "参数名在 ID 关键词表内";
        } else {
            base = "参数名匹配 ID 命名模式（以 id / no / code 结尾）";
        }
        return base + "，值形态为" + shape.label();
    }
}
