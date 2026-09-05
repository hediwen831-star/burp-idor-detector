package com.hediwen.burp.idor.config;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 检测器配置。
 *
 * <h2>⚠️ 默认不主动重放（最重要的一个设计决定）</h2>
 *
 * 一个插件如果在后台**自动**对每个看起来像 ID 的参数发起额外请求，会带来三个问题：
 *
 * <ol>
 *   <li><b>把目标打挂</b>：一个列表页可能有几十个 ID 参数，乘以重放 + 对照请求，
 *       流量会被放大数倍。用户以为只是在正常浏览，实际在跑扫描。</li>
 *   <li><b>污染业务数据</b>：如果检测的是写接口（POST/PUT/DELETE），
 *       重放可能真的修改了数据 —— 这比漏检严重得多。</li>
 *   <li><b>打草惊蛇</b>：授权的渗透测试有明确的窗口期和流量约定，
 *       插件擅自发请求属于越界。</li>
 * </ol>
 *
 * <p>所以 {@link #activeReplayEnabled} 默认是 {@code false}：
 * <b>插件装上后只做被动观察（识别候选参数），不发任何请求。</b>
 * 用户必须主动配置第二身份并打开开关，才会开始真正的越权重放。</p>
 *
 * <p>这和 ASP 项目里「Web 接口默认只绑 127.0.0.1、绑公网必须配 token」
 * 是同一类取舍：<b>工具的能力边界就是它的风险边界，默认值必须选安全的那一侧。</b></p>
 *
 * <h2>只读方法白名单</h2>
 *
 * 即使打开了重放开关，也只对安全方法生效。
 * {@link #SAFE_METHODS} 里的方法必须被认定为「不会改变服务端状态」。
 */
public final class DetectorConfig {

    /**
     * 允许重放的 HTTP 方法。
     *
     * <p>只放了 GET / HEAD / OPTIONS。POST 虽然也可能只是查询（GraphQL、
     * 搜索接口都是 POST），但它同样可能是「提交订单」——
     * 在无法区分的情况下，**保守的做法是不碰**。</p>
     *
     * <p>如果确实需要检测 POST 接口，应该由用户在明确知道接口语义的前提下
     * 手动用 Repeater 验证，而不是让插件自动扫描。</p>
     */
    public static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    // ── 运行状态 ─────────────────────────────────────────────────────

    /** 是否允许主动重放。默认 false —— 见类注释。 */
    private volatile boolean activeReplayEnabled = false;

    /** 第二身份（攻击者视角）。 */
    private volatile CredentialProfile secondIdentity = CredentialProfile.empty();

    // ── 判定参数 ─────────────────────────────────────────────────────

    /** 相似度阈值：高于它认为「内容基本相同」。 */
    private volatile double similarityThreshold = 0.85;

    /** 是否发送对照请求（用不存在的 ID 排除通配响应）。强烈建议保持开启。 */
    private volatile boolean sendControlRequest = true;

    /** 单个响应最多读取多少字节用于比对。超过则截断 —— 防止大文件把内存吃满。 */
    private volatile int maxResponseBytes = 512 * 1024;

    /** 两个请求之间的最小间隔（毫秒）。限速是安全底线，不是可调优化项。 */
    private volatile int minRequestIntervalMs = 100;

    /** 每个 host 最多检测多少个候选（防止在中大型站点上刷出成千上万个重放请求）。 */
    private volatile int maxCandidatesPerHost = 50;

    // ── 范围控制 ─────────────────────────────────────────────────────

    /** 只检测这些 host（空集表示不限制）。 */
    private final Set<String> includeHosts = ConcurrentHashMap.newKeySet();

    /** 排除这些 host（优先级高于 includeHosts）。 */
    private final Set<String> excludeHosts = ConcurrentHashMap.newKeySet();

    /** 每个 host 已经检测过的候选数量。 */
    private final ConcurrentHashMap<String, Integer> candidateCounter = new ConcurrentHashMap<>();

    /** 已经检测过的请求指纹，避免同一请求被重复重放。 */
    private final Set<String> seenRequestKeys = ConcurrentHashMap.newKeySet();

    // ── 访问器 ───────────────────────────────────────────────────────

    public boolean isActiveReplayEnabled() {
        return activeReplayEnabled;
    }

    public void setActiveReplayEnabled(boolean enabled) {
        this.activeReplayEnabled = enabled;
    }

    public CredentialProfile getSecondIdentity() {
        return secondIdentity;
    }

    public void setSecondIdentity(CredentialProfile profile) {
        this.secondIdentity = profile == null ? CredentialProfile.empty() : profile;
    }

    public double getSimilarityThreshold() {
        return similarityThreshold;
    }

    public void setSimilarityThreshold(double threshold) {
        this.similarityThreshold = Math.max(0.5, Math.min(1.0, threshold));
    }

    public boolean isSendControlRequest() {
        return sendControlRequest;
    }

    public void setSendControlRequest(boolean send) {
        this.sendControlRequest = send;
    }

    public int getMaxResponseBytes() {
        return maxResponseBytes;
    }

    public void setMaxResponseBytes(int bytes) {
        this.maxResponseBytes = Math.max(4096, bytes);
    }

    public int getMinRequestIntervalMs() {
        return minRequestIntervalMs;
    }

    public void setMinRequestIntervalMs(int ms) {
        this.minRequestIntervalMs = Math.max(0, ms);
    }

    public int getMaxCandidatesPerHost() {
        return maxCandidatesPerHost;
    }

    public void setMaxCandidatesPerHost(int max) {
        this.maxCandidatesPerHost = Math.max(1, max);
    }

    public Set<String> getIncludeHosts() {
        return includeHosts;
    }

    public Set<String> getExcludeHosts() {
        return excludeHosts;
    }

    // ── 判定辅助 ─────────────────────────────────────────────────────

    /**
     * 当前配置是否足以执行检测。
     *
     * @return 可检测返回 true
     */
    public boolean canDetect() {
        return activeReplayEnabled && secondIdentity.isConfigured();
    }

    /**
     * 判断某个 host 是否在检测范围内。
     *
     * @param host 目标主机名（不含端口）
     */
    public boolean isHostInScope(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String normalized = host.toLowerCase();
        if (excludeHosts.contains(normalized)) {
            return false;
        }
        return includeHosts.isEmpty() || includeHosts.contains(normalized);
    }

    /**
     * 登记一次候选检测，判断是否超出该 host 的配额。
     *
     * @param host 目标主机名
     * @return 还有配额返回 true
     */
    public boolean registerCandidate(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        int current = candidateCounter.merge(host.toLowerCase(), 1, Integer::sum);
        return current <= maxCandidatesPerHost;
    }

    /**
     * 判断某个请求是否已经检测过。
     *
     * <p>Burp 的被动扫描会对同一请求多次触发（重放、跳转、刷新都会），
     * 不去重的话同一个候选能被检测几十次，白白放大流量。</p>
     *
     * @param key 请求指纹（调用方负责构造，通常用 method + url + 候选参数值）
     * @return 首次出现返回 true（应该继续检测）
     */
    public boolean markSeen(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        return seenRequestKeys.add(key);
    }

    /** 清空运行时计数（重置统计时用）。 */
    public void resetCounters() {
        candidateCounter.clear();
        seenRequestKeys.clear();
    }

    /**
     * 生成给用户看的配置摘要。
     */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("主动重放: ").append(activeReplayEnabled ? "已启用" : "已关闭（仅被动观察）").append('\n');
        sb.append("第二身份: ").append(secondIdentity.describe()).append('\n');
        sb.append("相似度阈值: ").append(String.format("%.2f", similarityThreshold)).append('\n');
        sb.append("对照请求: ").append(sendControlRequest ? "开启" : "关闭").append('\n');
        sb.append("方法白名单: ").append(String.join(", ", SAFE_METHODS.stream().sorted().toList())).append('\n');
        sb.append("单 host 上限: ").append(maxCandidatesPerHost).append(" 个候选\n");
        if (!includeHosts.isEmpty()) {
            sb.append("仅检测: ").append(String.join(", ", includeHosts)).append('\n');
        }
        if (!excludeHosts.isEmpty()) {
            sb.append("排除: ").append(String.join(", ", excludeHosts)).append('\n');
        }
        return sb.toString();
    }
}
