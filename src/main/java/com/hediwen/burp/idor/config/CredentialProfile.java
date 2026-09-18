package com.hediwen.burp.idor.config;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * 身份凭据 —— 用于「换一个身份重放请求」。
 *
 * <h2>为什么用「替换某个请求头」这种通用形式</h2>
 *
 * 真实项目里的身份凭证形态差异很大：
 *
 * <ul>
 *   <li>传统 Web：{@code Cookie: JSESSIONID=...; SESSION=...}</li>
 *   <li>前后端分离：{@code Authorization: Bearer eyJ...}</li>
 *   <li>网关鉴权：{@code X-Auth-Token: ...} / {@code X-Api-Key: ...}</li>
 *   <li>老系统：{@code Cookie: PHPSESSID=...} 或自定义头</li>
 * </ul>
 *
 * <p>与其为每种形态写一套适配（还要处理「Cookie 里换哪一个」「Bearer 要不要保留前缀」），
 * 不如统一成「替换/新增一个请求头」——<b>用户直接从 Burp 里复制那一条完整的头</b>粘贴进来。</p>
 *
 * <p>这样做的代价是用户需要手工填，但换来的是：<b>不存在「插件不认识这种鉴权方式」的情况</b>。
 * 对安全工具来说，「永远能配上」比「大多数情况自动识别」更重要。</p>
 *
 * @param name        身份名称（仅用于展示，如「受害者账号 A」）
 * @param headerName  要设置/替换的请求头名（如 {@code Cookie}、{@code Authorization}）
 * @param headerValue 请求头值
 */
public record CredentialProfile(String name, String headerName, String headerValue) {

    /** 缺省身份名称。 */
    private static final String DEFAULT_NAME = "第二身份";

    /**
     * 校验凭据是否可用。
     *
     * @return 可用返回 true
     */
    public boolean isConfigured() {
        return headerName != null && !headerName.isBlank()
                && headerValue != null && !headerValue.isBlank();
    }

    /**
     * 把本凭据应用到请求上。
     *
     * <p>注意：用 {@code withHeader} 而不是「追加头」——
     * 如果原请求已有同名头（比如旧的 Cookie），追加会导致两个头同时存在，
     * 服务端取哪个取决于实现，检测结果就不可靠了。
     * <b>必须是替换语义。</b></p>
     *
     * @param request 原始请求
     * @return 应用了第二身份的请求
     */
    public HttpRequest applyTo(HttpRequest request) {
        if (!isConfigured()) {
            return request;
        }
        return request.withHeader(headerName.trim(), headerValue.trim());
    }

    /** 用于日志/报告的脱敏描述 —— 不打印完整凭据值。 */
    public String describe() {
        if (!isConfigured()) {
            return (name == null || name.isBlank() ? DEFAULT_NAME : name) + "（未配置）";
        }
        String masked = maskValue(headerValue);
        return String.format("%s [%s: %s]", name == null || name.isBlank() ? DEFAULT_NAME : name,
                headerName.trim(), masked);
    }

    /**
     * 脱敏：只保留首尾少量字符。
     *
     * <p>Burp 的日志和 Issue 详情可能被用户截图或分享，
     * 凭据不该以明文出现在这些地方。</p>
     */
    static String maskValue(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 12) {
            return "****";
        }
        return trimmed.substring(0, 6) + "****" + trimmed.substring(trimmed.length() - 4);
    }

    /** 构造一个未配置的占位身份。 */
    public static CredentialProfile empty() {
        return new CredentialProfile(DEFAULT_NAME, "", "");
    }
}
