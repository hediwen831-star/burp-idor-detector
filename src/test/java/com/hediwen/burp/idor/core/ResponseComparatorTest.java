package com.hediwen.burp.idor.core;

import com.hediwen.burp.idor.core.ResponseComparator.Fingerprint;
import com.hediwen.burp.idor.core.ResponseComparator.Verdict;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 响应对比测试。
 *
 * <p>这是整个插件最核心的逻辑 —— 判定准不准全看这里，所以覆盖最密。
 * 尤其是**通配响应**那条：它是误报控制的关键，
 * 一旦失效，插件就会对任何返回固定内容的接口刷出满屏假阳性。</p>
 */
class ResponseComparatorTest {

    private static final double THRESHOLD = 0.85;

    /** 构造指纹的便捷方法。 */
    private static Fingerprint fp(int status, String contentType, String body) {
        return ResponseComparator.fingerprint(status, contentType, body);
    }

    // ── 标准化 ──────────────────────────────────────────────────

    @Test
    @DisplayName("CSRF token 等动态内容应被标准化掉")
    void normalizesCsrfTokens() {
        String a = "<input name=\"csrf_token\" value=\"aaa111bbb222\">";
        String b = "<input name=\"csrf_token\" value=\"ccc333ddd444\">";

        String na = ResponseComparator.normalize(a);
        String nb = ResponseComparator.normalize(b);

        assertEquals(na, nb, "只有 token 不同的两个页面，标准化后应该一致");
        assertFalse(na.contains("aaa111bbb222"), "token 值不该残留在标准化结果里");
    }

    @Test
    @DisplayName("JSON 里的 token 字段应被标准化")
    void normalizesJsonTokens() {
        String a = "{\"csrfToken\":\"abc123\",\"name\":\"alice\"}";
        String b = "{\"csrfToken\":\"xyz789\",\"name\":\"alice\"}";
        assertEquals(ResponseComparator.normalize(a), ResponseComparator.normalize(b));
    }

    @Test
    @DisplayName("ISO 时间戳与 Unix 时间戳应被标准化")
    void normalizesTimestamps() {
        String a = "{\"created\":\"2026-09-17T13:00:00Z\",\"ts\":1758100000}";
        String b = "{\"created\":\"2026-09-18T09:30:12Z\",\"ts\":1758200000}";

        assertEquals(ResponseComparator.normalize(a), ResponseComparator.normalize(b),
                "只有时间不同的两个响应，标准化后应该一致");
    }

    @Test
    @DisplayName("空白差异应被压缩")
    void normalizesWhitespace() {
        // 注意：这里压缩的是【空白量】，不是【空格本身】。
        // 连续空白（换行 + 缩进）会变成单个空格，但原本就有的单个空格会保留 ——
        // 否则 "a b" 和 "ab" 会被判成同一个东西，那是另一回事。
        String multiLine = ResponseComparator.normalize("{\n  \"a\": 1\n}");

        assertFalse(multiLine.contains("\n"), "换行应该被压缩掉");
        assertFalse(multiLine.contains("  "), "连续空白应该被压成一个");

        // 结果是「压掉多余空白后的原文本」，不是「格式化后的 JSON」——
        // 所以 { 后面和 } 前面各留了一个空格。这对相似度计算没有影响
        // （两边都是同样的处理方式），不值得为它引入 JSON 解析。
        assertEquals("{ \"a\": 1 }", multiLine);
        assertEquals(multiLine, ResponseComparator.normalize("{\n\n    \"a\": 1\n\n}"));
    }

    @Test
    @DisplayName("长十六进制串（哈希/traceId）应被标准化")
    void normalizesLongHexStrings() {
        String a = "traceId: 4bf92f3577b34da6a3ce929d0e0e4736";
        String b = "traceId: 00f067aa0ba902b7c1d2e3f4a5b6c7d8";
        assertEquals(ResponseComparator.normalize(a), ResponseComparator.normalize(b));
    }

    @Test
    @DisplayName("短数字（业务 ID）不该被当成时间戳标准化掉")
    void doesNotNormalizeShortIds() {
        // 8 位以内是普通 ID，不该被 10 位时间戳的规则吃掉
        String normalized = ResponseComparator.normalize("{\"id\":1001}");
        assertTrue(normalized.contains("1001"), "短 ID 应该保留，否则相似度判断会失真");
    }

    // ── 相似度 ──────────────────────────────────────────────────

    @Test
    @DisplayName("完全相同的响应相似度接近 1")
    void identicalResponsesAreSimilar() {
        Fingerprint a = fp(200, "application/json", "{\"id\":1,\"name\":\"alice\"}");
        Fingerprint b = fp(200, "application/json", "{\"id\":1,\"name\":\"alice\"}");
        assertTrue(ResponseComparator.similarity(a, b) > 0.95);
    }

    @Test
    @DisplayName("完全不同的响应相似度很低")
    void differentResponsesAreNotSimilar() {
        Fingerprint a = fp(200, "application/json",
                "{\"id\":1,\"name\":\"alice\",\"balance\":9999,\"orders\":[1,2,3]}");
        Fingerprint b = fp(403, "text/html",
                "<html><body>Access Denied. You do not have permission to view this resource.</body></html>");
        assertTrue(ResponseComparator.similarity(a, b) < 0.5);
    }

    @Test
    @DisplayName("状态码不同会显著降低相似度")
    void differentStatusCodeLowersSimilarity() {
        String body = "same body content here for both responses";
        Fingerprint ok = fp(200, "text/html", body);
        Fingerprint redirect = fp(302, "text/html", body);
        assertTrue(ResponseComparator.similarity(ok, redirect) < 1.0);
    }

    // ── 三态判定（核心）──────────────────────────────────────────

    @Test
    @DisplayName("换身份相似 + 对照不相似 → 疑似越权")
    void detectsIdor() {
        String realResource = "{\"id\":1001,\"owner\":\"alice\",\"email\":\"alice@corp.com\",\"salary\":12345}";

        Fingerprint base = fp(200, "application/json", realResource);
        Fingerprint replay = fp(200, "application/json", realResource);
        Fingerprint control = fp(404, "application/json",
                "{\"error\":\"resource not found\",\"code\":40400}");

        var result = ResponseComparator.compare(base, replay, control, THRESHOLD);

        assertEquals(Verdict.SUSPECTED_IDOR, result.verdict());
        assertTrue(result.isSuspected());
        assertTrue(result.note().contains("未校验归属"));
    }

    @Test
    @DisplayName("★ 通配响应必须被识别为误报（误报控制的关键）")
    void rejectsWildcardResponse() {
        // 场景：这个接口对任何 ID 都返回同一个固定页面
        String fixedResponse = "{\"error\":\"invalid parameter\",\"message\":\"参数格式不正确\"}";

        Fingerprint base = fp(200, "application/json", fixedResponse);
        Fingerprint replay = fp(200, "application/json", fixedResponse);
        Fingerprint control = fp(200, "application/json", fixedResponse);

        var result = ResponseComparator.compare(base, replay, control, THRESHOLD);

        assertEquals(Verdict.WILDCARD_RESPONSE, result.verdict(),
                "换身份相似但对照也相似时，必须判为通配响应而不是越权");
        assertFalse(result.isSuspected(), "通配响应不能被当成越权上报");
    }

    @Test
    @DisplayName("换身份后响应不同 → 权限校验有效")
    void detectsProperAccessControl() {
        Fingerprint base = fp(200, "application/json",
                "{\"id\":1001,\"owner\":\"alice\",\"privateData\":\"secret\"}");
        Fingerprint replay = fp(403, "application/json",
                "{\"error\":\"forbidden\",\"message\":\"无权访问该资源\"}");
        Fingerprint control = fp(404, "application/json", "{\"error\":\"not found\"}");

        var result = ResponseComparator.compare(base, replay, control, THRESHOLD);

        assertEquals(Verdict.ACCESS_DENIED, result.verdict());
        assertFalse(result.isSuspected());
    }

    @Test
    @DisplayName("含动态 token 的真实越权场景仍能被检出")
    void detectsIdorDespiteDynamicContent() {
        // 两次响应带不同的 CSRF token 和 traceId —— 这是真实情况
        String baseBody = """
                {"id":1001,"owner":"alice","csrfToken":"aaa111","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}
                """;
        String replayBody = """
                {"id":1001,"owner":"alice","csrfToken":"bbb222","traceId":"00f067aa0ba902b7c1d2e3f4a5b6c7d8"}
                """;

        Fingerprint base = fp(200, "application/json", baseBody);
        Fingerprint replay = fp(200, "application/json", replayBody);
        Fingerprint control = fp(404, "application/json", "{\"error\":\"not found\"}");

        var result = ResponseComparator.compare(base, replay, control, THRESHOLD);

        assertEquals(Verdict.SUSPECTED_IDOR, result.verdict(),
                "动态内容被正确标准化之后，应该仍能识别出越权");
    }

    @Test
    @DisplayName("阈值可调，且边界行为正确")
    void thresholdIsConfigurable() {
        Fingerprint base = fp(200, "application/json", "{\"a\":1,\"b\":2,\"c\":3,\"d\":4}");
        Fingerprint replay = fp(200, "application/json", "{\"a\":1,\"b\":2,\"c\":3,\"d\":4}");
        Fingerprint control = fp(200, "application/json", "{\"a\":9,\"b\":8,\"c\":7,\"d\":6}");

        // 低阈值下 control 也可能被判为相似 → 应该归到通配响应
        var strict = ResponseComparator.compare(base, replay, control, 0.99);
        assertNotEquals(Verdict.ACCESS_DENIED, strict.verdict(),
                "换身份后完全相同，不该判为「权限校验有效」");
    }

    // ── 辅助函数 ────────────────────────────────────────────────

    @Test
    @DisplayName("Jaccard 的边界情况")
    void jaccardEdgeCases() {
        var a = ResponseComparator.shingles("hello world");
        var b = ResponseComparator.shingles("hello world");
        assertTrue(ResponseComparator.jaccard(a, b) > 0.99);

        // 两个空集视为完全相似（两个空响应确实是「一样的」）
        assertEquals(1.0, ResponseComparator.jaccard(
                ResponseComparator.shingles(""), ResponseComparator.shingles("")));

        // 一方为空一方不为空 → 完全不相似
        assertEquals(0.0, ResponseComparator.jaccard(
                ResponseComparator.shingles(""), ResponseComparator.shingles("content")));
    }

    @Test
    @DisplayName("对照值生成：数字取一个远超正常范围的值")
    void generatesNonExistentValues() {
        String control = IdorScanCheck.nonExistentValueLike("1001");
        assertNotEquals("1001", control, "对照值不能等于原值");
        assertTrue(control.length() > 6, "对照值应该远离正常 ID 范围，比如 999999999999");

        // 负数保持符号，避免改变服务端的分支逻辑
        assertTrue(IdorScanCheck.nonExistentValueLike("-5").startsWith("-"));

        // UUID 生成一个合法但不同的 UUID
        String uuidControl = IdorScanCheck.nonExistentValueLike("550e8400-e29b-41d4-a716-446655440000");
        assertNotEquals("550e8400-e29b-41d4-a716-446655440000", uuidControl);
        assertTrue(uuidControl.matches("[0-9a-f-]{36}"));

        // 其他形态拼一个明显异常的字符串
        assertTrue(IdorScanCheck.nonExistentValueLike("abc123xyz").contains("not_exists"));
    }

    @Test
    @DisplayName("pathAndQueryOf 能正确提取路径与查询串")
    void extractsPathAndQuery() {
        assertEquals("/api/users?id=1",
                IdorScanCheck.pathAndQueryOf("https://example.com/api/users?id=1"));
        assertEquals("/api/users",
                IdorScanCheck.pathAndQueryOf("https://example.com/api/users"));
        assertEquals("/",
                IdorScanCheck.pathAndQueryOf("https://example.com"));

        // 相对形式：Java 的 URI 会把它当成相对路径，这是合理行为。
        // 真实场景里 Montoya 的 request.url() 总是返回绝对 URL，走不到这个分支。
        assertEquals("not-a-valid-url",
                IdorScanCheck.pathAndQueryOf("not-a-valid-url"));

        // 真正非法的输入（含空格）才回退到 "/"
        assertEquals("/", IdorScanCheck.pathAndQueryOf("not a valid url"));
    }
}
