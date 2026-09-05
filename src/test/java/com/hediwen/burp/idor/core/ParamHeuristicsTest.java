package com.hediwen.burp.idor.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ID 参数识别测试。
 *
 * <p>这一层的准确率直接决定后面会不会满屏误报，所以覆盖要密：
 * 既要确认「像 ID 的被识别出来」，也要确认「不像 ID 的不被误认」。</p>
 */
class ParamHeuristicsTest {

    // ── 应该被识别为候选 ─────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "id", "uid", "user_id", "userId", "userid",
            "order_id", "orderId", "product_id", "doc_id",
            "account_id", "member_id", "tenantId", "group_id",
            "order_no", "orderCode", "sn"
    })
    @DisplayName("常见 ID 命名应被识别")
    void recognizesIdLikeNames(String name) {
        Optional<ParamHeuristics.Candidate> result = ParamHeuristics.classify(name, "1001");
        assertTrue(result.isPresent(), name + " 应该被识别为候选");
    }

    @Test
    @DisplayName("数字值应判定为 NUMERIC 形态")
    void recognizesNumericValue() {
        var candidate = ParamHeuristics.classify("id", "1001").orElseThrow();
        assertEquals(ParamHeuristics.ValueShape.NUMERIC, candidate.shape());
    }

    @Test
    @DisplayName("UUID 值应判定为 UUID 形态")
    void recognizesUuidValue() {
        var candidate = ParamHeuristics.classify(
                "user_id", "550e8400-e29b-41d4-a716-446655440000").orElseThrow();
        assertEquals(ParamHeuristics.ValueShape.UUID, candidate.shape());
    }

    @Test
    @DisplayName("候选必须带上判定理由（结论要可追溯）")
    void candidateCarriesReason() {
        var candidate = ParamHeuristics.classify("user_id", "42").orElseThrow();
        assertFalse(candidate.reason().isBlank(), "判定理由不能为空");
        assertTrue(candidate.describe().contains("user_id"), "描述里应包含参数名");
    }

    // ── 应该被排除 ─────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "page", "pageSize", "page_size", "limit", "offset", "size",
            "sort", "order", "orderBy", "sortBy", "direction",
            "timestamp", "ts", "time", "date", "startTime", "endTime",
            "version", "ver", "cache", "rand", "nonce",
            "token", "csrf", "csrfToken", "sign", "signature",
            "callback", "format", "lang", "locale"
    })
    @DisplayName("分页/排序/时间/鉴权类参数必须被排除")
    void excludesNoiseParams(String name) {
        Optional<ParamHeuristics.Candidate> result = ParamHeuristics.classify(name, "1001");
        assertTrue(result.isEmpty(), name + " 不该被当成 ID 参数");
    }

    @Test
    @DisplayName("名字不像 ID 的参数应被排除")
    void excludesNonIdNames() {
        assertTrue(ParamHeuristics.classify("username", "1001").isEmpty());
        assertTrue(ParamHeuristics.classify("keyword", "1001").isEmpty());
        assertTrue(ParamHeuristics.classify("email", "1001").isEmpty());
        assertTrue(ParamHeuristics.classify("status", "1001").isEmpty());
    }

    @Test
    @DisplayName("名字像 ID 但值不像的应被排除")
    void excludesWhenValueIsNotAnIdentifier() {
        // 空值：换身份重放往往会触发「参数缺失」的另一条代码路径，结果不可比
        assertTrue(ParamHeuristics.classify("id", "").isEmpty());
        assertTrue(ParamHeuristics.classify("id", "   ").isEmpty());

        // 短纯字母：多半是枚举值（如 status=active）
        assertTrue(ParamHeuristics.classify("id", "abc").isEmpty());
        assertTrue(ParamHeuristics.classify("id", "true").isEmpty());

        // 含空格的内容不是标识符
        assertTrue(ParamHeuristics.classify("id", "hello world").isEmpty());
    }

    @Test
    @DisplayName("空参数名应返回空结果而不是抛异常")
    void handlesBlankName() {
        assertTrue(ParamHeuristics.classify(null, "1001").isEmpty());
        assertTrue(ParamHeuristics.classify("", "1001").isEmpty());
        assertTrue(ParamHeuristics.classify("   ", "1001").isEmpty());
    }

    // ── 值形态判断 ─────────────────────────────────────────────

    @Test
    @DisplayName("值形态判断的各种边界")
    void classifiesValueShapes() {
        assertEquals(ParamHeuristics.ValueShape.NUMERIC, ParamHeuristics.classifyValue("0"));
        assertEquals(ParamHeuristics.ValueShape.NUMERIC, ParamHeuristics.classifyValue("-1"));
        assertEquals(ParamHeuristics.ValueShape.NUMERIC,
                ParamHeuristics.classifyValue("9223372036854775807"));

        assertEquals(ParamHeuristics.ValueShape.UUID,
                ParamHeuristics.classifyValue("550e8400-e29b-41d4-a716-446655440000"));

        // 短 token
        assertEquals(ParamHeuristics.ValueShape.TOKEN,
                ParamHeuristics.classifyValue("abc123xyz"));

        // 不像标识符
        assertEquals(ParamHeuristics.ValueShape.UNKNOWN, ParamHeuristics.classifyValue(""));
        assertEquals(ParamHeuristics.ValueShape.UNKNOWN, ParamHeuristics.classifyValue(null));
        assertEquals(ParamHeuristics.ValueShape.UNKNOWN, ParamHeuristics.classifyValue("a b c"));
    }

    @Test
    @DisplayName("大小写不敏感 —— userId 和 userid 都要认")
    void isCaseInsensitive() {
        assertTrue(ParamHeuristics.classify("UserId", "1").isPresent());
        assertTrue(ParamHeuristics.classify("USER_ID", "1").isPresent());
        assertTrue(ParamHeuristics.classify("UserID", "1").isPresent());
    }

    @Test
    @DisplayName("参数名前后空白应被容忍")
    void trimsName() {
        assertTrue(ParamHeuristics.classify("  user_id  ", "1").isPresent());
    }
}
