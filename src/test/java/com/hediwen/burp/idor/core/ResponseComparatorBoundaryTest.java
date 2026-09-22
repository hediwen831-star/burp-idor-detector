package com.hediwen.burp.idor.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 边界值探针 —— 用来主动找 bug，而不是确认已知行为。
 *
 * <p>这些用例来自一次项目完整度盘点：核心逻辑的常规路径已有覆盖，
 * 但「输入处在极端值上会怎样」没人试过。这类问题在真实 Burp 流量里
 * 一定会遇到（空响应体、二进制附件、几 MB 的列表页）。</p>
 */
class ResponseComparatorBoundaryTest {

    @Test
    @DisplayName("空响应体：两个空响应应判为高度相似")
    void emptyBodiesAreSimilar() {
        var a = ResponseComparator.fingerprint(200, "text/html", "");
        var b = ResponseComparator.fingerprint(200, "text/html", "");
        assertTrue(ResponseComparator.similarity(a, b) > 0.99);
    }

    @Test
    @DisplayName("空 vs 非空：必须显著区分，否则会把「有内容」误判成「无内容」")
    void emptyVersusNonEmpty() {
        var empty = ResponseComparator.fingerprint(200, "text/html", "");
        var full = ResponseComparator.fingerprint(200, "text/html", "hello world");
        double sim = ResponseComparator.similarity(empty, full);
        // 状态码 0.3 + 类型 0.1 = 0.4，正文 0 分
        assertEquals(0.4, sim, 0.001, "空响应不该被当成与有内容响应相似");
    }

    @Test
    @DisplayName("null 正文与空正文等价，不应抛 NPE")
    void nullBodyIsSafe() {
        var a = ResponseComparator.fingerprint(200, null, null);
        var b = ResponseComparator.fingerprint(200, "", "");
        assertEquals(1.0, ResponseComparator.similarity(a, b), 0.001);
    }

    @Test
    @DisplayName("正文短于 shingle 长度（5）时不应崩溃，且相同短串仍相似")
    void shortBodyBelowShingleSize() {
        var a = ResponseComparator.fingerprint(200, "text/plain", "ab");
        var b = ResponseComparator.fingerprint(200, "text/plain", "ab");
        assertEquals(1.0, ResponseComparator.similarity(a, b), 0.001);

        var c = ResponseComparator.fingerprint(200, "text/plain", "cd");
        assertTrue(ResponseComparator.similarity(a, c) < 1.0, "不同短串不该被认为相同");
    }

    @Test
    @DisplayName("超长正文：不应出现性能塌陷或栈溢出")
    void veryLongBodyDoesNotBlowUp() {
        String big = "x".repeat(2_000_000);
        var a = ResponseComparator.fingerprint(200, "text/html", big);
        var b = ResponseComparator.fingerprint(200, "text/html", big);
        long start = System.nanoTime();
        double sim = ResponseComparator.similarity(a, b);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals(1.0, sim, 0.001);
        assertTrue(ms < 5000, "2MB 正文的相似度计算耗时 " + ms + "ms，过慢");
    }

    @Test
    @DisplayName("二进制/控制字符正文不应抛异常")
    void binaryBodyIsSafe() {
        String binary = "\u0000\u0001\u0002\uFFFD\uD83D\uDE00 mixed \r\n\ttext";
        var a = ResponseComparator.fingerprint(200, "application/octet-stream", binary);
        var b = ResponseComparator.fingerprint(200, "application/octet-stream", binary);
        assertEquals(1.0, ResponseComparator.similarity(a, b), 0.001);
    }

    @Test
    @DisplayName("Content-Type 带 charset 参数时，应与不带参数的同类响应算同一种")
    void contentTypeIgnoresCharset() {
        var a = ResponseComparator.fingerprint(200, "application/json; charset=utf-8", "{\"a\":1}");
        var b = ResponseComparator.fingerprint(200, "application/json", "{\"a\":1}");
        assertEquals(1.0, ResponseComparator.similarity(a, b), 0.001,
                "charset 差异不该影响内容类型判定");
    }

    @Test
    @DisplayName("Content-Type 大小写不同不应影响判定")
    void contentTypeIsCaseInsensitive() {
        var a = ResponseComparator.fingerprint(200, "Application/JSON", "{\"a\":1}");
        var b = ResponseComparator.fingerprint(200, "application/json", "{\"a\":1}");
        assertEquals(1.0, ResponseComparator.similarity(a, b), 0.001);
    }

    @Test
    @DisplayName("3xx 与 2xx 的正文都为空时，不应被误判为相似")
    void redirectVersusOkIsNotSimilar() {
        // 这是三态对比最容易出错的地方：302 跳登录页和 200 正常页
        // 正文可能都是空/极短，但语义完全相反
        var redirect = ResponseComparator.fingerprint(302, "text/html", "");
        var ok = ResponseComparator.fingerprint(200, "text/html", "");
        double sim = ResponseComparator.similarity(redirect, ok);
        assertTrue(sim < ResponseComparator.DEFAULT_SIMILARITY_THRESHOLD,
                "302 与 200 的空响应相似度 " + sim + " 过高，会把「被踢到登录页」误判成「权限校验有效」");
    }

    @Test
    @DisplayName("同类别状态码（都是 4xx）应拿到部分分数")
    void sameStatusClassGetsPartialCredit() {
        var a = ResponseComparator.fingerprint(404, "text/html", "not found");
        var b = ResponseComparator.fingerprint(403, "text/html", "not found");
        double sim = ResponseComparator.similarity(a, b);
        // 0.15（同类别） + 0.1（类型相同） + 0.6 * 1.0（正文相同） = 0.85
        assertEquals(0.85, sim, 0.001);
    }

    @Test
    @DisplayName("一方无 Content-Type 时扣分应小于「类型冲突」")
    void missingContentTypeIsNotPenalizedFully() {
        var noType = ResponseComparator.fingerprint(200, null, "hello");
        var json = ResponseComparator.fingerprint(200, "application/json", "hello");
        double missing = ResponseComparator.similarity(noType, json);

        var html = ResponseComparator.fingerprint(200, "text/html", "hello");
        double conflict = ResponseComparator.similarity(html, json);

        assertTrue(missing > conflict,
                "信息缺失（" + missing + "）不应比类型冲突（" + conflict + "）惩罚更重");
    }

    @Test
    @DisplayName("阈值边界：恰好等于阈值时应判定为相似（含等号）")
    void thresholdBoundaryIsInclusive() {
        var base = ResponseComparator.fingerprint(200, "text/html", "abcdefghij");
        var replay = ResponseComparator.fingerprint(200, "text/html", "abcdefghij");
        var control = ResponseComparator.fingerprint(500, "text/html", "zzzzzzzzzz");

        var c = ResponseComparator.compare(base, replay, control, 1.0);
        assertTrue(c.baseVsReplay() >= 1.0);
        assertFalse(c.isSuspected() && c.verdict() == ResponseComparator.Verdict.WILDCARD_RESPONSE,
                "对照完全不相似时不该判成通配响应");
    }

    @Test
    @DisplayName("所有输入都相同时（base=replay=control），应判为通配响应而非越权")
    void universalResponseIsWildcard() {
        var same = ResponseComparator.fingerprint(200, "text/html", "same content everywhere");
        var c = ResponseComparator.compare(same, same, same, ResponseComparator.DEFAULT_SIMILARITY_THRESHOLD);
        assertEquals(ResponseComparator.Verdict.WILDCARD_RESPONSE, c.verdict(),
                "「任何 ID 都返回同样内容」必须判为误报，这是防误报的核心");
    }
}
