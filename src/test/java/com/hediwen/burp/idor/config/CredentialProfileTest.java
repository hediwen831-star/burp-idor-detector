package com.hediwen.burp.idor.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 身份凭据测试。
 *
 * <p>重点是**脱敏**：凭据不该以明文出现在日志或 Issue 详情里 ——
 * 那些地方会被用户截图、复制、分享。</p>
 */
class CredentialProfileTest {

    @Test
    @DisplayName("配置完整的凭据应判定为可用")
    void configuredProfileIsUsable() {
        var profile = new CredentialProfile("账号B", "Cookie", "JSESSIONID=abc123");
        assertTrue(profile.isConfigured());
    }

    @Test
    @DisplayName("缺任一项都判定为不可用")
    void incompleteProfileIsNotUsable() {
        assertFalse(new CredentialProfile("n", "", "value").isConfigured());
        assertFalse(new CredentialProfile("n", "Cookie", "").isConfigured());
        assertFalse(new CredentialProfile("n", null, "value").isConfigured());
        assertFalse(new CredentialProfile("n", "Cookie", null).isConfigured());
        assertFalse(new CredentialProfile("n", "   ", "   ").isConfigured());
    }

    @Test
    @DisplayName("空凭据工厂方法")
    void emptyProfile() {
        assertFalse(CredentialProfile.empty().isConfigured());
    }

    // ── 脱敏（关键）──────────────────────────────────────────────

    @Test
    @DisplayName("★ 长凭据必须脱敏，不能明文出现在日志里")
    void masksLongCredentials() {
        String secret = "JSESSIONID=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        String masked = CredentialProfile.maskValue(secret);

        assertFalse(masked.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                "完整凭据值不该出现在脱敏结果里");
        assertTrue(masked.contains("****"), "应该能看到脱敏标记");
        assertTrue(masked.startsWith("JSESSI"), "保留开头一点便于用户辨认是哪一个凭据");
    }

    @Test
    @DisplayName("短凭据直接全部打码，避免「脱敏后反而泄漏」")
    void masksShortCredentialsCompletely() {
        // 短字符串如果只留首尾，等于没脱敏
        assertEquals("****", CredentialProfile.maskValue("short"));
        assertEquals("****", CredentialProfile.maskValue("123456789012"));
    }

    @Test
    @DisplayName("空值不抛异常")
    void handlesEmptyValues() {
        assertEquals("", CredentialProfile.maskValue(null));
        assertEquals("", CredentialProfile.maskValue(""));
    }

    @Test
    @DisplayName("describe 输出应包含头名但不包含完整凭据")
    void describeDoesNotLeakCredential() {
        String secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        var profile = new CredentialProfile("受害者账号B", "Authorization", secret);

        String description = profile.describe();

        assertTrue(description.contains("受害者账号B"));
        assertTrue(description.contains("Authorization"));
        assertFalse(description.contains("payload.signature"), "完整凭据不该出现在描述里");
    }

    @Test
    @DisplayName("未配置时的描述应明确说明")
    void describesUnconfigured() {
        assertTrue(CredentialProfile.empty().describe().contains("未配置"));
    }
}
