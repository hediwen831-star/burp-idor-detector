package com.hediwen.burp.idor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.hediwen.burp.idor.config.DetectorConfig;
import com.hediwen.burp.idor.core.IdorScanCheck;
import com.hediwen.burp.idor.ui.ConfigPanel;

/**
 * Burp 扩展入口。
 *
 * <h2>插件做什么</h2>
 *
 * 检测越权访问（IDOR / Broken Object Level Authorization）：
 * 从 Burp 的真实流量里挑出「像资源标识的参数」，用第二身份重放，
 * 通过三态对比判断服务端是否校验了资源归属。
 *
 * <h2>加载时会做什么 / 不会做什么</h2>
 *
 * <p>加载时只做两件事：注册一个被动扫描检查、注册一个配置面板。</p>
 *
 * <p><b>不会发送任何请求。</b>插件的默认状态是「仅被动观察」——
 * 只识别哪些参数像 ID，不重放。用户必须显式配置第二身份并勾选启用之后，
 * 才会开始真正的越权检测。</p>
 *
 * <p>这个默认值是有意选的。见 {@link DetectorConfig} 的类注释：
 * 一个在后台自动发请求的安全插件，最大的风险不是漏检，是把它装上的那一刻
 * 就开始不受控地给目标制造流量。</p>
 */
public class IdorDetectorExtension implements BurpExtension {

    /** 注册到 Burp 的扩展名。 */
    private static final String EXTENSION_NAME = "IDOR Detector";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        DetectorConfig config = new DetectorConfig();

        // 被动扫描检查：观察流量、识别候选、按配置决定是否重放。
        // 用 PER_REQUEST 而不是 PER_HOST —— 越权是「逐条资源」的问题，
        // 同一个 host 下不同接口的行为完全不同，必须逐请求判断。
        api.scanner().registerPassiveScanCheck(
                new IdorScanCheck(api, config),
                ScanCheckType.PER_REQUEST);

        // 配置面板作为独立的 Suite Tab
        api.userInterface().registerSuiteTab(EXTENSION_NAME, new ConfigPanel(api, config));

        printBanner(api);
    }

    /**
     * 加载时在 Burp 的 Output 里打印一段说明。
     *
     * <p>不是装饰 —— 插件必须在被装上的第一时间就告诉用户
     * 「我现在不会发请求，你需要做什么才会开始检测」。
     * 否则用户要么以为它没工作，要么以为它在乱发请求。</p>
     */
    private void printBanner(MontoyaApi api) {
        api.logging().logToOutput("""
                ================================================================
                  IDOR Detector —— 越权（IDOR）自动化检测
                ================================================================

                  当前状态：仅被动观察，不会发送任何额外请求。

                  插件现在只做一件事：从流量里识别「像资源标识的参数」，
                  并记录到日志。不会重放、不会扫描。

                  要启用真正的检测，请到 "IDOR Detector" 标签页：
                    1) 填入第二身份（从 Burp 里复制一条完整的鉴权请求头）
                    2) 勾选「启用主动重放」
                    3) 点「保存配置」

                  检测方式（三态对比）：
                    ① 以当前会话请求一次          → 基准响应
                    ② 换第二身份重放同一请求      → 判断内容是否相同
                    ③ 把 ID 换成不存在的值再请求  → 排除「通配响应」误报

                  安全说明：
                    · 仅对 GET / HEAD / OPTIONS 生效（避免误改业务数据）
                    · 带限速（默认 100ms 间隔）
                    · 单 host 候选数有上限（默认 50）
                    · 结果只是「疑似」，请人工确认后再上报
                ================================================================
                """);
    }
}
