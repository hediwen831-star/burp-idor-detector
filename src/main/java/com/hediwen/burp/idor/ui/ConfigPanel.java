package com.hediwen.burp.idor.ui;

import burp.api.montoya.MontoyaApi;
import com.hediwen.burp.idor.config.CredentialProfile;
import com.hediwen.burp.idor.config.DetectorConfig;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Arrays;

/**
 * Burp 里的配置面板（一个独立 Suite Tab）。
 *
 * <h2>设计上最需要注意的一点</h2>
 *
 * 面板顶部必须**明确告诉用户「现在发不发请求」**。
 *
 * <p>一个安全插件最危险的状态是「用户以为它没在工作，实际它在发请求」。
 * 所以这里的状态栏不是装饰：它实时反映当前是「仅被动观察」
 * 还是「会主动重放」，让用户任何时候都知道自己在什么状态。</p>
 *
 * <p>这与 ASP 项目里「Web 接口默认只绑回环、绑公网必须配 token」是同一个原则：
 * <b>让工具的行为边界始终对使用者可见。</b></p>
 */
public class ConfigPanel extends JPanel {

    private final transient MontoyaApi api;
    private final transient DetectorConfig config;

    private final JCheckBox enableReplay = new JCheckBox("启用主动重放（会向目标发送额外请求）");
    private final JTextField identityName = new JTextField(18);
    private final JTextField headerName = new JTextField(18);
    private final JTextArea headerValue = new JTextArea(3, 48);
    private final JCheckBox sendControl = new JCheckBox("发送对照请求（用不存在的 ID 排除通配响应）");
    private final JSpinner threshold = new JSpinner(new SpinnerNumberModel(0.85, 0.50, 1.00, 0.01));
    private final JSpinner intervalMs = new JSpinner(new SpinnerNumberModel(100, 0, 5000, 50));
    private final JSpinner maxPerHost = new JSpinner(new SpinnerNumberModel(50, 1, 1000, 10));
    private final JTextArea includeHosts = new JTextArea(3, 48);
    private final JTextArea excludeHosts = new JTextArea(3, 48);
    private final JLabel status = new JLabel();

    public ConfigPanel(MontoyaApi api, DetectorConfig config) {
        this.api = api;
        this.config = config;

        setLayout(new BorderLayout());
        add(buildContent(), BorderLayout.CENTER);

        loadFromConfig();
        refreshStatus();
    }

    private JPanel buildContent() {
        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // ── 状态栏 ─────────────────────────────────────────────────
        status.setFont(status.getFont().deriveFont(Font.BOLD));
        status.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        root.add(status);

        // ── 安全提示 ───────────────────────────────────────────────
        JTextArea notice = new JTextArea("""
                默认不发送任何请求。插件装上后只做被动观察（识别哪些参数像 ID），
                不会主动重放。只有当你①配置了第二身份 并 ②勾选「启用主动重放」之后，
                才会开始真正的越权检测。

                为什么这么设计：自动重放会放大对目标的请求量，而且如果误判到写接口，
                可能真的修改业务数据。工具的默认值必须选安全的那一侧。
                """);
        notice.setEditable(false);
        notice.setLineWrap(true);
        notice.setWrapStyleWord(true);
        notice.setOpaque(false);
        notice.setBorder(BorderFactory.createEmptyBorder(0, 0, 14, 0));
        root.add(notice);

        // ── 开关 ──────────────────────────────────────────────────
        root.add(sectionLabel("运行模式"));
        enableReplay.addActionListener(e -> refreshStatus());
        root.add(enableReplay);
        root.add(Box.createVerticalStrut(4));
        sendControl.setToolTipText("建议保持开启：没有对照请求时无法区分「越权」和「该接口对任何 ID 都返回同样内容」");
        root.add(sendControl);
        root.add(Box.createVerticalStrut(14));

        // ── 第二身份 ───────────────────────────────────────────────
        root.add(sectionLabel("第二身份（用于重放请求）"));
        root.add(hint("从 Burp 里复制一条完整的鉴权请求头粘贴进来。常见形式：\n"
                + "  Cookie: JSESSIONID=...; SESSION=...\n"
                + "  Authorization: Bearer eyJhbGci...\n"
                + "  X-Auth-Token: ..."));

        JPanel identityRow = new JPanel();
        identityRow.setLayout(new BoxLayout(identityRow, BoxLayout.X_AXIS));
        identityRow.add(new JLabel("身份名称"));
        identityRow.add(Box.createHorizontalStrut(8));
        identityRow.add(identityName);
        identityRow.add(Box.createHorizontalStrut(16));
        identityRow.add(new JLabel("请求头名"));
        identityRow.add(Box.createHorizontalStrut(8));
        identityRow.add(headerName);
        identityRow.add(Box.createHorizontalGlue());
        root.add(identityRow);
        root.add(Box.createVerticalStrut(4));
        root.add(new JLabel("请求头值"));
        headerValue.setLineWrap(true);
        headerValue.setWrapStyleWord(true);
        JScrollPane valueScroll = new JScrollPane(headerValue);
        valueScroll.setPreferredSize(new Dimension(600, 70));
        valueScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));
        root.add(valueScroll);
        root.add(Box.createVerticalStrut(14));

        // ── 判定参数 ───────────────────────────────────────────────
        root.add(sectionLabel("判定参数"));
        root.add(spinnerRow("相似度阈值", threshold,
                "高于该值认为「两次响应内容基本相同」。太高会漏报，太低会误报，0.85 是经验起点"));
        root.add(spinnerRow("请求间隔 (ms)", intervalMs,
                "两次请求之间的最小间隔。限速是安全底线，不建议调到 0"));
        root.add(spinnerRow("单 host 候选上限", maxPerHost,
                "防止在一个中大型站点上刷出成百上千个重放请求"));
        root.add(Box.createVerticalStrut(14));

        // ── 范围控制 ───────────────────────────────────────────────
        root.add(sectionLabel("范围控制"));
        root.add(hint("每行一个主机名（不含端口）。留空表示不限制；排除列表优先级高于包含列表。"));
        root.add(new JLabel("仅检测这些 host"));
        includeHosts.setLineWrap(true);
        JScrollPane includeScroll = new JScrollPane(includeHosts);
        includeScroll.setPreferredSize(new Dimension(600, 60));
        includeScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));
        root.add(includeScroll);
        root.add(Box.createVerticalStrut(6));
        root.add(new JLabel("排除这些 host"));
        excludeHosts.setLineWrap(true);
        JScrollPane excludeScroll = new JScrollPane(excludeHosts);
        excludeScroll.setPreferredSize(new Dimension(600, 60));
        excludeScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));
        root.add(excludeScroll);
        root.add(Box.createVerticalStrut(16));

        // ── 按钮 ──────────────────────────────────────────────────
        JPanel buttons = new JPanel();
        buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));
        JButton save = new JButton("保存配置");
        save.addActionListener(e -> saveToConfig());
        JButton resetCounters = new JButton("重置计数");
        resetCounters.setToolTipText("清空「已检测请求」去重表和单 host 计数，允许重新检测");
        resetCounters.addActionListener(e -> {
            config.resetCounters();
            api.logging().logToOutput("[IDOR Detector] 计数已重置");
            refreshStatus();
        });
        JButton showSummary = new JButton("输出当前配置到日志");
        showSummary.addActionListener(e ->
                api.logging().logToOutput("[IDOR Detector] 当前配置：\n" + config.describe()));
        buttons.add(save);
        buttons.add(Box.createHorizontalStrut(8));
        buttons.add(resetCounters);
        buttons.add(Box.createHorizontalStrut(8));
        buttons.add(showSummary);
        buttons.add(Box.createHorizontalGlue());
        root.add(buttons);
        root.add(Box.createVerticalGlue());

        return root;
    }

    private JLabel sectionLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize2D() + 1f));
        label.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
        return label;
    }

    private JLabel hint(String text) {
        JLabel label = new JLabel("<html><body style='width:560px'>"
                + text.replace("\n", "<br>").replace(" ", "&nbsp;") + "</body></html>");
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        return label;
    }

    private JPanel spinnerRow(String label, JSpinner spinner, String tooltip) {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setToolTipText(tooltip);
        JLabel name = new JLabel(label);
        name.setPreferredSize(new Dimension(140, 24));
        spinner.setMaximumSize(new Dimension(110, 26));
        row.add(name);
        row.add(spinner);
        row.add(Box.createHorizontalStrut(12));
        row.add(new JLabel("<html><i style='font-size:10px'>" + tooltip + "</i></html>"));
        row.add(Box.createHorizontalGlue());
        row.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        return row;
    }

    // ── 状态刷新 ─────────────────────────────────────────────────

    /**
     * 刷新状态栏。
     *
     * <p>这段文字是这个面板最重要的部分 —— 它告诉用户「现在插件会不会发请求」。</p>
     */
    private void refreshStatus() {
        if (config.canDetect()) {
            status.setText("状态：检测已启用 —— 会对候选请求发起重放（含对照请求）");
        } else if (enableReplay.isSelected()) {
            status.setText("状态：已勾选主动重放，但第二身份未配置完整 —— 实际不会发请求");
        } else {
            status.setText("状态：仅被动观察 —— 不会发送任何额外请求");
        }
    }

    // ── 载入与保存 ───────────────────────────────────────────────

    private void loadFromConfig() {
        enableReplay.setSelected(config.isActiveReplayEnabled());

        CredentialProfile profile = config.getSecondIdentity();
        identityName.setText(profile.name());
        headerName.setText(profile.headerName());
        headerValue.setText(profile.headerValue());

        sendControl.setSelected(config.isSendControlRequest());
        threshold.setValue(config.getSimilarityThreshold());
        intervalMs.setValue(config.getMinRequestIntervalMs());
        maxPerHost.setValue(config.getMaxCandidatesPerHost());

        includeHosts.setText(String.join("\n", config.getIncludeHosts()));
        excludeHosts.setText(String.join("\n", config.getExcludeHosts()));
    }

    private void saveToConfig() {
        config.setActiveReplayEnabled(enableReplay.isSelected());
        config.setSecondIdentity(new CredentialProfile(
                identityName.getText().trim(),
                headerName.getText().trim(),
                headerValue.getText().trim()));
        config.setSendControlRequest(sendControl.isSelected());
        config.setSimilarityThreshold(((Number) threshold.getValue()).doubleValue());
        config.setMinRequestIntervalMs(((Number) intervalMs.getValue()).intValue());
        config.setMaxCandidatesPerHost(((Number) maxPerHost.getValue()).intValue());

        config.getIncludeHosts().clear();
        config.getIncludeHosts().addAll(parseHosts(includeHosts.getText()));
        config.getExcludeHosts().clear();
        config.getExcludeHosts().addAll(parseHosts(excludeHosts.getText()));

        refreshStatus();
        api.logging().logToOutput("[IDOR Detector] 配置已更新：\n" + config.describe());
    }

    /** 解析多行 host 输入，忽略空行与注释行。 */
    static java.util.List<String> parseHosts(String text) {
        return Arrays.stream(text.split("\\R"))
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .map(String::toLowerCase)
                .distinct()
                .toList();
    }
}
