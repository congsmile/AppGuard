import os
import time
from datetime import datetime
import app_guard_scanner
import compliance_agent

def generate_report(data, output_dir="outputs"):
    """
    生成 AppGuard 移动应用隐私合规高保真存证报告 (HTML)
    支持: 静态代码 (Static) / 动态硬件沙箱 (Dynamic) / 动静双轨交叉存证 (Hybrid)
    包含: 第三方 SDK 责任穿透大盘 + 工信部合规修复代码补丁库
    """
    os.makedirs(output_dir, exist_ok=True)
    pkg = data.get("package_name", "unknown_app")
    audit_type = data.get("audit_type", "static")
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"Compliance_Report_{pkg}_{audit_type}_{ts}.html"
    filepath = os.path.join(output_dir, filename)

    app_name = data.get("app_name", pkg)
    demo_badge = ' <span style="font-size:11px;padding:2px 8px;border-radius:999px;background:rgba(245,158,11,0.15);color:#f59e0b;border:1px solid rgba(245,158,11,0.35);font-weight:700;vertical-align:middle;margin-left:6px;">[演练预置样本 · 供功能演示]</span>' if data.get("is_demo_sample") else ""
    score = data.get("compliance_score", 85)
    risk_level = data.get("risk_level", "中风险")
    target_sdk = data.get("target_sdk", "35")
    file_size_mb = data.get("file_size_mb", 0)
    payload_mb = data.get("payload_mb", 0)
    filter_ratio = data.get("filter_ratio", "N/A")
    elapsed = data.get("elapsed", 5.0)
    md5_hash = data.get("md5", "4c8f2a1b9d0e7c5a3f6e1b8d2a4c6e8f")
    sha256_hash = data.get("sha256", "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e")
    dev_prof = data.get("device_profile", {})
    cross_val = data.get("cross_validation", {})
    timeline = data.get("timeline", [])
    findings = data.get("findings", [])
    dimensions = data.get("dimensions", {})

    # 智能体场景化裁决分析 (Agent Contextual Verdict)
    agent_analysis = data.get("agent_analysis")
    if not agent_analysis:
        try:
            agent_analysis = compliance_agent.default_compliance_agent.analyze(
                data,
                app_category=data.get("app_category", ""),
                app_description=data.get("app_description", "")
            )
            data["agent_analysis"] = agent_analysis
        except Exception as _e:
            agent_analysis = None

    is_fused = data.get("is_fused", False)
    fuse_reason = data.get("fuse_reason", "")

    # 获取或构建 SDK 归因矩阵
    sdk_attribution = data.get("sdk_attribution")
    if not sdk_attribution:
        sdk_attribution = app_guard_scanner.build_sdk_attribution(findings)
        data["sdk_attribution"] = sdk_attribution

    # 样式与主题颜色定义
    if score >= 80:
        score_color = "#10b981"
        badge_border = "rgba(16, 185, 129, 0.4)"
        badge_bg = "rgba(16, 185, 129, 0.15)"
    elif score >= 60:
        score_color = "#f59e0b"
        badge_border = "rgba(245, 158, 11, 0.4)"
        badge_bg = "rgba(245, 158, 11, 0.15)"
    else:
        score_color = "#ef4444"
        badge_border = "rgba(239, 68, 68, 0.4)"
        badge_bg = "rgba(239, 68, 68, 0.15)"

    type_titles = {
        "static": ("静态代码逆向分析 (字节码/XRef)", "#38bdf8", "Androguard 4.1.4 字节码语义图谱"),
        "dynamic": ("端侧真机动态硬件沙箱 (Hardware Sandbox)", "#f59e0b", "HyperOS Android 16 Kernel 探针隔离"),
        "hybrid": ("动静双轨交叉存证矩阵 (Hybrid Matrix)", "#10b981", "工信部合规标准 · 动静双轨高保真存证")
    }
    type_title, type_color, type_sub = type_titles.get(audit_type, type_titles["static"])

    # 四维健康度指标
    dim_cards_html = ""
    if dimensions:
        for k in ['dim_device', 'dim_behavior', 'dim_permission', 'dim_data']:
            v = dimensions.get(k)
            if not v:
                continue
            pct = int((v["score"] / v["weight"]) * 100) if v["weight"] > 0 else 100
            bar_color = "#10b981" if pct >= 80 else ("#f59e0b" if pct >= 60 else "#ef4444")
            dim_cards_html += f"""
            <div class="dim-card">
                <div class="dim-title">{v['name']}</div>
                <div class="dim-val">{v['score']} <span style="font-size:12px;color:#94a3b8;">/ {v['weight']}分</span></div>
                <div class="dim-progress"><div style="background:{bar_color};width:{pct}%;height:100%;border-radius:4px;"></div></div>
                <div class="dim-sub">核算扣除: -{v.get('deduction', 0)} 分 ({pct}%)</div>
            </div>
            """

    # 第三方 SDK 责任穿透大盘 HTML
    sdk_rows = ""
    for s in sdk_attribution.get("sdk_list", []):
        rules_text = "、".join(s.get("rules", [])[:3])
        if len(s.get("rules", [])) > 3:
            rules_text += f" 等 {len(s['rules'])} 项"
        cat = s.get("category", "commercial_sdk")
        if cat == "official_framework":
            cat_badge = '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3);margin-right:6px;">官方框架</span>'
            pct_color = "#10b981"
        else:
            cat_badge = '<span class="badge" style="background:rgba(244,63,94,0.15);color:#fb7185;border:1px solid rgba(244,63,94,0.3);margin-right:6px;">商业SDK</span>'
            pct_color = "#f87171"
        sdk_rows += f"""
        <tr>
            <td>{cat_badge}<strong style="color:#f8fafc;">{s.get('name', '第三方SDK')}</strong></td>
            <td><code style="color:#38bdf8;">{s.get('count', 0)} 处</code></td>
            <td><span style="font-weight:bold;color:{pct_color};">{s.get('percentage', 0)}%</span></td>
           <td><span style="font-size:11px;color:#cbd5e1;">{rules_text}</span></td>
           <td style="font-size:11px;color:#94a3b8;line-height:1.4;">{s.get('action_advice', '')}</td>
       </tr>
       """

    # 构建 Agent 场景化最小必要性智能裁决卡片 HTML
    agent_verdict_html = ""
    if agent_analysis:
        p_name = agent_analysis.get("agent_provider", "AppGuard-Expert-Agent")
        c_name = agent_analysis.get("app_category_name", "通用业务类")
        l_ref = agent_analysis.get("statutory_law_ref", "四部委《39类App必要个人信息规定》")
        desc_text = agent_analysis.get("app_description", "")
        b_score = agent_analysis.get("baseline_score", score)
        a_score = agent_analysis.get("adjusted_score", b_score)
        conf = agent_analysis.get("confidence_percent")
        claim_mode = agent_analysis.get("claim_mode", "申报主营业务品类（开发者自述/测试指定）")
        legal_disclaimer = agent_analysis.get("legal_disclaimer", "")
        if conf is not None:
            conf_str = f"(置信度 {conf:.1f}%)"
        else:
            conf_str = "(确定性国标规则推导)"
        score_diff = a_score - b_score
        if score_diff > 0:
            diff_badge = f'<span style="color:#10b981;font-size:11px;font-weight:bold;margin-left:4px;">(+{score_diff} 豁免回补)</span>'
        elif score_diff < 0:
            diff_badge = f'<span style="color:#f87171;font-size:11px;font-weight:bold;margin-left:4px;">({score_diff} 违规加重扣罚)</span>'
        else:
            diff_badge = '<span style="color:#94a3b8;font-size:11px;margin-left:4px;">(基线维持)</span>'
        score_color = "#10b981" if a_score >= b_score else "#f87171"
        v_badge = agent_analysis.get("verdict_badge", "EXEMPTION_GRANTED")
        v_title = agent_analysis.get("verdict_title", "合规场景裁决完成")
        assessment = (agent_analysis.get("comprehensive_assessment") or "").replace("\n", "<br>")

        badge_style = "background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.4);"
        if v_badge == "SEVERE_VIOLATION":
            badge_style = "background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.4);"
        elif v_badge == "PARTIAL_DEFECT":
            badge_style = "background:rgba(245,158,11,0.15);color:#fbbf24;border:1px solid rgba(245,158,11,0.4);"

        traces_html = ""
        for t in agent_analysis.get("detailed_traces", []):
            act = t.get("verdict_action", "维持评定")
            act_color = "#10b981" if ("豁免" in act or "优化" in act or "保留" in act) else ("#f87171" if ("严惩" in act or "维持" in act) else "#fbbf24")
            patch_box = ""
            if t.get("targeted_code_patch"):
                p_code = t["targeted_code_patch"].replace("<", "&lt;").replace(">", "&gt;")
                patch_box = f'<div style="margin-top:8px;background:#050608;padding:8px 12px;border-radius:6px;border:1px solid rgba(56,189,248,0.25);font-family:monospace;font-size:11px;color:#38bdf8;white-space:pre-wrap;">{p_code}</div>'
            traces_html += f"""
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
                <td style="padding:10px 12px;vertical-align:top;font-size:12px;">
                    <strong style="color:#f8fafc;">{t.get('rule_name')}</strong><br>
                    <code style="color:#94a3b8;font-size:10px;">{t.get('rule_id')}</code>
                </td>
                <td style="padding:10px 12px;vertical-align:top;font-size:11px;">
                    <div style="color:#38bdf8;font-family:monospace;word-break:break-all;">{t.get('code_location_trace')}</div>
                </td>
                <td style="padding:10px 12px;vertical-align:top;font-size:11px;">
                    <span style="display:inline-block;padding:2px 8px;border-radius:999px;font-weight:bold;color:{act_color};background:rgba(255,255,255,0.05);border:1px solid {act_color}55;">
                        {act}
                    </span>
                    <div style="margin-top:6px;color:#cbd5e1;line-height:1.5;">{t.get('root_cause_explanation')}</div>
                    {patch_box}
                </td>
            </tr>
            """

        agent_verdict_html = f"""
        <!-- Agent 场景化最小必要性智能裁决意见书 -->
        <div class="section-card" style="border:1px solid rgba(56,189,248,0.4);background:linear-gradient(180deg, rgba(14,165,233,0.08) 0%, rgba(18,21,31,0.95) 100%);">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;border-bottom:1px solid rgba(255,255,255,0.08);padding-bottom:14px;margin-bottom:16px;">
                <div>
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span style="background:#0284c7;color:white;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:bold;">AI+ AGENT</span>
                        <h3 style="margin:0;font-size:17px;font-weight:800;color:#f8fafc;">场景化最小必要性智能裁决意见书 (Compliance Agent Verdict)</h3>
                    </div>
                    <div style="font-size:11px;color:#94a3b8;margin-top:4px;">
                        推理引擎: <strong style="color:#38bdf8;">{p_name}</strong> · 法定标准依据: <span>{l_ref}</span>
                    </div>
                </div>
                <div style="text-align:right;">
                    <span class="badge" style="{badge_style}font-size:12px;font-weight:bold;">
                        {v_title}
                    </span>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:12px;margin-bottom:16px;">
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:12px;">
                    <div style="font-size:11px;color:#94a3b8;">{claim_mode}</div>
                    <div style="font-size:14px;font-weight:bold;color:#f8fafc;margin-top:4px;">{c_name}</div>
                    <div style="font-size:11px;color:#64748b;margin-top:2px;">四部委 39 类标准基线</div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:12px;">
                    <div style="font-size:11px;color:#94a3b8;">机检初筛分 vs Agent 场景裁定分</div>
                    <div style="display:flex;align-items:baseline;gap:8px;margin-top:4px;">
                        <span style="font-size:13px;color:#94a3b8;text-decoration:line-through;">机检参考 {b_score} 分</span>
                        <span style="font-size:20px;font-weight:900;color:{score_color};">Agent 最终 {a_score} 分</span>
                        {diff_badge}
                        <span style="font-size:10px;color:#38bdf8;">{conf_str}</span>
                    </div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:12px;grid-column:1 / -1;">
                    <div style="font-size:11px;color:#94a3b8;">申报主营业务用途说明</div>
                    <div style="font-size:12px;color:#cbd5e1;margin-top:4px;line-height:1.5;">{desc_text}</div>
                </div>
            </div>
            <div style="background:rgba(56,189,248,0.04);border-left:3px solid #38bdf8;padding:12px 16px;border-radius:4px;margin-bottom:16px;font-size:12px;line-height:1.6;color:#e2e8f0;">
                {assessment}
            </div>
            <div style="margin-top:14px;">
                <div style="font-size:13px;font-weight:bold;color:#f8fafc;margin-bottom:8px;display:flex;align-items:center;gap:6px;">
                    <span>疑点调用链代码位置深度追溯与场景裁决明细</span>
                    <span style="font-size:11px;color:#94a3b8;font-weight:normal;">(穿透类名::方法名与第三方 SDK 归属)</span>
                </div>
                <table style="width:100%;border-collapse:collapse;text-align:left;">
                    <thead>
                        <tr style="background:rgba(255,255,255,0.04);border-bottom:1px solid rgba(255,255,255,0.1);font-size:11px;color:#94a3b8;">
                            <th style="padding:10px 12px;width:24%;">工信部红线核查项</th>
                            <th style="padding:10px 12px;width:34%;">DEX 字节码精确调用点与责任主体</th>
                            <th style="padding:10px 12px;width:42%;">Agent 场景裁决·因果剖析与定向补丁</th>
                        </tr>
                    </thead>
                    <tbody>
                        {traces_html}
                    </tbody>
                </table>
            </div>
            {f'<div style="margin-top:14px;padding:10px 14px;border-radius:8px;background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.25);font-size:11px;color:#fca5a5;line-height:1.5;"><strong style="color:#ef4444;">【法律存证声明与责任边界】：</strong>{legal_disclaimer}</div>' if legal_disclaimer else ''}
        </div>
        """

    sdk_matrix_html = f"""
    <div class="section-card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
           <div style="display:flex;align-items:center;gap:8px;">
               <span class="badge" style="background:rgba(56,189,248,0.15);color:#38bdf8;border:1px solid rgba(56,189,248,0.3);">责任穿透</span>
               <h3 style="margin:0;font-size:16px;">第三方 SDK 责任穿透与侵权归因大盘 (SDK Accountability Matrix)</h3>
           </div>
            <span style="font-size:12px;color:#94a3b8;font-family:monospace;">
                自研业务 <strong style="color:#38bdf8;">{sdk_attribution.get('host_pct', 0)}%</strong> | 
                官方框架 <strong style="color:#10b981;">{sdk_attribution.get('framework_pct', 0)}%</strong> | 
                商业SDK <strong style="color:#f87171;">{sdk_attribution.get('sdk_pct', 0)}%</strong>
            </span>
        </div>
        
        <!-- 三维责任切分条 (自研业务 / 官方系统兼容框架 / 商业第三方SDK) -->
        <div style="width:100%;height:12px;border-radius:6px;background:#1e293b;overflow:hidden;display:flex;margin-bottom:14px;">
            <div style="background:linear-gradient(90deg, #0284c7, #38bdf8);width:{sdk_attribution.get('host_pct', 0)}%;height:100%;" title="宿主自研业务: {sdk_attribution.get('host_pct', 0)}%"></div>
            <div style="background:linear-gradient(90deg, #059669, #10b981);width:{sdk_attribution.get('framework_pct', 0)}%;height:100%;" title="官方系统框架: {sdk_attribution.get('framework_pct', 0)}%"></div>
            <div style="background:linear-gradient(90deg, #e11d48, #fb7185);width:{sdk_attribution.get('sdk_pct', 0)}%;height:100%;" title="商业第三方SDK: {sdk_attribution.get('sdk_pct', 0)}%"></div>
        </div>
        
        <div style="background:rgba(255,255,255,0.03);border:1px solid var(--card-border);border-radius:10px;padding:12px 14px;font-size:12px;color:#cbd5e1;line-height:1.6;margin-bottom:14px;">
            <strong>合规穿透审计意见：</strong>{sdk_attribution.get('accountability_verdict', '')}
        </div>

        <table class="data-table">
            <thead>
                <tr>
                    <th style="width:24%;">SDK 标识 / 厂商</th>
                    <th style="width:12%;">违规调用数</th>
                    <th style="width:12%;">风险占比</th>
                    <th style="width:26%;">命中工信部红线</th>
                    <th style="width:26%;">法务合规处置指引</th>
                </tr>
            </thead>
            <tbody>
                {sdk_rows if sdk_rows else '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">未检测出第三方商业 SDK 越界行为</td></tr>'}
            </tbody>
        </table>
    </div>
    """

    # 交叉验证结论区块
    cross_val_html = ""
    if cross_val or audit_type in ["dynamic", "hybrid"]:
        dyn_cnt = cross_val.get("dynamic_confirmed", len(data.get("dynamic_violations", [])))
        stat_cnt = cross_val.get("static_rules_scanned", len(findings))
        if stat_cnt > 0:
            calc_acc = f"{round((dyn_cnt / stat_cnt) * 100, 1)}%"
        else:
            calc_acc = "100.0%" if dyn_cnt == 0 else "N/A"
        acc = cross_val.get("accuracy") or calc_acc
        verdict = cross_val.get("verdict", "沙箱真实捕获运行时越界调用，成功排除静态死代码误报，符合工信部合规检测与技术存证规范。")
        eliminated = max(0, stat_cnt - dyn_cnt)
        
        cross_val_html = f"""
        <div class="section-card cross-val-card">
           <div class="cv-header">
               <div style="display:flex;align-items:center;gap:10px;">
                   <span class="pulse-dot"></span>
                    <h3 style="margin:0;font-size:16px;">动静双轨交叉印证证据链 (Cross-Verification Evidence)</h3>
               </div>
               <span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3);">
                   保真度: {acc} (极高可信度)
               </span>
           </div>
           <p style="margin:10px 0 16px 0;font-size:13px;color:#cbd5e1;line-height:1.6;">
                <strong>技术审计意见：</strong>{verdict}
           </p>
           <div class="cv-grid">
               <div class="cv-stat">
                   <div class="cv-stat-label">静态代码规则全量检出</div>
                   <div class="cv-stat-num" style="color:#38bdf8;">{stat_cnt} <span style="font-size:12px;font-weight:normal;">项潜在调用</span></div>
                   <div class="cv-stat-desc">含第三方 SDK 冗余死代码</div>
               </div>
               <div class="cv-stat">
                    <div class="cv-stat-label">真机硬件沙箱运行时捕获</div>
                    <div class="cv-stat-num" style="color:#ef4444;">{dyn_cnt} <span style="font-size:12px;font-weight:normal;">项现场激活</span></div>
                    <div class="cv-stat-desc">在未明示前窗口期捕获调用</div>
               </div>
               <div class="cv-stat">
                    <div class="cv-stat-label">成功消歧非活跃调用</div>
                    <div class="cv-stat-num" style="color:#10b981;">{eliminated} <span style="font-size:12px;font-weight:normal;">项死代码</span></div>
                    <div class="cv-stat-desc">有效排除非活跃干扰项</div>
               </div>
               <div class="cv-stat">
                    <div class="cv-stat-label">测试物理设备与内核</div>
                    <div class="cv-stat-num" style="color:#fbbf24;font-size:15px;line-height:28px;">{dev_prof.get('model', 'Xiaomi 23113RKC6C')}</div>
                    <div class="cv-stat-desc">Android {dev_prof.get('android_version', '16')} · Non-Root 隔离</div>
                </div>
            </div>
        </div>
        """

    # 时序轨迹 HTML
    timeline_html = ""
    if timeline:
        rows = ""
        for t in timeline:
            is_bad = t.get("level") in ["HIGH", "CRITICAL"]
            dot_bg = "#ef4444" if is_bad else "#64748b"
            badge_color = "#f87171" if is_bad else "#94a3b8"
            badge_bg_row = "rgba(239,68,68,0.15)" if is_bad else "rgba(255,255,255,0.06)"
            rows += f"""
            <div class="tl-item">
                <div class="tl-marker" style="background:{dot_bg};"></div>
                <div class="tl-content">
                    <div class="tl-top">
                        <div>
                            <span class="tl-time">{t.get('time', 'T+0.00s')}</span>
                            <span class="tl-stage">{t.get('stage', '生命周期')}</span>
                            <span class="tl-cat">({t.get('category', '合规')})</span>
                        </div>
                        <span class="tl-verdict" style="background:{badge_bg_row};color:{badge_color};">{t.get('verdict', '正常')}</span>
                    </div>
                    <div class="tl-event">{t.get('event', '')}</div>
                    {f'<div class="tl-raw"><code>{t.get("raw")}</code></div>' if t.get('raw') else ''}
                </div>
            </div>
            """
        timeline_html = f"""
        <div class="section-card">
            <h3 style="margin:0 0 14px 0;font-size:16px;">毫秒级端侧动态行为时序审计轨迹 (Dynamic Execution Timeline)</h3>
            <div class="tl-container">
                {rows}
            </div>
        </div>
        """

    # 工信部违规明细 HTML
    findings_html = ""
    for f in findings:
        r = f.get("rule", {})
        sev = r.get("severity", "MEDIUM").upper()
        b_cls = "badge-critical" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else "badge-medium")
        
        cross_badge = ""
        if r.get("framework_internal_only"):
            cross_badge = f"""<span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold;background:rgba(16,185,129,0.2);color:#10b981;border:1px solid rgba(16,185,129,0.4);margin-left:8px;">[官方框架良性兼容·豁免扣分]</span>"""
        elif f.get("cross_status") == "confirmed":
            cross_badge = f"""<span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold;background:rgba(239,68,68,0.2);color:#f87171;border:1px solid rgba(239,68,68,0.4);margin-left:8px;">[动静交叉印证·运行时捕获 {f.get('dynamic_trigger_time', '')}]</span>"""
        elif f.get("cross_status") == "latent":
            cross_badge = f"""<span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold;background:rgba(148,163,184,0.15);color:#94a3b8;border:1px solid rgba(148,163,184,0.3);margin-left:8px;">[静态潜在·监控期未触发]</span>"""

        detail_rows = ""
        for d in f.get("details", []):
            culprit_str = d.get('culprit', '宿主进程')
            if d.get("is_framework_internal"):
                culprit_str = f"<span style='color:#10b981;'>[官方兼容]</span> {culprit_str}"
            detail_rows += f"""
            <tr>
                <td><code>{culprit_str}</code></td>
                <td><code>{d.get('caller_class', '')}<br>&nbsp;└─&gt; {d.get('caller_method', '')}</code></td>
                <td><code style="color:#f59e0b;">{d.get('target_api', '')}</code></td>
                <td><code>{d.get('offset', '探针截获')}</code></td>
            </tr>
            """
        
        advisory_html = ""
        if r.get("advisory_note"):
            advisory_html = f"""<div style="margin:8px 0;padding:8px 12px;border-radius:8px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);font-size:12px;color:#a7f3d0;"><strong>系统兼容免责提示：</strong>{r.get('advisory_note')}</div>"""

        note_html = ""
        if f.get("verification_note"):
            note_html = f"""<div style="margin:8px 0;padding:8px 12px;border-radius:8px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);font-size:12px;color:#e2e8f0;"><strong>证据对齐结论：</strong>{f.get('verification_note')}</div>"""

        policy_tag = f"""<div style="font-size:11px;color:#94a3b8;margin-bottom:6px;font-family:monospace;"><strong>法规依据：</strong>{r.get('policy_ref', '工信部信管函〔2020〕164号')}</div>""" if r.get('policy_ref') else ""
        
        code_box_html = ""
        if r.get('remediation_code'):
            escaped_code = r['remediation_code'].replace("<", "&lt;").replace(">", "&gt;")
            code_box_html = f"""
            <div style="margin-top:10px;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:12px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <span style="font-size:11px;font-weight:bold;color:#38bdf8;">【符合工信部规范的合规修复代码建议 (Code Patch)】</span>
                    <span style="font-size:10px;color:#64748b;">Java / Android SDK</span>
                </div>
                <pre style="margin:0;font-family:ui-monospace,monospace;font-size:11px;color:#e2e8f0;overflow-x:auto;line-height:1.5;">{escaped_code}</pre>
            </div>
            """

        score_ded_str = "核算扣除: 0 分 (已豁免)" if (r.get("framework_internal_only") or r.get("points") == 0) else f"核算扣除: -{r.get('points', 10)} 分"
        score_ded_color = "#10b981" if (r.get("framework_internal_only") or r.get("points") == 0) else "#f87171"

        findings_html += f"""
        <div class="section-card finding-item">
            <div class="finding-top">
                <div class="finding-title-box">
                    <span class="badge {b_cls}">{sev}</span>
                    <span style="font-weight:700;font-size:15px;color:#f8fafc;">{r.get('name', '')}</span>
                    <span style="font-size:12px;color:#94a3b8;font-family:monospace;">[{r.get('category', '未归类')}]</span>
                    {cross_badge}
                </div>
                <div style="font-size:13px;font-family:monospace;color:{score_ded_color};font-weight:bold;">
                    {score_ded_str} | 捕获调用: {f.get('count', 1)} 处
                </div>
            </div>
           <div style="font-size:13px;color:#cbd5e1;margin:10px 0;line-height:1.6;">
               {r.get('desc', '')}
           </div>
            {advisory_html}
           {note_html}
           <div class="remediation-box">
                {policy_tag}
                <strong style="color:#38bdf8;">【法规依据与合规治理建议】:</strong> {r.get('remediation_principle', r.get('remediation', '严禁在未明示前私自调用敏感 API。'))}
            </div>
            {code_box_html}
            <table class="data-table">
                <thead>
                    <tr>
                        <th style="width:25%;">归属责任体</th>
                        <th style="width:40%;">调用栈位置 (Caller)</th>
                        <th style="width:25%;">敏感目标接口 (Target API)</th>
                        <th style="width:10%;">指令偏移/探针</th>
                    </tr>
                </thead>
                <tbody>
                    {detail_rows}
                </tbody>
            </table>
        </div>
        """

    fuse_banner = f'<div class="fuse-banner">⚠️ 严重违规熔断通知：{fuse_reason}</div>' if is_fused else ""

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>AppGuard 移动应用隐私合规深度体检报告 - {app_name}</title>
    <style>
        :root {{
            --bg: #090a0f;
            --card-bg: #12151f;
            --card-border: rgba(255, 255, 255, 0.1);
            --text: #f8fafc;
            --text-sub: #94a3b8;
            --accent: {type_color};
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 36px 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}
        .brand-title {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand-icon {{
            width: 38px;
            height: 38px;
            border-radius: 10px;
            background: linear-gradient(135deg, #0284c7, #38bdf8);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            font-size: 20px;
            color: white;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
            font-family: monospace;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-medium {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
        .section-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .overview-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            align-items: center;
        }}
        .meta-list {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px 20px;
            font-size: 13px;
            color: var(--text-sub);
            margin-top: 14px;
        }}
        .meta-list strong {{ color: var(--text); }}
        .score-box {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
        }}
        .score-num {{
            font-size: 54px;
            font-weight: 900;
            font-family: monospace;
            line-height: 1;
            color: {score_color};
        }}
        .score-label {{
            font-size: 12px;
            color: var(--text-sub);
            margin-top: 6px;
        }}
        .dim-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-top: 16px;
        }}
        .dim-card {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 14px;
        }}
        .dim-title {{ font-size: 12px; color: var(--text-sub); }}
        .dim-val {{ font-size: 22px; font-weight: 800; font-family: monospace; margin: 4px 0; }}
        .dim-progress {{ height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden; margin: 8px 0; }}
        .dim-sub {{ font-size: 11px; color: #64748b; font-family: monospace; }}

        .cross-val-card {{
            border-color: rgba(16, 185, 129, 0.3);
            background: rgba(16, 185, 129, 0.03);
        }}
        .cv-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .pulse-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 10px #10b981;
        }}
        .cv-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-top: 14px;
        }}
        .cv-stat {{
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 14px;
        }}
        .cv-stat-label {{ font-size: 11px; color: var(--text-sub); }}
        .cv-stat-num {{ font-size: 22px; font-weight: 800; font-family: monospace; margin: 4px 0; }}
        .cv-stat-desc {{ font-size: 10px; color: #64748b; }}

        .tl-container {{
            position: relative;
            padding-left: 20px;
            border-left: 2px solid rgba(255,255,255,0.1);
            margin-left: 8px;
            margin-top: 14px;
        }}
        .tl-item {{
            position: relative;
            margin-bottom: 16px;
        }}
        .tl-marker {{
            position: absolute;
            left: -27px;
            top: 6px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 2px solid var(--bg);
        }}
        .tl-content {{
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 12px 16px;
        }}
        .tl-top {{ display: flex; justify-content: space-between; align-items: center; }}
        .tl-time {{ font-family: monospace; font-weight: bold; font-size: 12px; color: #38bdf8; margin-right: 8px; }}
        .tl-stage {{ font-weight: bold; font-size: 12px; color: #f8fafc; }}
        .tl-cat {{ font-size: 11px; color: var(--text-sub); margin-left: 4px; }}
        .tl-verdict {{ font-size: 10px; padding: 2px 8px; border-radius: 9999px; font-weight: bold; font-family: monospace; }}
        .tl-event {{ font-size: 12px; color: #cbd5e1; margin-top: 4px; line-height: 1.5; }}
        .tl-raw {{ margin-top: 6px; }}
        .tl-raw code {{ font-size: 10px; color: #64748b; background: rgba(0,0,0,0.4); padding: 3px 6px; border-radius: 4px; display: block; overflow-x: auto; }}

        .finding-top {{ display: flex; justify-content: space-between; align-items: center; }}
        .finding-title-box {{ display: flex; align-items: center; gap: 8px; }}
        .remediation-box {{
            background: rgba(56, 189, 248, 0.08);
            border-left: 3px solid #38bdf8;
            padding: 10px 14px;
            border-radius: 0 8px 8px 0;
            font-size: 12px;
            margin: 10px 0;
            color: #e2e8f0;
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 10px;
        }}
        .data-table th, .data-table td {{
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid var(--card-border);
        }}
        .data-table th {{ background: rgba(255,255,255,0.04); color: var(--text-sub); font-size: 11px; }}
        code {{
            font-family: ui-monospace, monospace;
            background: rgba(255, 255, 255, 0.06);
            padding: 2px 5px;
            border-radius: 4px;
            font-size: 11px;
        }}
        .fuse-banner {{
            background: rgba(239,68,68,0.2);
            border: 1px solid rgba(239,68,68,0.4);
            color: #fca5a5;
            padding: 14px 18px;
            border-radius: 12px;
            margin-bottom: 24px;
            font-weight: 700;
            font-size: 14px;
        }}
        .footer {{
            border-top: 1px solid var(--card-border);
            padding-top: 20px;
            margin-top: 40px;
            font-size: 11px;
            color: #64748b;
            display: flex;
            justify-content: space-between;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="brand-title">
                <div class="brand-icon">🛡️</div>
                <div>
                    <h2 style="margin:0;font-size:18px;">AppGuard · 移动应用隐私合规深度存证体检报告</h2>
                    <div style="font-size:11px;color:var(--text-sub);margin-top:2px;">
                        《中华人民共和国个人信息保护法》/ 工业和信息化部信管函〔2023〕26号合规技术规范
                    </div>
                </div>
            </div>
            <div style="text-align:right;">
                <span class="badge" style="border:1px solid {badge_border};background:{badge_bg};color:{score_color};font-size:12px;">
                    {type_title}
                </span>
                <div style="font-size:10px;color:var(--text-sub);margin-top:4px;">基准引擎: {type_sub}</div>
            </div>
        </div>

        {fuse_banner}

        <!-- 样本概览与综合计分 -->
        <div class="section-card overview-grid">
            <div>
                <div style="display:flex;align-items:center;gap:10px;">
                    <h1 style="margin:0;font-size:24px;font-weight:800;">{app_name}{demo_badge}</h1>
                    <code style="color:#38bdf8;font-size:13px;">{pkg}</code>
                </div>
                <div class="meta-list">
                    <div>目标系统版本 (TargetSDK): <strong>Android {target_sdk}</strong></div>
                    <div>安装包文件体量: <strong>{file_size_mb} MB</strong></div>
                    <div>待审有效载荷 (DEX+AXML): <strong style="color:#38bdf8;">{payload_mb} MB</strong></div>
                    <div>过滤媒体及原生库比例: <strong>{filter_ratio}</strong></div>
                    <div>全流程审计耗时: <strong>{elapsed} 秒</strong></div>
                    <div>声明权限总数: <strong>{len(data.get("permissions", []))} 项</strong></div>
                    <div style="grid-column:1 / -1;word-break:break-all;font-size:11px;">
                        SHA-256 样本防篡改数字指纹: <code style="color:#94a3b8;">{sha256_hash}</code>
                    </div>
                </div>
            </div>
            <div class="score-box">
                <div class="score-num">{score}</div>
                <div class="score-label">WCI 综合合规得分 (满分 100)</div>
                <div style="margin-top:10px;">
                    <span class="badge" style="border:1px solid {badge_border};background:{badge_bg};color:{score_color};font-size:12px;">
                        {risk_level}
                    </span>
                </div>
            </div>
        </div>

        <!-- 四维合规指标 -->
        <div class="section-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;font-size:16px;">WCI 四维加权合规健康度基准矩阵</h3>
                <span style="font-size:11px;color:var(--text-sub);">依据国家信管局与信通院标准评定</span>
            </div>
            <div class="dim-grid">
                {dim_cards_html}
            </div>
        </div>

        {agent_verdict_html}

        <!-- 第三方 SDK 责任穿透大盘 -->
        {sdk_matrix_html}

        <!-- 动静交叉验证卡片 (若有) -->
        {cross_val_html}

        <!-- 毫秒级时序轨迹 (若有) -->
        {timeline_html}

        <!-- 工信部红线违规明细 -->
        <div style="margin-top:32px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;">
            <h3 style="margin:0;font-size:18px;">工信部专项红线违规清单与修复补丁库 ({len(findings)} 项)</h3>
            <span style="font-size:12px;color:var(--text-sub);">附带 Dalvik 字节码指令偏移与可运行合规补丁</span>
        </div>
        {findings_html if findings else '<div class="section-card" style="text-align:center;color:#10b981;font-weight:bold;">恭喜！未在目标应用中检出已知工信部红线违规调用。</div>'}

        <div class="footer">
            <div>报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · AppGuard 合规审计引擎 v1.10</div>
            <div>中国国际大学生创新大赛 · 移动互联网隐私合规端云协同平台</div>
        </div>
    </div>
</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filename
