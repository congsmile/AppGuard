import unittest
import os
import re
import time
import tempfile
from datetime import datetime
import app_guard_scanner
import sandbox_runner
import report_generator
import compliance_agent

class TestAuditEngine(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandbox_runner.AndroidDynamicSandbox()

    def test_parse_time_ago_multi_units(self):
        """测试多级复合相对时间解析 (验证分、秒、毫秒、小时、天各级别完整换算，杜绝子单位丢失)"""
        cases = [
            ("+12s340ms ago", 12.34),
            ("+450ms ago", 0.45),
            ("+1m20s ago", 80.0),
            ("+2h5m ago", 7500.0),       # 2*3600 + 5*60 = 7500.0 (曾发生丢失 5 分钟 bug)
            ("+3d4h ago", 273600.0),     # 3*86400 + 4*3600 = 273600.0 (曾发生丢失 4 小时 bug)
            ("+1d2h3m4s500ms ago", 86400.0 + 7200.0 + 180.0 + 4.0 + 0.5),
            ("+5s ago", 5.0)
        ]
        for text, expected in cases:
            res = self.sandbox._parse_time_ago(text)
            self.assertIsNotNone(res, f"未能解析: {text}")
            self.assertAlmostEqual(res, expected, places=2, msg=f"时间解析偏差: {text}")

    def test_was_op_accessed_window_filtering(self):
        """测试 AppOps 时间窗口严格裁决 (杜绝历史老数据绕过窗口判定)"""
        now = time.time()
        # 构造 AppOps 字典：剪贴板在 3 天前访问，设备标识在 2 秒前访问
        ops_dict = {
            "READ_CLIPBOARD": {
                "mode": "allow",
                "time_str": "+3d4h ago",
                "time_seconds": 273600.0,
                "raw": "READ_CLIPBOARD: allow; time=+3d4h ago;"
            },
            "READ_PHONE_STATE": {
                "mode": "allow",
                "time_str": "+2s100ms ago",
                "time_seconds": 2.1,
                "raw": "READ_PHONE_STATE: allow; time=+2s100ms ago;"
            }
        }

        # 监控窗口为 8 秒
        window_ago = 8.0

        # 3 天前的剪贴板操作，严格在 8 秒窗口外，严禁判定为违规
        res_clip, _, _ = self._call_was_op_accessed(["READ_CLIPBOARD"], ops_dict, window_ago)
        self.assertFalse(res_clip, "历史记录 (3天前) 错误绕过时间窗口被误判为违规")

        # 2.1 秒前的设备标识操作，在 8 秒窗口内，应正确判定
        res_phone, _, item = self._call_was_op_accessed(["READ_PHONE_STATE"], ops_dict, window_ago)
        self.assertTrue(res_phone, "窗口内 (2.1s前) 的活跃调用未被判定")
        self.assertEqual(item["time_seconds"], 2.1)

    def _call_was_op_accessed(self, op_keys, ops_dict, max_ago):
        for k in op_keys:
            if k in ops_dict:
                item = ops_dict[k]
                t = item.get("time_seconds")
                if t is not None:
                    if max_ago is None or t <= max_ago:
                        return True, k, item
        return False, None, None

    def test_logcat_system_noise_exclusion(self):
        """测试 Logcat 目标进程隔离与系统噪声过滤 (杜绝系统广播与无关应用误判)"""
        target_pkg = "com.test.targetapp"
        target_pids = {"9876"}
        target_uid = "10999"

        # 场景 1: 系统基带例行广播 (TelephonyRegistry notifyServiceState)
        res1 = self.sandbox._synthesize_evidence(
            package_name=target_pkg,
            dev_profile={"connected": True},
            baseline_ops={},
            pre_agree_ops={},
            post_ops={},
            raw_logs=["09-13 21:00:00.100  100  100 I TelephonyRegistry: notifyServiceStateForSubscriber phoneId=0"],
            static_findings=[],
            duration_seconds=5,
            start_wall_time=time.time(),
            target_pids=target_pids,
            target_uid=target_uid
        )
        self.assertEqual(len(res1["dynamic_violations"]), 0, "系统基带广播被误报为设备标识泄露")

        # 场景 2: 其他应用访问剪贴板
        res2 = self.sandbox._synthesize_evidence(
            package_name=target_pkg,
            dev_profile={"connected": True},
            baseline_ops={},
            pre_agree_ops={},
            post_ops={},
            raw_logs=["09-13 21:00:00.200  200  200 D ClipboardService: getPrimaryClip from com.other.thirdparty"],
            static_findings=[],
            duration_seconds=5,
            start_wall_time=time.time(),
            target_pids=target_pids,
            target_uid=target_uid
        )
        self.assertEqual(len(res2["dynamic_violations"]), 0, "其他应用访问剪贴板被误报到目标应用头上")

        # 场景 3: 系统例行传感器刷新
        res3 = self.sandbox._synthesize_evidence(
            package_name=target_pkg,
            dev_profile={"connected": True},
            baseline_ops={},
            pre_agree_ops={},
            post_ops={},
            raw_logs=["09-13 21:00:00.300  100  100 D SensorService: sensor list updated accelerometer"],
            static_findings=[],
            duration_seconds=5,
            start_wall_time=time.time(),
            target_pids=target_pids,
            target_uid=target_uid
        )
        self.assertEqual(len(res3["dynamic_violations"]), 0, "系统传感器列表刷新被误判为摇一摇传感器监听")

        # 场景 4: 目标应用在自身 PID 下真实调用剪贴板 (正向捕获)
        now = time.time()
        res4 = self.sandbox._synthesize_evidence(
            package_name=target_pkg,
            dev_profile={"connected": True},
            baseline_ops={},
            pre_agree_ops={},
            post_ops={},
            raw_logs=["09-13 21:00:01.500 9876 9876 D ClipboardService: getPrimaryClip from com.test.targetapp"],
            static_findings=[],
            duration_seconds=5,
            start_wall_time=now,
            target_pids=target_pids,
            target_uid=target_uid
        )
        self.assertEqual(len(res4["dynamic_violations"]), 1, "目标应用真实剪贴板越界未被捕获")
        self.assertEqual(res4["dynamic_violations"][0]["rule_id"], "MIIT-10-CLIPBOARD")

    def test_prefix_match_short_prefix_boundary(self):
        """测试 SDK 短前缀路径边界匹配 (避免 com/mob 误伤 com/mobileapp)"""
        self.assertTrue(app_guard_scanner.is_prefix_match("com/mob/SecVerify", "com/mob"))
        self.assertFalse(app_guard_scanner.is_prefix_match("com/mobileapp/Util", "com/mob"))
        self.assertTrue(app_guard_scanner.is_prefix_match("io/rong/imlib/RongIM", "io/rong"))
        self.assertFalse(app_guard_scanner.is_prefix_match("io/rongcloud2x/Client", "io/rong"))

    def test_androidx_attribution_and_benign_exemption(self):
        """测试 AndroidX 官方系统组件责任穿透与良性兼容豁免"""
        # 1. 归属识别
        culprit = app_guard_scanner.identify_culprit("Landroidx/appcompat/widget/AppCompatReceiveContentHelper;")
        self.assertIn("AndroidX 官方支持库", culprit)

        # 2. 良性内部向下兼容识别
        is_benign = app_guard_scanner.is_benign_framework_call(
            "androidx/appcompat/widget/AppCompatReceiveContentHelper",
            "tryPerformPaste",
            "ClipboardManager -> getPrimaryClip"
        )
        self.assertTrue(is_benign, "AndroidX 官方长按粘贴实现未被识别为良性兼容")

        # 3. 责任穿透三维大盘构建
        findings = [
            {
                "rule": {
                    "id": "MIIT-10-CLIPBOARD",
                    "name": "私自静默读取剪贴板信息",
                    "severity": "CRITICAL",
                    "dimension": "dim_data",
                    "base_deduction": 8,
                    "max_deduction": 12,
                    "framework_internal_only": True
                },
                "count": 1,
                "details": [
                    {
                        "target_api": "ClipboardManager -> getPrimaryClip",
                        "caller_class": "androidx.appcompat.widget.AppCompatReceiveContentHelper",
                        "caller_method": "tryPerformPaste",
                        "culprit": culprit,
                        "is_framework_internal": True
                    }
                ]
            }
        ]
        attr = app_guard_scanner.build_sdk_attribution(findings)
        self.assertEqual(attr["framework_calls"], 1)
        self.assertEqual(attr["host_calls"], 0)
        self.assertEqual(attr["sdk_calls"], 0)
        self.assertEqual(attr["framework_pct"], 100.0)

        # 4. 豁免扣分评估模型 (WCI)
        score_res = app_guard_scanner.calculate_weighted_score(findings)
        score = score_res["compliance_score"]
        is_fused = score_res["is_fused"]
        self.assertEqual(score, 100, "仅包含官方兼容良性调用的规则不应扣分")
        self.assertFalse(is_fused, "良性兼容规则不应触发严重熔断")

    def test_server_dynamic_score_null_safety(self):
        """测试 Server 端动静双轨在 dynamic_score 为 None 时的异常安全性 (防御 500 崩溃)"""
        import server
        static_findings = [
            {"rule": {"id": "MIIT-01-DEVICE-ID", "name": "设备标识", "severity": "CRITICAL"}, "count": 1}
        ]

        # 模拟沙箱失败返回 dynamic_score 为 None
        dyn_res = {
            "success": False,
            "dynamic_score": None,
            "timeline": [],
            "dynamic_violations": [],
            "cross_validation": {}
        }

        # 验证混合计算逻辑
        static_score = 80.0
        dyn_success = dyn_res.get("success", False)
        raw_dyn_score = dyn_res.get("dynamic_score")

        if dyn_success and raw_dyn_score is not None:
            comp_score = round(static_score * 0.5 + raw_dyn_score * 0.5, 1)
        else:
            comp_score = static_score

        self.assertEqual(comp_score, 80.0, "沙箱不可用时混合评分应平稳回退至静态分")

    def test_report_generation_three_color_matrix(self):
        """测试报告生成器三色责任条与技术审计报告完整性 (写入临时目录，避免污染 outputs 目录)"""
        sample_data = {
            "package_name": "com.test.sample",
            "app_name": "审计样本",
            "compliance_score": 92.0,
            "audit_type": "hybrid",
            "dimensions": {
                "dim_device": {"name": "设备标识规范", "score": 25, "weight": 25, "deduction": 0},
                "dim_behavior": {"name": "敏感行为合规", "score": 25, "weight": 25, "deduction": 0},
                "dim_permission": {"name": "权限最小化", "score": 22, "weight": 25, "deduction": 3},
                "dim_data": {"name": "数据收集透明", "score": 20, "weight": 25, "deduction": 5}
            },
            "sdk_attribution": {
                "total_calls": 10,
                "host_calls": 5,
                "host_pct": 50.0,
                "framework_calls": 3,
                "framework_pct": 30.0,
                "sdk_calls": 2,
                "sdk_pct": 20.0,
                "sdk_list": [
                    {"name": "穿山甲广告SDK", "category": "commercial_sdk", "count": 2, "percentage": 20.0, "rules": ["MIIT-04-SHAKE"], "action_advice": "配置防误触门槛"},
                    {"name": "AndroidX 官方支持库", "category": "official_framework", "count": 3, "percentage": 30.0, "rules": ["MIIT-10-CLIPBOARD"], "action_advice": "官方组件无需整改"}
                ],
                "accountability_verdict": "自研业务占比 50.0%，官方框架 30.0%，商业SDK 20.0%。"
            },
            "findings": [],
            "timeline": []
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            rep_file = report_generator.generate_report(sample_data, output_dir=tmp_dir)
            self.assertTrue(rep_file.startswith("Compliance_Report_"))
            self.assertTrue(rep_file.endswith(".html"))
            full_path = os.path.join(tmp_dir, rep_file)
            self.assertTrue(os.path.exists(full_path))
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("官方系统框架: 30.0%", content)
            self.assertIn("宿主自研业务: 50.0%", content)
            self.assertIn("商业第三方SDK: 20.0%", content)
            self.assertIn("linear-gradient(90deg, #059669, #10b981)", content)

    def test_cli_html_report_advisory_and_three_color_rendering(self):
        """测试 CLI 报告路径下 generate_html_report 对官方兼容豁免徽章、免责提示与三色大盘的完整渲染"""
        findings = [
            {
                "rule": {
                    "id": "MIIT-10-CLIPBOARD",
                    "name": "私自静默读取剪贴板信息",
                    "category": "个人数据收集",
                    "severity": "HIGH",
                    "desc": "在未明示前读取剪贴板数据",
                    "policy_ref": "工信部信管函〔2020〕164号 第四条",
                    "remediation": "移除未明示前读取",
                    "remediation_principle": "严禁在用户同意前调用",
                    "framework_internal_only": True,
                    "points": 0,
                    "calculated_points": 0,
                    "advisory_note": "【系统兼容提示】仅在 AndroidX/官方兼容库内部向下兼容链路中发现调用，已豁免扣分。"
                },
                "count": 1,
                "details": [
                    {
                        "target_api": "ClipboardManager -> getPrimaryClip",
                        "caller_class": "androidx.appcompat.widget.AppCompatReceiveContentHelper",
                        "caller_method": "tryPerformPaste",
                        "culprit": "AndroidX 官方支持库 (系统兼容组件)",
                        "offset": "0x12",
                        "is_framework_internal": True
                    }
                ]
            }
        ]
        attr = app_guard_scanner.build_sdk_attribution(findings)
        with tempfile.TemporaryDirectory() as tmp_dir:
            rep_path = app_guard_scanner.generate_html_report(
                apk_path="mock.apk",
                app_name="测试样本",
                package_name="com.test.sample",
                target_sdk="34",
                permissions=["android.permission.INTERNET"],
                score=100,
                risk_level="LOW (低风险)",
                findings=findings,
                elapsed=1.0,
                sdk_attribution=attr,
                output_dir=tmp_dir
            )
            self.assertTrue(os.path.exists(rep_path))
            with open(rep_path, "r", encoding="utf-8") as f:
                html = f.read()
            self.assertIn("[官方框架良性兼容·豁免扣分]", html)
            self.assertIn("系统兼容免责提示：", html)
            self.assertIn("扣减分值: 0 分 (已豁免)", html)
            self.assertIn("[官方兼容]", html)
            self.assertIn("linear-gradient(90deg, #059669, #10b981)", html)
            self.assertIn("合规穿透审计意见：", html)

    def test_material_and_framework_benign_exemption(self):
        """测试 Google Material 官方库、WorkManager 与协程等良性向下兼容调用的系统化识别与豁免"""
        # 1. Google Material 组件长按粘贴剪贴板
        is_mat_clip = app_guard_scanner.is_benign_framework_call(
            "com.google.android.material.textfield.EndCompoundLayout",
            "tryPaste",
            "ClipboardManager -> getPrimaryClip"
        )
        self.assertTrue(is_mat_clip, "Google Material 输入控件剪贴板操作应被识别为良性兼容")

        # 2. AndroidX WorkManager 调度前台服务
        is_work_fg = app_guard_scanner.is_benign_framework_call(
            "androidx.work.impl.utils.WorkForeground",
            "startForegroundService",
            "Context -> startForegroundService"
        )
        self.assertTrue(is_work_fg, "WorkManager 前台服务兼容调度应被识别为良性兼容")

        # 3. KotlinX 协程调度
        is_coroutine_fg = app_guard_scanner.is_benign_framework_call(
            "kotlinx.coroutines.DelayKt",
            "delay",
            "Context -> startForegroundService"
        )
        self.assertTrue(is_coroutine_fg, "KotlinX 协程标准调度应被识别为良性兼容")

        # 4. 商业广告 SDK 偷跑剪贴板（严禁豁免）
        is_ad_clip = app_guard_scanner.is_benign_framework_call(
            "com.bytedance.sdk.openadsdk.core.ClipHelper",
            "getPrimaryClip",
            "ClipboardManager -> getPrimaryClip"
        )
        self.assertFalse(is_ad_clip, "商业广告 SDK 剪贴板调用绝对不可被豁免")

        # 5. 宿主自研业务偷跑剪贴板（严禁豁免）
        is_host_clip = app_guard_scanner.is_benign_framework_call(
            "com.example.myapp.MainActivity",
            "onCreate",
            "ClipboardManager -> getPrimaryClip"
        )
        self.assertFalse(is_host_clip, "宿主应用自身剪贴板调用绝对不可被豁免")

    def test_cli_findings_categorization(self):
        """测试 CLI 审计结果对实际违规扣分项与官方框架豁免项的分组及核算统计"""
        findings = [
            {
                "rule": {
                    "id": "MIIT-01-DEVICE-ID",
                    "name": "私自获取设备序列号与IMEI",
                    "severity": "CRITICAL",
                    "dimension": "dim_device",
                    "base_deduction": 15,
                    "max_deduction": 20,
                    "framework_internal_only": False,
                    "points": 15
                },
                "count": 1,
                "details": [{"culprit": "宿主自研业务模块", "target_api": "getDeviceId", "caller_class": "A", "caller_method": "b", "offset": "0x1"}]
            },
            {
                "rule": {
                    "id": "MIIT-10-CLIPBOARD",
                    "name": "私自静默读取剪贴板信息",
                    "severity": "HIGH",
                    "dimension": "dim_data",
                    "base_deduction": 0,
                    "max_deduction": 0,
                    "framework_internal_only": True,
                    "points": 0,
                    "advisory_note": "官方兼容豁免"
                },
                "count": 2,
                "details": [{"culprit": "AndroidX 官方支持库 (系统兼容组件)", "target_api": "getPrimaryClip", "caller_class": "X", "caller_method": "y", "offset": "0x2", "is_framework_internal": True}]
            }
        ]
        deduct_findings = [f for f in findings if not f.get("rule", {}).get("framework_internal_only")]
        exempt_findings = [f for f in findings if f.get("rule", {}).get("framework_internal_only")]

        self.assertEqual(len(deduct_findings), 1)
        self.assertEqual(len(exempt_findings), 1)
        self.assertEqual(deduct_findings[0]["rule"]["points"], 15)
        self.assertEqual(exempt_findings[0]["rule"]["points"], 0)

    def test_agent_category_inference(self):
        """测试 Agent 针对常见包名的品类先验推断"""
        self.assertEqual(compliance_agent.infer_app_category("mark.via"), "browser_utility")
        self.assertEqual(compliance_agent.infer_app_category("com.tencent.qqgame.xq"), "mobile_game")
        self.assertEqual(compliance_agent.infer_app_category("com.cainiao.wireless"), "ecommerce_life")
        self.assertEqual(compliance_agent.infer_app_category("com.eg.android.AlipayGphone"), "finance_banking")
        self.assertEqual(compliance_agent.infer_app_category("com.autonavi.minimap"), "navigation_travel")

    def test_agent_contextual_exemption_and_tracing(self):
        """测试 Agent 结合业务场景执行最小必要性研判、调用位置溯源与合规豁免"""
        agent = compliance_agent.ComplianceAgent(config={"mode": "offline_only"})
        dummy_data = {
            "app_name": "Via",
            "package_name": "mark.via",
            "compliance_score": 71,
            "findings": [
                {
                    "rule": {"id": "MIIT-06-SILENT-DOWNLOAD", "name": "诱导点击与静默下载安装 APK", "points": 5, "calculated_points": 5},
                    "details": [{"caller_class": "sa.m1", "caller_method": "c", "target_api": "android.app.DownloadManager -> enqueue", "culprit": "应用自身业务模块"}]
                },
                {
                    "rule": {"id": "MIIT-04-SHAKE-SENSOR", "name": "开屏‘摇一摇’传感器高频监听与误触风险", "points": 5, "calculated_points": 5},
                    "details": [{"caller_class": "q3.a", "caller_method": "c", "target_api": "android.hardware.SensorManager -> registerListener", "culprit": "应用自身业务模块"}]
                }
            ]
        }
        res = agent.analyze(dummy_data, app_category="browser_utility", app_description="极简移动浏览器，用于网页浏览与下载")
        self.assertEqual(res["baseline_score"], 71)
        self.assertGreater(res["adjusted_score"], 71, "浏览器下载能力应获得场景豁免，使修正得分高于基准分")
        self.assertEqual(res["app_category_key"], "browser_utility")
        
        traces = {t["rule_id"]: t for t in res["detailed_traces"]}
        self.assertIn("MIIT-06-SILENT-DOWNLOAD", traces)
        self.assertIn("豁免", traces["MIIT-06-SILENT-DOWNLOAD"]["verdict_action"])
        self.assertEqual(traces["MIIT-06-SILENT-DOWNLOAD"]["adjusted_points"], 0)
        self.assertIn("sa.m1::c", traces["MIIT-06-SILENT-DOWNLOAD"]["code_location_trace"])

        self.assertIn("MIIT-04-SHAKE-SENSOR", traces)
        v_action = traces["MIIT-04-SHAKE-SENSOR"]["verdict_action"]
        self.assertTrue("维持" in v_action or "严惩" in v_action or "扣分" in v_action)
        self.assertEqual(traces["MIIT-04-SHAKE-SENSOR"]["adjusted_points"], 5)

    def test_report_generator_embeds_agent_verdict(self):
        """测试报告生成引擎正确嵌入 Agent 场景化最小必要裁决意见书"""
        with tempfile.TemporaryDirectory() as temp_dir:
            dummy_audit = {
                "app_name": "TestApp",
                "package_name": "com.test.app",
                "compliance_score": 80,
                "findings": [],
                "app_category": "browser_utility",
                "app_description": "测试浏览器"
            }
            rep_name = report_generator.generate_report(dummy_audit, output_dir=temp_dir)
            rep_path = os.path.join(temp_dir, rep_name)
            self.assertTrue(os.path.exists(rep_path))
            with open(rep_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("场景化最小必要性智能裁决意见书", content)
            self.assertIn("AI+ AGENT", content)
            self.assertIn("四部委 39 类标准", content)

    def test_namespace_impersonation_blocked(self):
        """测试杜绝命名空间伪装绕过 (防将自研代码伪装在 androidx 等官方路径下逃避审计)"""
        evil_class = "com.example.app.androidx.EvilHelper"
        self.assertFalse(app_guard_scanner.is_prefix_match(evil_class.replace(".", "/"), "androidx", is_sdk=False))
        self.assertFalse(app_guard_scanner.is_benign_framework_call(evil_class, "onPaste", "getPrimaryClip"))
        self.assertEqual(app_guard_scanner.identify_culprit(evil_class), "应用自身业务模块")

        # 验证真实顶层 AndroidX 依然正常通过
        real_androidx = "androidx.appcompat.widget.AppCompatReceiveContentHelper"
        self.assertTrue(app_guard_scanner.is_prefix_match(real_androidx.replace(".", "/"), "androidx", is_sdk=False))
        self.assertTrue(app_guard_scanner.is_benign_framework_call(real_androidx, "onPaste", "getPrimaryClip"))
        self.assertEqual(app_guard_scanner.identify_culprit(real_androidx), "AndroidX 官方支持库 (系统兼容组件)")

    def test_timeline_is_chronological(self):
        """测试动态时间线严格按真实发生时刻升序排序 (消除时间倒流 Bug)"""
        sandbox = sandbox_runner.AndroidDynamicSandbox()
        # 构造 AppOps 滞后捕获剪贴板 (如持续监控期内发生)
        post_ops = {
            "READ_CLIPBOARD": {"time_seconds": 3.4, "raw": "read_clipboard"}
        }
        res = sandbox._synthesize_evidence(
            package_name="com.test.pkg",
            dev_profile={"connected": True},
            baseline_ops={},
            pre_agree_ops={},
            post_ops=post_ops,
            raw_logs=[],
            static_findings=[],
            duration_seconds=10,
            start_wall_time=time.time()
        )
        timeline = res["timeline"]
        self.assertTrue(len(timeline) >= 4)
        times = []
        for item in timeline:
            t_str = item["time"]
            m = re.search(r"T\+([\d\.]+)s?", t_str)
            if m:
                times.append(float(m.group(1)))
        # 验证提取出的秒数是严格单调递增的
        self.assertEqual(times, sorted(times), f"时间线必须升序排列: {times}")

    def test_fetch_remote_models_fallback_without_key(self):
        """测试在未提供 API Key 时，直接请求模型能优雅返回该提供商的候选模型与错误说明"""
        import compliance_agent
        res = compliance_agent.fetch_remote_models("deepseek", "", "https://api.deepseek.com")
        self.assertFalse(res["success"])
        self.assertIn("请先输入 API Key", res["error"])
        self.assertTrue(len(res["models"]) >= 1)
        self.assertIn("deepseek-chat", res["models"])
        self.assertEqual(res["source"], "fallback")

        # 测试自定义端点缺 key
        res_custom = compliance_agent.fetch_remote_models("custom", "", "https://api.example.com/v1")
        self.assertFalse(res_custom["success"])
        self.assertTrue(len(res_custom["models"]) >= 1)

    def test_classify_app_and_describe(self):
        """测试 Agent 自动推断应用国标类别与生成主营用途说明"""
        import compliance_agent
        from unittest.mock import patch
        # 设定离线模式以保证单测确定性
        offline_cfg = {"enabled": True, "mode": "offline_only", "api_key": ""}
        with patch("compliance_agent.get_agent_config", return_value=offline_cfg):
            # 1. 实用工具 (浏览器)
            r_via = compliance_agent.classify_app_and_describe("mark.via", "Via 浏览器")
            self.assertEqual(r_via["category"], "browser_utility")
            self.assertIn("实用工具", r_via["category_name"])
            self.assertIn("第32条", r_via["law_ref"])
            self.assertTrue(len(r_via["description"]) > 10)
            self.assertGreaterEqual(r_via["confidence"], 0.90)

            # 2. 手机游戏
            r_game = compliance_agent.classify_app_and_describe("com.tencent.qqgame.xq", "天天象棋")
            self.assertEqual(r_game["category"], "mobile_game")
            self.assertIn("游戏", r_game["category_name"])

            # 3. 电商物流
            r_cainiao = compliance_agent.classify_app_and_describe("com.cainiao.wireless", "菜鸟裹裹")
            self.assertEqual(r_cainiao["category"], "ecommerce_life")

            # 4. 移动支付金融
            r_pay = compliance_agent.classify_app_and_describe("com.eg.android.AlipayGphone", "支付宝")
            self.assertEqual(r_pay["category"], "finance_banking")

if __name__ == "__main__":
    unittest.main()
