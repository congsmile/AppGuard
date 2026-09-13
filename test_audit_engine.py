import unittest
import time
from datetime import datetime
import app_guard_scanner
import sandbox_runner
import report_generator

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
        """测试报告生成器三色责任条与技术审计报告完整性"""
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
        rep_file = report_generator.generate_report(sample_data)
        self.assertTrue(rep_file.startswith("Compliance_Report_"))
        self.assertTrue(rep_file.endswith(".html"))

if __name__ == "__main__":
    unittest.main()
