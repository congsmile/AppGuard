import os
import sys
import json
import time
import math
from datetime import datetime

try:
    from loguru import logger
    logger.disable("androguard")
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("[!] Error: androguard is not installed in current environment.")
    print("[!] Please run with: work/venv/bin/python3 app_guard_scanner.py <apk_path>")
    sys.exit(1)

# ======================================================================
# 工信部与个人信息保护法合规规则库 (MIIT Compliance Knowledge Base)
# 依据：《中华人民共和国个人信息保护法》、工信部信管函〔2020〕164号、工信部信管函〔2023〕26号、
#       GB/T 35273-2020《个人信息安全规范》、信通院 T/TAF 077.1-2022 规范
# 四维加权分级评估模型 (4-Tier Weighted Compliance Index, WCI)
# ======================================================================
DIMENSION_METADATA = {
    "dim_device": {
        "id": "dim_device",
        "name": "设备硬件指纹防护",
        "weight": 25,
        "icon": "fa-microchip",
        "desc": "管控 IMEI、MEID、MAC、SIM 手机号等不可逆硬件设备标识跨应用强追踪"
    },
    "dim_behavior": {
        "id": "dim_behavior",
        "name": "交互规范与传感器防护",
        "weight": 25,
        "icon": "fa-person-walking-dashed-line-arrow-right",
        "desc": "治理开屏摇一摇高频误触乱跳转、静默后台下发 APK、无感知麦克风录音偷窥"
    },
    "dim_permission": {
        "id": "dim_permission",
        "name": "权限边界与生命周期合规",
        "weight": 25,
        "icon": "fa-shield-halved",
        "desc": "严禁超范围全盘遍历已安装应用、后台高频轮询 GPS 定位、全家桶自启链式唤醒"
    },
    "dim_data": {
        "id": "dim_data",
        "name": "私密数据与防逃逸合规",
        "weight": 25,
        "icon": "fa-lock",
        "desc": "防范冷启动私自读取剪贴板淘口令、逃逸分区存储扫描相册、动态下发 Dex 逃避审查"
    }
}

MIIT_RULES = [
    # ----------------------------------------------------
    # 维度一：设备硬件指纹防护 (25分)
    # ----------------------------------------------------
    {
        "id": "MIIT-01-DEVICE-ID",
        "dimension": "dim_device",
        "name": "违规收集设备唯一标识符",
        "category": "设备信息",
        "severity": "CRITICAL",
        "base_deduction": 8,
        "max_deduction": 12,
        "desc": "在用户未明示同意《隐私政策》前或无合理业务场景下获取 IMEI、MEID、序列号等不可重置硬件唯一标识",
        "policy_ref": "《个人信息保护法》第十三/十七条 · 工信部信管函〔2020〕164号 · 工信部信管函〔2023〕26号 · MSA《移动智能终端补充设备标识规范》",
        "remediation_principle": "【延迟合闸与匿名化替代】未获得用户勾选《隐私政策》同意前，严格拦截底层 TelephonyManager 调用并返回空串；Android 10+ 废弃 IMEI/MEID，全面迁移至中国信通院 MSA 统一匿名设备标识符 (OAID)。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-01: OAID 匿名替代与隐私合闸代理
public class DeviceIdComplianceHelper {
    private static volatile String sOaid = null;

    public static String getSafeDeviceId(Context context) {
        // 1. 核心合闸校验：未签署隐私协议前严禁触发底层敏感硬件调用
        if (!PrivacyConsentManager.isAgreed(context)) {
            Log.w("AppGuard-AI", "[合规阻断] 用户未明示同意隐私协议，拦截设备硬件标识读取");
            return ""; 
        }
        // 2. Android 10+ 废弃 TelephonyManager.getDeviceId()，切换至 MSA OAID
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (sOaid != null) return sOaid;
            MsaSdkHelper.getOaid(context, oaid -> sOaid = oaid);
            return sOaid != null ? sOaid : "";
        }
        // 3. 低版本非敏感场景使用应用级随机 UUID 替代
        return InstallationIdHelper.getOrCreateInstallUuid(context);
    }
}""",
        "signatures": [
            {"class": "Landroid/telephony/TelephonyManager;", "method": "getDeviceId"},
            {"class": "Landroid/telephony/TelephonyManager;", "method": "getImei"},
            {"class": "Landroid/telephony/TelephonyManager;", "method": "getMeid"},
            {"class": "Landroid/telephony/TelephonyManager;", "method": "getSubscriberId"},
            {"class": "Landroid/telephony/TelephonyManager;", "method": "getSimSerialNumber"},
            {"class": "Landroid/os/Build;", "method": "getSerial"},
        ],
        "remediation": "将获取设备 ID 延后至用户点击《隐私政策》同意按钮之后；Android 10+ 强制使用信通院 MSA OAID 匿名设备标识。"
    },
    {
        "id": "MIIT-02-MAC-NETWORK",
        "dimension": "dim_device",
        "name": "违规收集网络物理地址 (MAC/BSSID)",
        "category": "网络信息",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "未经明示授权读取 WiFi MAC 地址、路由器 BSSID，涉嫌用于室内微定位与跨应用硬指纹追踪",
        "policy_ref": "《个人信息保护法》第十三条 · 工信部信管函〔2020〕164号第一项“私自收集个人信息” · GB/T 35273-2020 附录A",
        "remediation_principle": "【最小必要与非敏感网络状态感知】移除初始化阶段扫描 WiFi MAC/BSSID 逻辑；网络状态监听统一接入 ConnectivityManager，严禁提取路由器物理地址。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-02: 非敏感网络连通性状态感知 (规避 MAC/BSSID 抓取)
public class NetworkStateComplianceHelper {
    public static boolean isNetworkConnected(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            return caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
        } else {
            NetworkInfo info = cm.getActiveNetworkInfo();
            return info != null && info.isConnected();
        }
    }
}""",
        "signatures": [
            {"class": "Landroid/net/wifi/WifiInfo;", "method": "getMacAddress"},
            {"class": "Landroid/net/wifi/WifiInfo;", "method": "getBSSID"},
            {"class": "Ljava/net/NetworkInterface;", "method": "getHardwareAddress"}
        ],
        "remediation": "禁止在初始化阶段扫描 WiFi 物理地址；网络连通性检测统一使用 ConnectivityManager 替代。"
    },
    {
        "id": "MIIT-03-PHONE-NUMBER",
        "dimension": "dim_device",
        "name": "私自获取本机号码与通讯标识",
        "category": "设备信息",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "未经用户单独同意，调用系统底层接口私自读取 SIM 卡本机手机号码",
        "policy_ref": "《个人信息保护法》第二十八/二十九条（敏感个人信息需取得单独同意） · 工信部信管函〔2021〕158号",
        "remediation_principle": "【显式授权与合规免密网关】停用底层 TelephonyManager.getLine1Number()；手机号属敏感个人信息，必须集成运营商合规免密网关 SDK 并展示授权弹窗。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-03: 运营商网关合规一键登录 (废弃底层 getLine1Number 私自抓取)
public class AuthComplianceHelper {
    public static void requestCarrierOneKeyLogin(Activity activity, AuthCallback callback) {
        // 1. 弹出显式授权确认窗口（告知运营商协议与脱敏号码）
        CarrierAuthDialog.show(activity, () -> {
            // 2. 调用运营商合规 SDK 网关置换 Token，服务端安全置换手机号
            QuickLoginSDK.getInstance().getLoginToken(activity, 3000, new TokenListener() {
                @Override
                public void onSuccess(String token) {
                    callback.onAuthenticated(token); // 服务端验签取号，端侧不接触明文号码
                }
                @Override
                public void onFailure(int code, String msg) {
                    callback.fallbackToSmsCode(); // 失败优雅降级为短信验证码
                }
            });
        });
    }
}""",
        "signatures": [
            {"class": "Landroid/telephony/TelephonyManager;", "method": "getLine1Number"}
        ],
        "remediation": "禁止直接索取底层手机号，应接入三大运营商认证的合规一键免密登录 SDK（必须伴随显式授权确认）。"
    },

    # ----------------------------------------------------
    # 维度二：交互规范与传感器防护 (25分)
    # ----------------------------------------------------
    {
        "id": "MIIT-04-SHAKE-SENSOR",
        "dimension": "dim_behavior",
        "name": "开屏‘摇一摇’传感器高频监听与误触风险",
        "category": "传感器行为",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "高频注册加速度计/陀螺仪传感器，违反工信部开屏转动角度必须大于35度、持续不低于3秒的技术规范",
        "policy_ref": "工信部信管函〔2023〕26号第十条 · 电信终端产业协会 T/TAF 077.1-2022 / TAF-T-004-2022《摇一摇防误触最新规范》",
        "remediation_principle": "【TAF-2022 国标三重滤波阻尼】开屏广告摇一摇严禁超灵敏触发。必须严格遵循：加速度≥15m/s²、旋转角度≥35°、晃动持续时间≥3.0秒，并提供常驻显著的“跳过/关闭”按键。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-04: TAF-077-2022 标准防误触‘摇一摇’传感器代理
public class TafCompliantShakeDetector implements SensorEventListener {
    private static final float MIN_ACC_THRESHOLD = 15.0f; // TAF规范: >= 15 m/s²
    private static final float MIN_ROT_DEG = 35.0f;       // TAF规范: >= 35°
    private static final long MIN_DURATION_MS = 3000L;    // TAF规范: 持续>= 3.0s
    private long mShakeStartTime = 0;

    @Override
    public void onSensorChanged(SensorEvent event) {
        if (event.sensor.getType() == Sensor.TYPE_ACCELEROMETER) {
            float gX = event.values[0], gY = event.values[1], gZ = event.values[2];
            double totalAcc = Math.sqrt(gX * gX + gY * gY + gZ * gZ) - 9.8;
            if (totalAcc >= MIN_ACC_THRESHOLD) {
                if (mShakeStartTime == 0) mShakeStartTime = System.currentTimeMillis();
                long elapsed = System.currentTimeMillis() - mShakeStartTime;
                if (elapsed >= MIN_DURATION_MS) {
                    triggerAdJump(); // 唯有满足三重国标阈值方可触发交互
                    mShakeStartTime = 0;
                }
            } else {
                mShakeStartTime = 0; // 不满足阈值立即重置，杜绝行车颠簸误触
            }
        }
    }
}""",
        "signatures": [
            {"class": "Landroid/hardware/SensorManager;", "method": "registerListener"}
        ],
        "remediation": "接入合规传感器代理类（CompliantSensorProxy），对晃动加速度及旋转角度设置硬件级 35 度与 15m/s² 阈值滤波，过滤轻微晃动误触。"
    },
    {
        "id": "MIIT-05-SILENT-DOWNLOAD",
        "dimension": "dim_behavior",
        "name": "诱导点击与静默下载安装 APK",
        "category": "交互行为",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "在广告交互中未弹窗明示应用主体及权限，私自调用系统下载器向后台推送安装包",
        "policy_ref": "工信部信管函〔2020〕164号第三项“欺骗误导强迫用户” · 工信部信管函〔2023〕26号第八条（明示下载与安装）",
        "remediation_principle": "【显式告知与二次确认阻断】严禁隐式排队静默下载；广告点击必须弹出二级确认 Dialog，展示应用名称、开发主体、安装包大小及所需权限清单，经二次确认方可启动下载。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-05: 显式二次确认弹窗 (阻断静默后台下载)
public class CompliantDownloadManager {
    public static void enqueueWithConsent(Context ctx, AppDownloadMeta meta) {
        // 1. 强制弹出符合工信部规范的下载确认对话框
        new AlertDialog.Builder(ctx)
            .setTitle("应用下载确认")
            .setMessage("应用名称: " + meta.appName + "\n" +
                         "开发企业: " + meta.developerCompany + "\n" +
                         "版本信息: v" + meta.versionName + " (" + meta.sizeMb + " MB)\n" +
                         "权限清单: 存储空间、网络通信")
            .setPositiveButton("立即下载", (dialog, which) -> {
                // 2. 仅在用户显式确认后提交系统下载队列
                DownloadManager dm = (DownloadManager) ctx.getSystemService(Context.DOWNLOAD_SERVICE);
                DownloadManager.Request req = new DownloadManager.Request(Uri.parse(meta.downloadUrl));
                req.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                dm.enqueue(req);
            })
            .setNegativeButton("取消", null)
            .show();
    }
}""",
        "signatures": [
            {"class": "Landroid/app/DownloadManager;", "method": "enqueue"},
            {"class": "Landroid/content/pm/PackageInstaller$Session;", "method": "commit"}
        ],
        "remediation": "严禁广告 SDK 或业务代码私自提交下载任务，必须弹出显式确认框标明应用名称、版本、开发者主体及所需权限。"
    },
    {
        "id": "MIIT-06-AUDIO-CAMERA",
        "dimension": "dim_behavior",
        "name": "无感知麦克风录音与偷拍偷窥",
        "category": "硬件传感器",
        "severity": "CRITICAL",
        "base_deduction": 8,
        "max_deduction": 12,
        "desc": "在无明确音视频互动场景或后台息屏状态下私自拉起麦克风或摄像头采集流",
        "policy_ref": "《个人信息保护法》第二十八/二十九条 · 工信部信管函〔2020〕164号第二项 · Android 12+ 隐私指示器规范",
        "remediation_principle": "【场景化前台绑定与可见性指示】麦克风/摄像头采集只能在用户主动操作的功能页面触发（如语音搜索、扫码）；息屏、退后台或页面销毁时必须立即 release 释放资源，前台录制必须配合显著的录制呼吸灯指示。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-06: 麦克风生命周期受控安全包装器
public class CompliantAudioRecorder {
    private AudioRecord mAudioRecord;
    private boolean mIsUserInitiated = false;

    public void startRecordingOnUserClick(Activity activity) {
        // 1. 校验用户是否前台主动点击
        if (!activity.hasWindowFocus() || !mIsUserInitiated) {
            Log.w("AppGuard-AI", "[合规拦截] 非前台主动手势，拒绝初始化 AudioRecord");
            return;
        }
        // 2. 绑定 Lifecycle，退后台立即释放资源
        activity.getLifecycle().addObserver((LifecycleEventObserver) (source, event) -> {
            if (event == Lifecycle.Event.ON_PAUSE || event == Lifecycle.Event.ON_STOP) {
                stopAndRelease(); // 退后台瞬时注销，严防静默偷录
            }
        });
        mAudioRecord.startRecording();
    }
}""",
        "signatures": [
            {"class": "Landroid/media/AudioRecord;", "method": "startRecording"},
            {"class": "Landroid/media/MediaRecorder;", "method": "start"},
            {"class": "Landroid/hardware/camera2/CameraDevice;", "method": "createCaptureSession"},
            {"class": "Landroid/hardware/Camera;", "method": "takePicture"}
        ],
        "remediation": "严禁在不可见界面或后台调用录音/拍照硬件；录音必须伴随系统通知栏常驻指示与前台录制计时动画。"
    },

    # ----------------------------------------------------
    # 维度三：权限边界与生命周期合规 (25分)
    # ----------------------------------------------------
    {
        "id": "MIIT-07-APP-LIST",
        "dimension": "dim_permission",
        "name": "超范围读取已安装应用列表",
        "category": "应用行为",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "调用 PackageManager 获取设备全部已安装应用，涉嫌非法获取用户画像或竞品窥探",
        "policy_ref": "《个人信息保护法》第十三条 · 工信部信管函〔2020〕164号第一项 · Android 11+ Package Visibility 规范",
        "remediation_principle": "【最小包可见性声明与按需查询】严禁在 Manifest 中声明 QUERY_ALL_PACKAGES；业务跨应用交互必须在 AndroidManifest.xml 中配置 <queries> 显式列举白名单包名，代码中按包名按需定向查询。",
        "remediation_code": """<!-- [合规代码补丁] AppGuard-Patch-07: AndroidManifest.xml 配置 <queries> 白名单声明 -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- 彻底移除 <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" /> -->
    <queries>
        <!-- 仅按需声明核心业务关联应用的包名或 Intent Filter -->
        <package android:name="com.tencent.mm" />          <!-- 微信分享/支付 -->
        <package android:name="com.eg.android.AlipayGphone" /> <!-- 支付宝支付 -->
        <intent>
            <action android:name="android.intent.action.VIEW" />
            <data android:scheme="https" />
        </intent>
    </queries>
</manifest>""",
        "signatures": [
            {"class": "Landroid/content/pm/PackageManager;", "method": "getInstalledPackages"},
            {"class": "Landroid/content/pm/PackageManager;", "method": "getInstalledApplications"}
        ],
        "remediation": "适配 Android 11+ 的 <queries> 元素，仅声明业务强依赖的应用包名，严禁全量遍历应用列表。"
    },
    {
        "id": "MIIT-08-LOCATION",
        "dimension": "dim_permission",
        "name": "后台超频索取高精度地理位置",
        "category": "位置隐私",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "后台运行或未启动位置核心业务时静默调用位置更新，存在越权定位追踪风险",
        "policy_ref": "《个人信息保护法》第二十八条（行踪轨迹属敏感个人信息） · 工信部信管函〔2020〕164号第二项 · 工信部信管函〔2023〕26号",
        "remediation_principle": "【前后台权限分离与低频降采样】非导航类 App 仅申请粗略定位 (ACCESS_COARSE_LOCATION)；页面进入 onStop 必须立即注销 LocationListener；后台定位最小间隔不得低于 300 秒，严禁后台超频追踪。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-08: 生命周期感知的合规定位管理器
public class CompliantLocationManager {
    private LocationManager mLocationManager;
    private LocationListener mListener;

    public void registerForegroundLocation(LifecycleOwner owner, Context context) {
        // 绑定前台生命周期，退后台立即注销定位
        owner.getLifecycle().addObserver((LifecycleEventObserver) (src, evt) -> {
            if (evt == Lifecycle.Event.ON_RESUME) {
                // 降级采样：最小间隔 180 秒，最小位移 100 米
                mLocationManager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 180000L, 100f, mListener);
            } else if (evt == Lifecycle.Event.ON_PAUSE) {
                mLocationManager.removeUpdates(mListener); // 退后台立即移除
            }
        });
    }
}""",
        "signatures": [
            {"class": "Landroid/location/LocationManager;", "method": "getLastKnownLocation"},
            {"class": "Landroid/location/LocationManager;", "method": "requestLocationUpdates"}
        ],
        "remediation": "进入后台时必须注销 LocationListener，非导航/地图类应用只允许申请粗略位置权限。"
    },
    {
        "id": "MIIT-09-AUTOSTART-WAKE",
        "dimension": "dim_permission",
        "name": "频繁自启动与‘全家桶’链式唤醒保活",
        "category": "生命周期",
        "severity": "MEDIUM",
        "base_deduction": 3,
        "max_deduction": 5,
        "desc": "注册开机、解锁、网络变更等广播自启，或通过隐式 Intent 链式唤醒关联应用全家桶",
        "policy_ref": "工信部信管函〔2020〕164号第四项“应用频繁自启动和关联唤醒” · 工信部信管函〔2023〕26号第九条",
        "remediation_principle": "【去关联化与受控调度】删除开机广播 RECEIVE_BOOT_COMPLETED 及网络变更自启广播；停用跨进程/跨应用隐式广播链式唤醒；后台离线任务一律迁移至系统标准 WorkManager 受控调度。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-09: 使用 WorkManager 替代守护进程自启保活
public class CompliantSyncScheduler {
    public static void schedulePeriodicTask(Context context) {
        // 使用系统级 WorkManager 受控调度，遵守电池优化规范，不占用前台自启通道
        PeriodicWorkRequest syncWork = new PeriodicWorkRequest.Builder(DataSyncWorker.class, 6, TimeUnit.HOURS)
            .setConstraints(new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.UNMETERED) // 仅在 WiFi 连接时同步
                .setRequiresBatteryNotLow(true)               // 电量充沛才执行
                .build())
            .build();
        WorkManager.getInstance(context).enqueueUniquePeriodicWork("ComplianceSync", ExistingPeriodicWorkPolicy.KEEP, syncWork);
    }
}""",
        "signatures": [
            {"class": "Landroid/content/Context;", "method": "startForegroundService"},
            {"class": "Landroid/app/job/JobScheduler;", "method": "schedule"}
        ],
        "remediation": "移除不必要的自启动广播监听器；禁止利用同厂商 SDK 相互拉起，遵循 Android 规范生命周期限制。"
    },

    # ----------------------------------------------------
    # 维度四：私密数据与防逃逸合规 (25分)
    # ----------------------------------------------------
    {
        "id": "MIIT-10-CLIPBOARD",
        "dimension": "dim_data",
        "name": "私自静默读取剪贴板信息",
        "category": "剪贴板隐私",
        "severity": "MEDIUM",
        "base_deduction": 3,
        "max_deduction": 5,
        "desc": "未经用户明确交互触发静默读取剪贴板内容，存在窃取淘口令、银行卡号等隐私隐患",
        "policy_ref": "《个人信息保护法》第十三/十七条 · 工信部信管函〔2023〕26号第七条 · Android 12+ 剪贴板安全感知机制",
        "remediation_principle": "【用户明确手势绑定】严禁在 Application 初始化、Activity onCreate 或无交互时读取剪贴板淘口令；必须严格限制在用户主动点击“粘贴”按键或长按输入框时方可触发 getPrimaryClip()。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-10: 绑定主动点击手势的安全剪贴板读取器
public class CompliantClipboardHelper {
    public static void readOnUserGesture(Activity activity, View pasteButton, Consumer<String> onTextPasted) {
        // 严禁冷启动自动嗅探，必须绑定在 View.OnClickListener 的主动触摸手势上
        pasteButton.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip()) {
                ClipData clipData = cm.getPrimaryClip();
                if (clipData != null && clipData.getItemCount() > 0) {
                    CharSequence text = clipData.getItemAt(0).coerceToText(activity);
                    if (text != null && text.length() > 0) {
                        onTextPasted.accept(text.toString());
                    }
                }
            }
        });
    }
}""",
        "signatures": [
            {"class": "Landroid/content/ClipboardManager;", "method": "getPrimaryClip"},
            {"class": "Landroid/content/ClipboardManager;", "method": "getText"}
        ],
        "remediation": "禁止在 Activity 启动时自动触发剪贴板读取，必须由用户明确点击粘贴操作时方可触发。"
    },
    {
        "id": "MIIT-11-STORAGE-PHOTO",
        "dimension": "dim_data",
        "name": "逃逸分区存储扫描全盘文件与相册",
        "category": "存储隐私",
        "severity": "HIGH",
        "base_deduction": 5,
        "max_deduction": 8,
        "desc": "违规索取全盘文件管理权限，或后台扫描用户公共相册媒体文件的 Exif GPS 定位数据",
        "policy_ref": "《个人信息保护法》第十三/二十八条 · 工信部信管函〔2020〕164号第二项 · Android 11+ Scoped Storage 分区存储规范",
        "remediation_principle": "【分区存储与系统 PhotoPicker 隔离】移除 MANAGE_EXTERNAL_STORAGE 滥用声明；应用沙盒内读写使用 context.getExternalFilesDir()；图片选择接入 Android 系统级 PhotoPicker 或 SAF。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-11: 接入系统 PhotoPicker 替代全盘存储扫描权限
public class MediaPickerComplianceHelper {
    public static void launchPhotoPicker(ComponentActivity activity, ActivityResultLauncher<PickVisualMediaRequest> launcher) {
        // Android 13+ / Jetpack PhotoPicker: 无需向用户申请任何读取存储权限即可安全选图
        launcher.launch(new PickVisualMediaRequest.Builder()
            .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly.INSTANCE)
            .build());
    }
}""",
        "signatures": [
            {"class": "Landroid/os/Environment;", "method": "getExternalStorageDirectory"},
            {"class": "Landroid/os/Environment;", "method": "getExternalStoragePublicDirectory"}
        ],
        "remediation": "严格遵守 Android 11+ 分区存储规范，严禁申请 MANAGE_EXTERNAL_STORAGE；选取照片应接入系统 PhotoPicker。"
    },
    {
        "id": "MIIT-12-DYNAMIC-DEX",
        "dimension": "dim_data",
        "name": "恶意动态类加载与反射逃逸对抗",
        "category": "安全对抗",
        "severity": "MEDIUM",
        "base_deduction": 3,
        "max_deduction": 5,
        "desc": "利用 DexClassLoader 动态下发未经审查的加密字节码，或大量使用反射躲避静态特征审查",
        "policy_ref": "工信部移动应用程序分发上架合规规范 · 《网络安全法》第二十二条 · 主流应用市场开发者代码安全标准",
        "remediation_principle": "【静态签名固化与下线外部下发】严禁在运行时从远程服务器下载解密可执行 Dex/So 文件并调用 DexClassLoader 加载；所有业务模块和 SDK 代码必须在发版时打入固定安装包并做签名校验。",
        "remediation_code": """// [合规代码补丁] AppGuard-Patch-12: 废弃外部动态 Dex 下发，采用静态签名校验加载
public class CompliantPluginLoader {
    public static void loadAuditedPlugin(Context context, File apkFile, String expectedSha256) throws Exception {
        // 1. 强力校验待加载 APK 的 SHA-256 签名指纹，严防中间人篡改或投毒
        String actualSha256 = DigestUtils.sha256Hex(new FileInputStream(apkFile));
        if (!actualSha256.equalsIgnoreCase(expectedSha256)) {
            throw new SecurityException("[AppGuard-AI 合规拦截] 动态插件指纹与应用安全基线不一致，拒绝加载！");
        }
        // 2. 存放在应用内部不可导出的只读目录 code_cache 中
        File optDir = context.getCodeCacheDir();
        new DexClassLoader(apkFile.getAbsolutePath(), optDir.getAbsolutePath(), null, context.getClassLoader());
    }
}""",
        "signatures": [
            {"class": "Ldalvik/system/DexClassLoader;", "method": "loadClass"},
            {"class": "Ldalvik/system/PathClassLoader;", "method": "loadClass"}
        ],
        "remediation": "下线未备案的热更新 Dex 下发通道；核心业务敏感接口显式声明调用，避免对抗性反射。"
    }
]

# 常见第三方 SDK 特征指纹库 (SDK Fingerprints)
KNOWN_SDKS = {
    "com/pangle": "穿山甲广告 (Pangle / ByteDance)",
    "com/bytedance/sdk/openadsdk": "穿山甲广告 SDK",
    "com/qq/e": "腾讯优量汇广告 (Tencent GDT)",
    "com/baidu/mobads": "百度移动广告 SDK",
    "com/kwad": "快手联盟广告 SDK",
    "com/kwai": "快手商业化 SDK",
    "com/sigmob": "Sigmob 移动广告 SDK",
    "com/tencent/bugly": "腾讯 Bugly 异常监控与崩溃分析",
    "com/tencent/mm/opensdk": "微信开放平台 SDK (OpenSDK)",
    "com/tencent/map": "腾讯地图 SDK",
    "com/tencent/tencentmap": "腾讯地图定位组件",
    "com/tencent/cos": "腾讯云对象存储 COS SDK",
    "com/tencent/cloud": "腾讯云移动终端 SDK",
    "com/tencent/smtt": "腾讯浏览服务 X5 内核 (TBS)",
    "com/tencent": "腾讯通用基础 SDK",
    "cn/jpush": "极光推送 (JPush)",
    "cn/jiguang": "极光开发者服务 (JIGUANG)",
    "com/igexin": "个推消息推送 (GeTui)",
    "com/getui": "个推开发者服务",
    "com/amap/api": "高德地图与高精度定位 SDK",
    "com/autonavi": "高德地图底层定位服务",
    "com/amap": "高德地图/定位 SDK",
    "com/baidu/location": "百度高精度定位 SDK",
    "com/baidu/mapapi": "百度地图 API",
    "com/baidu": "百度通用开发者服务",
    "com/umeng": "友盟统计与社会化分享 SDK",
    "com/alipay": "支付宝支付与移动安全 SDK",
    "com/sensorsdata": "神策数据用户行为分析 SDK",
    "com/talkingdata": "TalkingData 移动大数据分析",
    "com/mob": "MobTech 开发者服务 (ShareSDK/秒验)",
    "com/sina/weibo": "新浪微博社会化分享 SDK",
    "com/huawei/hms": "华为移动服务 (HMS Core)",
    "com/xiaomi/mipush": "小米消息推送 (MiPush)",
    "com/xiaomi/push": "小米系统推送组件",
    "com/heytap/msp": "OPPO HeyTap 移动推送 SDK",
    "com/oppo/push": "OPPO 推送服务",
    "com/vivo/push": "vivo 消息推送 SDK",
    "com/meizu/cloud/pushsdk": "魅族云推送 SDK",
    "io/agora": "声网 Agora 实时音视频 SDK",
    "com/netease/nimlib": "网易云信即时通讯 (NIM) SDK",
    "io/rong": "融云即时通讯 (RongCloud) SDK",
    "com/alibaba/sdk": "阿里云移动开发平台 SDK",
    "com/aliyun": "阿里云移动基础设施组件",
    "com/bytedance/applog": "火山引擎 DataFinder 移动分析",
    "com/bytedance": "字节跳动系通用组件",
    "com/geetest": "极验行为安全验证码 SDK",
    "com/dingxiang": "顶象无感验证与移动风控 SDK",
    "com/secneo": "梆梆移动应用安全加固组件",
    "com/ijiami": "爱加密安全加固与检测 SDK",
    "com/appsflyer": "AppsFlyer 移动归因与营销分析",
    "com/adjust/sdk": "Adjust 移动归因与防欺诈 SDK",
    "io/sentry": "Sentry 移动端性能监控与崩溃上报",
    "com/google/firebase": "Google Firebase 移动服务平台",
    "com/qiniu": "七牛云对象存储与移动多媒体 SDK"
}

OFFICIAL_FRAMEWORKS = {
    "androidx": "AndroidX 官方支持库 (系统兼容组件)",
    "android/support": "Android Support 官方兼容库 (系统兼容组件)",
    "com/google/android/material": "Google Material 官方设计库 (系统兼容组件)",
    "com/google/android/gms": "Google Play Services 官方基础服务",
    "kotlin": "Kotlin 官方标准库",
    "kotlinx": "KotlinX 协程扩展库"
}

def is_prefix_match(norm_path, prefix, is_sdk=False):
    p = prefix.strip("/")
    n = norm_path.strip("/")
    # 严格顶层前缀匹配（杜绝命名空间伪装绕过，例如 com.example.androidx.Evil）
    if n == p or n.startswith(p + "/"):
        return True
    # 仅对商业第三方 SDK 允许前两段内的重定位子包匹配（如 shadow/com/pangle），官方框架严禁子串匹配
    if is_sdk and ("/" + p + "/") in ("/" + n + "/"):
        parts = n.split("/")
        sub_prefix = "/".join(parts[:3])
        if ("/" + p + "/") in ("/" + sub_prefix + "/"):
            return True
    return False

def identify_culprit(caller_class):
    norm = caller_class.strip("L;").replace(".", "/")
    # 1. 优先按路径段精确匹配 54 款商业第三方 SDK
    for prefix in sorted(KNOWN_SDKS.keys(), key=len, reverse=True):
        if is_prefix_match(norm, prefix, is_sdk=True):
            return KNOWN_SDKS[prefix]
    # 2. 匹配 Google / AndroidX 官方系统兼容组件 (严格顶层前缀，严禁子串，防伪装推责)
    for prefix in sorted(OFFICIAL_FRAMEWORKS.keys(), key=len, reverse=True):
        if is_prefix_match(norm, prefix, is_sdk=False):
            return OFFICIAL_FRAMEWORKS[prefix]
    # 3. 宿主自研业务模块
    return "应用自身业务模块"

def is_benign_framework_call(caller_class, caller_method, target_api):
    """
    识别 AndroidX/Google Material/Kotlin 等官方系统框架内部的已知良性向下兼容实现
    包括夜间模式日落日出计算 (TwilightManager)、系统级长按粘贴与剪贴板分发、前台服务向下兼容分发等。
    避免将官方系统组件与基础扩展库的良性向下兼容调用错误扣在应用业务头上造成假阳性误报。
    """
    c = caller_class.strip("L;").replace(".", "/")
    m = caller_method or ""
    
    # 检查是否属于官方系统兼容库/官方基础标准库
    is_official = False
    for prefix in OFFICIAL_FRAMEWORKS.keys():
        if is_prefix_match(c, prefix, is_sdk=False):
            is_official = True
            break
            
    if is_official:
        # 1. 剪贴板良性向下兼容 (AndroidX / Google Material 文本长按粘贴、选区菜单、输入控件剪贴板存取)
        if any(kw in target_api for kw in ["getPrimaryClip", "hasPrimaryClip", "getPrimaryClipDescription"]):
            if any(pkg in c for pkg in [
                "androidx/appcompat/widget",
                "androidx/core/view",
                "android/support",
                "com/google/android/material"
            ]) or "Paste" in m or "Clipboard" in c or "ReceiveContent" in c:
                return True
                
        # 2. 位置服务良性兼容 (夜间日落日出计算 TwilightManager、暗黑模式自动切换等)
        if any(kw in target_api for kw in ["Location", "getLastKnownLocation", "requestSingleUpdate"]):
            if any(pkg in c for pkg in [
                "TwilightManager",
                "androidx/appcompat",
                "android/support",
                "com/google/android/material"
            ]):
                return True
                
        # 3. 前台服务启动向下兼容 (ContextCompat / WorkManager / 协程生命周期任务调度)
        if "startForegroundService" in target_api:
            if any(pkg in c for pkg in [
                "androidx/core",
                "android/support",
                "androidx/work",
                "kotlinx/coroutines"
            ]):
                return True
                
        # 4. 网络状态监测良性兼容 (WorkManager 约束条件追踪器 / Core 网络状态广播接收)
        if any(kw in target_api for kw in ["NetworkInfo", "getNetworkCapabilities", "getAllNetworks", "getActiveNetwork"]):
            if any(pkg in c for pkg in ["androidx/work", "androidx/core"]):
                return True

    return False

def build_sdk_attribution(findings):
    """
    第三方 SDK 责任穿透与侵权归因大盘
    统计应用自身业务 vs 官方系统兼容框架 vs 第三方商业 SDK 的违规调用占比与风险分摊
    """
    total_calls = 0
    host_calls = 0
    framework_calls = 0
    commercial_sdk_calls = 0
    sdk_map = {}
    
    for f in findings:
        r = f.get("rule", {})
        rule_name = r.get("name", "未命名规则")
        severity = r.get("severity", "MEDIUM")
        
        for d in f.get("details", []):
            total_calls += 1
            culprit = d.get("culprit", "应用自身业务模块")
            if "应用自身" in culprit or culprit == "Host App" or culprit == "宿主进程":
                host_calls += 1
            elif "系统兼容组件" in culprit or "官方" in culprit:
                framework_calls += 1
                if culprit not in sdk_map:
                    sdk_map[culprit] = {
                        "name": culprit,
                        "category": "official_framework",
                        "count": 0,
                        "rules": set(),
                        "severities": set(),
                        "sample_calls": []
                    }
                sdk_map[culprit]["count"] += 1
                sdk_map[culprit]["rules"].add(rule_name)
                sdk_map[culprit]["severities"].add(severity)
                if len(sdk_map[culprit]["sample_calls"]) < 3:
                    sdk_map[culprit]["sample_calls"].append({
                        "api": d.get("target_api", ""),
                        "caller": f"{d.get('caller_class', '')}->{d.get('caller_method', '')}"
                    })
            else:
                commercial_sdk_calls += 1
                if culprit not in sdk_map:
                    sdk_map[culprit] = {
                        "name": culprit,
                        "category": "commercial_sdk",
                        "count": 0,
                        "rules": set(),
                        "severities": set(),
                        "sample_calls": []
                    }
                sdk_map[culprit]["count"] += 1
                sdk_map[culprit]["rules"].add(rule_name)
                sdk_map[culprit]["severities"].add(severity)
                if len(sdk_map[culprit]["sample_calls"]) < 3:
                    sdk_map[culprit]["sample_calls"].append({
                        "api": d.get("target_api", ""),
                        "caller": f"{d.get('caller_class', '')}->{d.get('caller_method', '')}"
                    })
                    
    sdk_calls = commercial_sdk_calls
    host_pct = round((host_calls / total_calls * 100), 1) if total_calls > 0 else 0
    framework_pct = round((framework_calls / total_calls * 100), 1) if total_calls > 0 else 0
    sdk_pct = round((sdk_calls / total_calls * 100), 1) if total_calls > 0 else 0
    
    sdk_list = []
    for name, item in sdk_map.items():
        pct = round((item["count"] / total_calls * 100), 1) if total_calls > 0 else 0
        rules_list = sorted(list(item["rules"]))
        
        # 针对不同 SDK 类别提供具有法务实操价值的免责与治理指引
        if item.get("category") == "official_framework":
            action_advice = "官方系统兼容框架：该调用来源于 AndroidX/Google 官方支持库向下兼容实现，通常属于规范生命周期管理，建议复核触发链路并保持框架版本更新。"
        elif "穿山甲" in name or "优量汇" in name or "快手" in name or "Sigmob" in name:
            action_advice = "广告联盟 SDK：必须在用户同意《隐私政策》后延时初始化，并调用 setPrivacyCompliance(true) 模式，与厂商补签《个人信息处理连带合规协议》。"
        elif "推送" in name or "JPush" in name or "个推" in name or "mipush" in name:
            action_advice = "消息推送 SDK：停用广播链式唤醒保活通道，关闭后台静默读取设备标识与应用列表，升级至工信部合规版本。"
        elif "地图" in name or "高德" in name or "百度" in name:
            action_advice = "定位地图 SDK：停用冷启动持续轮询高精度 GPS，仅在导航或位置前台交互页面动态注册 Listener，进入后台即刻 unregister。"
        elif "统计" in name or "友盟" in name or "神策" in name:
            action_advice = "数据统计分析 SDK：严禁使用 TelephonyManager 获取 IMEI/MAC，应全面切换为中国信通院 MSA 统一匿名设备标识 (OAID)。"
        else:
            action_advice = "建议与第三方 SDK 供应商签署《个人信息处理连带合规协议》，在 Application.onCreate 设立延迟合闸开关，未明示前严格拦截。"

        sdk_list.append({
            "name": name,
            "category": item.get("category", "commercial_sdk"),
            "count": item["count"],
            "percentage": pct,
            "rules": rules_list,
            "severities": sorted(list(item["severities"])),
            "sample_calls": item["sample_calls"],
            "action_advice": action_advice
        })
        
    sdk_list.sort(key=lambda x: x["count"], reverse=True)
    primary_offender = sdk_list[0]["name"] if sdk_list else "无（均为宿主自研模块）"
    
    if sdk_pct >= 50:
        verdict = f"经 Dalvik 字节码调用流与 XRef 责任穿透分析：第三方商业集成 SDK 违规占比达 {sdk_pct}%，官方系统框架占比 {framework_pct}%，自研业务占比 {host_pct}%。商业 SDK 是导致应用触发监管通报的首要风险源，建议启动 SDK 延迟初始化合闸机制。"
    elif host_pct >= 50:
        verdict = f"经 Dalvik 字节码调用流与 XRef 责任穿透分析：主要责任源于应用宿主自研业务模块 ({host_pct}%)，官方系统框架占比 {framework_pct}%，商业 SDK 占比 {sdk_pct}%。建议优先依据工信部合规要求重构自研业务代码。"
    elif framework_pct > 0:
        verdict = f"经 Dalvik 字节码调用流与 XRef 责任穿透分析：应用自研业务占比 {host_pct}%，官方系统兼容框架占比 {framework_pct}%，第三方商业 SDK 占比 {sdk_pct}%。系统框架兼容组件占比较高，已实施误报消歧与免责归因。"
    else:
        verdict = f"经 Dalvik 字节码调用流与 XRef 责任穿透分析：检测到应用敏感调用，自研业务占比 {host_pct}%，商业 SDK 占比 {sdk_pct}%。"

    return {
        "total_calls": total_calls,
        "host_calls": host_calls,
        "host_pct": host_pct,
        "framework_calls": framework_calls,
        "framework_pct": framework_pct,
        "sdk_calls": sdk_calls,
        "sdk_pct": sdk_pct,
        "sdk_list": sdk_list,
        "sdk_count": len(sdk_list),
        "primary_offender": primary_offender,
        "accountability_verdict": verdict
    }

def calculate_weighted_score(findings):
    """
    四维加权分级评估模型 (4-Tier Weighted Compliance Index, WCI)
    """
    dim_deductions = {k: 0 for k in DIMENSION_METADATA}
    critical_hits = []
    high_hits = []
    
    for f in findings:
        r = f["rule"]
        dim_key = r.get("dimension", "dim_data")
        count = f["count"]
        base_p = r.get("base_deduction", 5)
        max_p = r.get("max_deduction", 8)
        
        if r.get("framework_internal_only"):
            rule_ded = 0
            r["calculated_points"] = 0
            r["points"] = 0
        else:
            # 频次对数阻尼公式
            extra = min(max_p - base_p, int(math.log2(count) * 1.2)) if count > 1 else 0
            rule_ded = base_p + extra
            r["calculated_points"] = rule_ded
            r["points"] = rule_ded
            
            dim_deductions[dim_key] += rule_ded
            if r["severity"] == "CRITICAL":
                critical_hits.append(r["name"])
            elif r["severity"] == "HIGH":
                high_hits.append(r["name"])

    # 计算四维得分（单维度封顶 25 分）
    dim_scores = {}
    raw_total = 0
    for dim_key, meta in DIMENSION_METADATA.items():
        ded = dim_deductions[dim_key]
        score = max(0, meta["weight"] - min(meta["weight"], ded))
        dim_scores[dim_key] = {
            "id": dim_key,
            "name": meta["name"],
            "weight": meta["weight"],
            "icon": meta["icon"],
            "score": score,
            "deduction": ded
        }
        raw_total += score

    # 工信部核心红线“熔断降级机制”
    is_fused = False
    fuse_reason = ""
    if critical_hits:
        final_score = min(raw_total, 55)
        risk_level = "CRITICAL (高危 - 触发工信部下架红线)"
        is_fused = True
        fuse_reason = f"触发工信部核心红线熔断：命中 {critical_hits[0]} 等一票否决项"
    elif high_hits:
        final_score = min(raw_total, 78)
        risk_level = "MEDIUM (中风险 - 存在重点通报隐患)"
    elif raw_total >= 85:
        final_score = raw_total
        risk_level = "LOW (低风险 - 合规达标)"
    else:
        final_score = raw_total
        risk_level = "MEDIUM (中风险 - 存在通报隐患)"

    return {
        "compliance_score": final_score,
        "raw_score": raw_total,
        "risk_level": risk_level,
        "is_fused": is_fused,
        "fuse_reason": fuse_reason,
        "dimensions": dim_scores,
        "critical_count": len(critical_hits),
        "high_count": len(high_hits)
    }

def run_audit(apk_path):
    if not os.path.isfile(apk_path):
        print(f"[!] Error: APK file not found at '{apk_path}'")
        return

    start_time = time.time()
    print(f"\n{'='*70}")
    print(f"[*] 启动移动应用隐私合规自动化智审引擎 (AppGuard-AI Audit Engine v1.10)")
    print(f"[*] 四维加权分级评估模型 (WCI) · 12 大工信部专项红线与责任穿透")
    print(f"[*] 目标安装包: {os.path.abspath(apk_path)}")
    print(f"{'='*70}\n")

    print("[1/4] 正在反编译并解析 DEX 字节码与清单文件...")
    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    app_name = a.get_app_name() or package_name
    target_sdk = a.get_target_sdk_version()
    permissions = list(a.get_permissions())

    print(f"    - 应用名称: {app_name}")
    print(f"    - 目标包名: {package_name}")
    print(f"    - Target SDK: {target_sdk}")
    print(f"    - 声明权限数: {len(permissions)}")

    print("\n[2/4] 正在执行 12 大工信部合规红线规则深度匹配与字节码调用链责任穿透...")
    findings = []

    for rule in MIIT_RULES:
        rule_findings = []
        for sig in rule["signatures"]:
            target_class = sig["class"]
            target_method = sig["method"]
            
            methods = dx.find_methods(classname=target_class, methodname=target_method)
            for m in methods:
                xrefs = m.get_xref_from()
                for xref_class, xref_method, offset in xrefs:
                    caller_clz_name = xref_class.name
                    caller_mth_name = xref_method.name
                    target_api_str = f"{target_class.strip('L;').replace('/', '.')} -> {target_method}"
                    caller_clz_str = caller_clz_name.strip('L;').replace('/', '.')
                    culprit = identify_culprit(caller_clz_name)
                    is_benign = is_benign_framework_call(caller_clz_str, caller_mth_name, target_api_str)
                    
                    rule_findings.append({
                        "target_api": target_api_str,
                        "caller_class": caller_clz_str,
                        "caller_method": caller_mth_name,
                        "culprit": culprit,
                        "offset": hex(offset),
                        "is_framework_internal": is_benign
                    })

        if rule_findings:
            rule_copy = dict(rule)
            # 检查是否全部调用点均为官方系统框架内部良性兼容实现
            framework_internal_only = all(d.get("is_framework_internal") for d in rule_findings)
            if framework_internal_only:
                rule_copy["framework_internal_only"] = True
                rule_copy["base_deduction"] = 0
                rule_copy["max_deduction"] = 0
                rule_copy["advisory_note"] = "【系统兼容提示】仅在 AndroidX/官方兼容库内部向下兼容链路中发现调用，非应用主观恶意违规，已依据责任穿透模型豁免扣分。"

            findings.append({
                "rule": rule_copy,
                "count": len(rule_findings),
                "details": rule_findings
            })

    # 执行四维加权分级评估
    eval_res = calculate_weighted_score(findings)
    compliance_score = eval_res["compliance_score"]
    risk_level = eval_res["risk_level"]
    dimensions = eval_res["dimensions"]
    is_fused = eval_res["is_fused"]
    fuse_reason = eval_res["fuse_reason"]

    # 执行第三方 SDK 责任穿透与侵权归因
    sdk_attribution = build_sdk_attribution(findings)

    color_code = "\033[92m" if compliance_score >= 80 else ("\033[93m" if compliance_score >= 60 else "\033[91m")
    reset_color = "\033[0m"

    print(f"\n[3/4] 审计完成！合规评估综合得分: {color_code}{compliance_score} / 100{reset_color}")
    print(f"    - 风险等级: {color_code}{risk_level}{reset_color}")
    if is_fused:
        print(f"    - \033[91m[!] {fuse_reason}\033[0m")
    deduct_findings = [f for f in findings if not f.get("rule", {}).get("framework_internal_only")]
    exempt_findings = [f for f in findings if f.get("rule", {}).get("framework_internal_only")]
    print(f"    - 检出敏感行为: {len(findings)} 项 (实际违规扣分: {len(deduct_findings)} 项, 官方系统框架良性兼容·已豁免: {len(exempt_findings)} 项)")
    print(f"    - 责任穿透: 宿主自研 {sdk_attribution['host_pct']}% | 官方系统框架 {sdk_attribution.get('framework_pct', 0)}% | 商业 SDK {sdk_attribution['sdk_pct']}% (涉及 {sdk_attribution['sdk_count']} 款 SDK/组件)")
    print(f"    - 四维分项健康度:")
    for dim_k, dim_v in dimensions.items():
        print(f"      · {dim_v['name']}: {dim_v['score']}/{dim_v['weight']} (扣除 {dim_v['deduction']} 分)")

    if deduct_findings:
        print(f"\n{'-'*75}")
        print(f"【实际违规扣分项】(共 {len(deduct_findings)} 项，计入最终评分扣减)")
        print(f"{'核查规则 / 违规项':<32} | {'危险等级':<10} | {'调用次数':<8} | {'核算扣分':<10}")
        print(f"{'-'*75}")
        for f in deduct_findings:
            r = f["rule"]
            culprits = set([d["culprit"] for d in f["details"]])
            culprit_str = ", ".join(culprits)
            print(f"{r['name']:<30} | {r['severity']:<10} | {f['count']:<8} | -{r['points']}分")
            print(f"  └─ 责任主体: {culprit_str}")
            for d in f["details"][:2]:
                print(f"     [调用点] {d['caller_class']}::{d['caller_method']} -> {d['target_api']}")
            if len(f["details"]) > 2:
                print(f"     [+] 其余 {len(f['details'])-2} 处调用详见 HTML 完整报告")
            print()

    if exempt_findings:
        print(f"{'-'*75}")
        print(f"【官方系统框架良性兼容·已豁免提示项】(共 {len(exempt_findings)} 项，不扣分)")
        print(f"{'核查规则 / 兼容项':<32} | {'风险归属':<10} | {'调用次数':<8} | {'核算状态':<10}")
        print(f"{'-'*75}")
        for f in exempt_findings:
            r = f["rule"]
            culprits = set([d["culprit"] for d in f["details"]])
            culprit_str = ", ".join(culprits)
            print(f"{r['name']:<30} | {'官方兼容':<10} | {f['count']:<8} | 0分 (已豁免)")
            print(f"  └─ 归属组件: {culprit_str}")
            print(f"  └─ 豁免说明: {r.get('advisory_note', '仅在官方系统兼容库内部向下兼容链路中调用，已依据穿透模型豁免')}")
            for d in f["details"][:2]:
                print(f"     [兼容调用] {d['caller_class']}::{d['caller_method']} -> {d['target_api']}")
            if len(f["details"]) > 2:
                print(f"     [+] 其余 {len(f['details'])-2} 处调用详见 HTML 完整报告")
            print()

    print("[4/4] 正在生成《移动应用隐私合规与SDK风险体检报告 (HTML)》...")
    elapsed_time = round(time.time() - start_time, 2)
    audit_dict = {
        "apk_path": apk_path,
        "app_name": app_name,
        "package_name": package_name,
        "target_sdk": target_sdk,
        "permissions_count": len(permissions),
        "permissions": permissions,
        "compliance_score": compliance_score,
        "raw_score": eval_res["raw_score"],
        "risk_level": risk_level,
        "is_fused": is_fused,
        "fuse_reason": fuse_reason,
        "dimensions": dimensions,
        "findings": findings,
        "sdk_attribution": sdk_attribution,
        "elapsed": elapsed_time,
        "audit_type": "static"
    }

    agent_analysis = None
    try:
        import compliance_agent
        import report_generator
        print("[*] 正在调用 Compliance Agent 执行 39 类国标场景化最小必要性研判与代码追溯...")
        agent_analysis = compliance_agent.default_compliance_agent.analyze(audit_dict)
        audit_dict["agent_analysis"] = agent_analysis
        report_filename = report_generator.generate_report(audit_dict, output_dir="outputs")
        report_path = os.path.join("outputs", report_filename)
        print(f"[+] Compliance Agent 智能体场景化裁决完成: {agent_analysis.get('verdict_title')}")
    except Exception as e:
        print(f"[!] 接入智能体报告引擎异常，回退至基础报告生成器: {e}")
        report_path = generate_html_report(apk_path, app_name, package_name, target_sdk, permissions, compliance_score, risk_level, findings, elapsed_time, dimensions, is_fused, fuse_reason, sdk_attribution)

    print(f"[+] 审计报告已生成: file://{os.path.abspath(report_path)}")
    print(f"[*] 全流程分析总耗时: {time.time() - start_time:.2f} 秒\n")
    return {
        "report_path": report_path,
        "report_filename": os.path.basename(report_path),
        "app_name": app_name,
        "package_name": package_name,
        "target_sdk": target_sdk,
        "permissions_count": len(permissions),
        "permissions": permissions,
        "compliance_score": compliance_score,
        "raw_score": eval_res["raw_score"],
        "risk_level": risk_level,
        "is_fused": is_fused,
        "fuse_reason": fuse_reason,
        "dimensions": dimensions,
        "findings": findings,
        "sdk_attribution": sdk_attribution,
        "agent_analysis": agent_analysis,
        "elapsed": elapsed_time
    }

def generate_html_report(apk_path, app_name, package_name, target_sdk, permissions, score, risk_level, findings, elapsed, dimensions=None, is_fused=False, fuse_reason="", sdk_attribution=None, output_dir="outputs"):
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, f"Compliance_Report_{package_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    
    if sdk_attribution is None:
        sdk_attribution = build_sdk_attribution(findings)

    # 提取 DEX 载荷体量
    payload_str = ""
    try:
        import zipfile
        with zipfile.ZipFile(apk_path, 'r') as z:
            c_bytes = sum(info.compress_size for info in z.infolist() if (info.filename.startswith("classes") and info.filename.endswith(".dex")) or info.filename == "AndroidManifest.xml")
            c_mb = round(c_bytes / (1024 * 1024), 2)
            payload_str = f"{c_mb} MB"
    except Exception:
        payload_str = "核心载荷"

    findings_html = ""
    for f in findings:
        r = f["rule"]
        sev = r["severity"].lower()
        badge_cls = "badge-critical" if sev == "critical" else ("badge-high" if sev == "high" else "badge-medium")
        severity_badge = f'<span class="badge {badge_cls}">{r["severity"]}</span>'
        
        cross_badge = ""
        if r.get("framework_internal_only"):
            cross_badge = '<span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold;background:rgba(16,185,129,0.2);color:#10b981;border:1px solid rgba(16,185,129,0.4);margin-left:8px;">[官方框架良性兼容·豁免扣分]</span>'
            score_text = f"扣减分值: 0 分 (已豁免) · 捕获调用: {f['count']} 处"
            score_color = "#10b981"
        else:
            score_text = f"扣减分值: -{r.get('points', r.get('calculated_points', 5))} 分 · 调用次数: {f['count']} 处"
            score_color = "var(--danger)"

        rows = ""
        for d in f["details"]:
            culprit_str = d['culprit']
            if d.get("is_framework_internal"):
                culprit_str = f"<span style='color:#10b981;'>[官方兼容]</span> {culprit_str}"
            rows += f"""
            <tr>
                <td><code>{culprit_str}</code></td>
                <td><code>{d['caller_class']}<br>&nbsp;└─&gt; {d['caller_method']}</code></td>
                <td><code style="color:var(--accent-blue);">{d['target_api']}</code></td>
                <td><code>{d['offset']}</code></td>
            </tr>
            """

        advisory_html = ""
        if r.get("advisory_note"):
            advisory_html = f"""<div style="margin:8px 0 12px 0;padding:8px 12px;border-radius:8px;background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);font-size:12px;color:#a7f3d0;line-height:1.6;"><strong>系统兼容免责提示：</strong>{r.get('advisory_note')}</div>"""

        policy_tag = f'<div style="font-size:11px;color:#94a3b8;margin-bottom:6px;font-family:monospace;"><strong>法规条款：</strong>{r.get("policy_ref", "工信部信管函〔2020〕164号")}</div>' if r.get("policy_ref") else ""
        code_patch_html = ""
        if r.get("remediation_code"):
            escaped_code = r["remediation_code"].replace("<", "&lt;").replace(">", "&gt;")
            code_patch_html = f"""
            <div style="margin-top:10px;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:12px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <span style="font-size:11px;font-weight:bold;color:#38bdf8;">【符合工信部规范的代码修复建议 (Code Patch)】</span>
                    <span style="font-size:10px;color:#64748b;">Java / Android SDK</span>
                </div>
                <pre style="margin:0;font-family:ui-monospace,monospace;font-size:11px;color:#e2e8f0;overflow-x:auto;line-height:1.5;">{escaped_code}</pre>
            </div>
            """

        findings_html += f"""
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div style="display: flex; align-items: center; flex-wrap: wrap;">
                    {severity_badge}
                    <strong style="font-size: 15px; margin-left: 8px;">{r['name']}</strong>
                    <span style="color: var(--text-sub); font-size: 12px; margin-left: 6px;">({r['category']})</span>
                    {cross_badge}
                </div>
                <div style="font-family: ui-monospace, monospace; color: {score_color}; font-weight: 700;">
                    {score_text}
                </div>
            </div>
            <div style="font-size: 13px; color: var(--text-sub); margin-bottom: 12px;">
                {r['desc']}
            </div>
            {advisory_html}
            <div class="remediation-box">
                {policy_tag}
                <strong>【工信部整改指引】:</strong> {r.get('remediation_principle', r['remediation'])}
            </div>
            {code_patch_html}
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">责任归属主体</th>
                        <th style="width: 40%;">调用者类与方法 (Caller)</th>
                        <th style="width: 25%;">敏感目标 API (Target)</th>
                        <th style="width: 10%;">字节码偏移</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    # 渲染四维健康度卡片
    dim_cards_html = ""
    if dimensions:
        for dim_k in ['dim_device', 'dim_behavior', 'dim_permission', 'dim_data']:
            dim_v = dimensions.get(dim_k)
            if not dim_v:
                continue
            pct = int((dim_v["score"] / dim_v["weight"]) * 100) if dim_v["weight"] > 0 else 100
            score_cls = "color:var(--success);" if pct >= 80 else ("color:var(--warning);" if pct >= 60 else "color:var(--danger);")
            dim_cards_html += f"""
            <div class="metric-card">
                <div class="metric-title">{dim_v['name']}</div>
                <div class="metric-val" style="{score_cls}">{dim_v['score']} <span style="font-size:12px;color:var(--text-sub);">/ {dim_v['weight']}分</span></div>
                <div style="font-size:11px;color:var(--text-sub);margin-top:4px;">扣减: -{dim_v['deduction']} 分 ({pct}%)</div>
            </div>
            """

    # 渲染 SDK 责任穿透 HTML
    sdk_rows = ""
    for sdk in sdk_attribution.get("sdk_list", []):
        rules_str = "、".join(sdk["rules"][:3])
        if len(sdk["rules"]) > 3:
            rules_str += f" 等 {len(sdk['rules'])} 项"
        sdk_rows += f"""
        <tr>
            <td><strong>{sdk['name']}</strong></td>
            <td><code>{sdk['count']} 处</code></td>
            <td><span style="font-weight:bold;color:#f87171;">{sdk['percentage']}%</span></td>
            <td>{rules_str}</td>
            <td style="font-size:11px;color:#cbd5e1;">{sdk['action_advice']}</td>
        </tr>
        """
    sdk_matrix_html = f"""
    <h4>第三方 SDK 责任穿透与侵权归因大盘 (SDK Accountability Matrix)</h4>
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <div style="font-size:13px;font-weight:bold;">
                责任切分：自研业务 <strong>{sdk_attribution.get('host_pct', 0)}%</strong> | 官方系统框架 <strong>{sdk_attribution.get('framework_pct', 0)}%</strong> | 商业第三方SDK <strong>{sdk_attribution.get('sdk_pct', 0)}%</strong>
            </div>
            <div style="font-size:12px;color:#94a3b8;">识别接入 SDK: {sdk_attribution.get('sdk_count', 0)} 家</div>
        </div>
        <!-- 三维责任切分条 (自研业务 / 官方系统兼容框架 / 商业第三方SDK) -->
        <div style="width:100%;height:12px;border-radius:6px;background:#1e293b;overflow:hidden;display:flex;margin-bottom:14px;">
            <div style="background:linear-gradient(90deg, #0284c7, #38bdf8);width:{sdk_attribution.get('host_pct', 0)}%;height:100%;" title="宿主自研业务: {sdk_attribution.get('host_pct', 0)}%"></div>
            <div style="background:linear-gradient(90deg, #059669, #10b981);width:{sdk_attribution.get('framework_pct', 0)}%;height:100%;" title="官方系统框架: {sdk_attribution.get('framework_pct', 0)}%"></div>
            <div style="background:linear-gradient(90deg, #e11d48, #fb7185);width:{sdk_attribution.get('sdk_pct', 0)}%;height:100%;" title="商业第三方SDK: {sdk_attribution.get('sdk_pct', 0)}%"></div>
        </div>
        <div style="font-size:12px;color:#cbd5e1;margin-bottom:14px;background:rgba(255,255,255,0.03);padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.08);">
            <strong>合规穿透审计意见：</strong>{sdk_attribution.get('accountability_verdict', '')}
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width:25%;">SDK 名称 / 供应商</th>
                    <th style="width:12%;">违规调用数</th>
                    <th style="width:12%;">风险占比</th>
                    <th style="width:25%;">触碰工信部红线</th>
                    <th style="width:26%;">法务合规处置建议</th>
                </tr>
            </thead>
            <tbody>
                {sdk_rows if sdk_rows else '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">未检测出第三方商业 SDK 越界调用</td></tr>'}
            </tbody>
        </table>
    </div>
    """

    fuse_notice_html = f"""
    <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); border-radius: 12px; padding: 14px 18px; margin-bottom: 20px; color: #fca5a5; font-size: 13px;">
        <strong>[!] 触发工信部核心红线一票否决熔断降级：</strong> {fuse_reason}
    </div>
    """ if is_fused else ""

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>AppGuard-AI 移动应用隐私合规与SDK安全体检报告 - {app_name}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card-bg: #111827;
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-sub: #9ca3af;
            --accent-blue: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{ max-width: 1050px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
            font-family: ui-monospace, monospace;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-medium {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .overview-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 16px;
        }}
        .metric-title {{ font-size: 12px; color: var(--text-sub); }}
        .metric-val {{ font-size: 24px; font-weight: 800; font-family: ui-monospace, monospace; margin-top: 4px; }}
        .score-circle {{
            width: 90px;
            height: 90px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            font-weight: 900;
            font-family: ui-monospace, monospace;
            background: rgba(56, 189, 248, 0.1);
            border: 3px solid var(--accent-blue);
            color: var(--accent-blue);
        }}
        .remediation-box {{
            background: rgba(56, 189, 248, 0.08);
            border-left: 4px solid var(--accent-blue);
            padding: 12px 16px;
            border-radius: 0 10px 10px 0;
            margin: 14px 0;
            font-size: 13px;
            line-height: 1.6;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 12px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background: rgba(255,255,255,0.04); color: var(--text-sub); }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: rgba(255, 255, 255, 0.08);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-title">
                <h2>AppGuard-AI · 基于国标场景先验与合规大模型的移动应用端云双轨智审报告</h2>
            </div>
            <div>
                <span class="badge badge-medium">对标 GB/T 35273-2020 规范</span>
            </div>
        </div>

        {fuse_notice_html}

        <div class="card" style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h3 style="margin: 0 0 6px 0;">{app_name} <span style="font-size: 14px; color: var(--text-sub);">({package_name})</span></h3>
                <div style="font-size: 13px; color: var(--text-sub);">
                    TargetSDK: <strong>{target_sdk}</strong> · 待审有效载荷: <strong>{payload_str}</strong> · 申请权限数: <strong>{len(permissions)}</strong> 项 · 审计耗时: <strong>{elapsed:.2f}s</strong>
                </div>
                <div style="margin-top: 8px; font-weight: 700; font-size: 14px;">
                    最终合规裁定: <span>{risk_level}</span>
                </div>
            </div>
            <div class="score-circle">
                {score}
            </div>
        </div>

        <h4>四维合规健康度基准 (4-Tier WCI Index)</h4>
        <div class="overview-grid">
            {dim_cards_html}
        </div>

        {sdk_matrix_html}

        <h4>工信部专项红线违规调用明细 ({len(findings)} 项)</h4>
        {findings_html if findings else '<div class="card" style="color:var(--success);text-align:center;font-weight:700;">恭喜！未在目标安装包中检测出已知工信部红线违规调用。</div>'}
    </div>
</body>
</html>
"""
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    return report_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 app_guard_scanner.py <path_to_apk>")
        sys.exit(1)
    run_audit(sys.argv[1])
