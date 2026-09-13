# AppGuard · 移动互联网应用程序隐私合规审计与端云协同分析系统 (v1.0)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Android_8.0--16.0-orange.svg)](https://developer.android.com)
[![Standard](https://img.shields.io/badge/Standard-工信部信管函〔2023〕26号-red.svg)](https://www.miit.gov.cn/)

**AppGuard** 是一套面向移动互联网应用程序（Android APP）的高性能、动静双轨隐私合规审计与端云协同自动化测试系统。系统深度对标《中华人民共和国个人信息保护法》、工业和信息化部《关于进一步提升移动互联网应用服务能力的通知》（**工信部信管函〔2023〕26号**）及电信终端产业协会 **T/TAF 077.1-2022** 规范，解决传统合规检测中“静态逆向误报率高、动态分析依赖 Root 易被对抗、违规取证与监管法规脱节”三大行业瓶颈。

---

## 🌟 核心特性 (Key Features)

### 1. 静态深层 AST 逆向与调用链追踪 (Static AST Engine)
- **全格式脱壳与解析**：精准解析 `AndroidManifest.xml` (AXML)、DEX 字节码及资源索引表。
- **敏感 API 调用链定位**：逆向还原设备标识（IMEI/OAID/MAC）、地理位置、通讯录、剪贴板等高敏感 API 调用的真实调用栈上下文。
- **50+ 主流 SDK 指纹识别**：深度覆盖极光、个推、穿山甲、腾讯广点通、阿里云、高德、微信 OpenSDK 等第三方组件的静态特征。
- **12 项合规红线规则库**：内置依据工信部历次通报重点构建的规则库，覆盖强制索权、超范围收集、隐蔽自启动等典型违规场景。

### 2. 免 Root 端云协同真机沙箱 (Dynamic Sandbox Probe)
- **无侵入免 Root 监控**：基于 Android 底层 `AppOps` 审计探针与系统级事件流，在完全无需 Root 的真实量产机（支持最新 Android 14/15/16）上稳定运行，彻底规避反调试与反作弊 SDK 的环境检测。
- **“摇一摇”广告滥用实测**：内置自动化传感器注入引擎，通过毫秒级加速度与陀螺仪向量模拟，精准诱发并取证开屏“摇一摇”误触与流氓跳转。
- **后台偷跑与静默访问捕获**：实时监控应用在后台、熄屏或锁屏状态下的麦克风占用、相机静默唤醒、频繁广播自启动及剪贴板偷窥行为。

### 3. 动静双轨多维置信度评分机制 (Dual-Track Scoring Engine)
- **动静互验消歧**：结合静态代码“存在性”与动态沙箱“发生性”，避免静态“包含 SDK 未调用”导致的假阳性误报，同时弥补纯动态分析测试覆盖盲区。
- **100 分制四维合规健康度雷达**：
  - **权限最小化 (20%)**：危险权限按需申请、杜绝一次性强制全量索权。
  - **数据收集透明度 (25%)**：明示收集目的、敏感隐私数据访问前置授权。
  - **行为合规度 (35%)**：后台静默访问拦截、摇一摇跳转防误触、自启动抑制。
  - **SDK 治理度 (20%)**：第三方 SDK 共享与合规声明、非必要组件剥离。

### 4. Apple 级液态微晶毛玻璃控制台 (Apple-Style Console)
- 采用精美现代的微晶液态毛玻璃视觉风格，完全适配系统深色/浅色模式无缝切换。
- 具备真机 USB ADB 热插拔自适应感知能力，支持“通道 A（本地 APK 拖拽上传）”与“通道 B（真机已装 App 即插即测）”双轨工作流。

### 5. 高保真合规诊断与技术存证报告 (Compliance Report Generator)
- 一键导出独立的单文件交互式 HTML 诊断报告。
- 包含标的 APK 的 SHA-256 唯一指纹哈希存证、法规范号溯源、技术证据截图与逐项整改工程建议。

---

## 📐 系统架构 (System Architecture)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                 AppGuard Web Console (Apple Fluid Glass UI)            │
│  [Channel A: APK Drag & Drop]           [Channel B: Real-Device ADB]  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ REST API / Server-Sent Events
┌──────────────────────────────────▼─────────────────────────────────────┐
│                   AppGuard Core Dispatcher (server.py)                 │
│  - Device Topology Auto-Detection     - Dynamic Duration Estimation    │
│  - Task Queue & Lifecycle Management  - Dual-Track Arbitration Engine  │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
┌───────────────────▼──────────────┐   ┌─────────────▼───────────────────┐
│   Static AST Analysis Engine     │   │     Dynamic Sandbox Runner      │
│   (app_guard_scanner.py)         │   │     (sandbox_runner.py)         │
│ ├─ AXML/Manifest Manifest Parser │   │ ├─ Non-Root AppOps Probe Engine │
│ ├─ Smali/DEX CallGraph Tracing   │   │ ├─ Sensor Shake/Tilt Injection  │
│ ├─ SDK Signature Matcher (50+)   │   │ ├─ Background Leakage Sniffer   │
│ └─ MIIT 12-Redline Rule Engine   │   │ └─ Foreground Mock User Action  │
└───────────────────┬──────────────┘   └─────────────┬───────────────────┘
                    └────────────────┬───────────────┘
                                     │ Multi-dimensional Fusion
┌────────────────────────────────────▼───────────────────────────────────┐
│              Compliance Diagnostic & Evidence Report Generator         │
│                    (report_generator.py -> outputs/*.html)             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 12 大工信部红线审计矩阵 (MIIT Compliance Matrix)

| 规则编号 | 审计项名称 | 监管法规依据 | 检测模式 |
| :--- | :--- | :--- | :--- |
| `RULE_001` | 私自收集个人信息 | 《个人信息保护法》第13条 / 工信部26号文 | 静态 AST + 动态 AppOps |
| `RULE_002` | 超范围收集个人信息 | 《必要个人信息范围规定》/ 工信部26号文 | 静态 Manifest + 动态访问 |
| `RULE_003` | 违规使用个人信息 | 《个人信息保护法》第17条 / 工信部26号文 | 静态调用链分析 |
| `RULE_004` | 强制用户使用定向推送 | 工信部信管函〔2023〕26号 第六条 | 静态 SDK 检索 |
| `RULE_005` | 欺骗误导强迫用户 | 工信部信管函〔2023〕26号 第八条 | 静态 Manifest + 动态模拟 |
| `RULE_006` | “摇一摇”乱跳转与过度敏感 | T/TAF 077.1-2022 / 工信部26号文 第十条 | 动态传感器注入实测 |
| `RULE_007` | 应用频繁自启动和关联唤醒 | 工信部信管函〔2023〕26号 第九条 | 静态广播接收器 + 动态探针 |
| `RULE_008` | 频繁索取权限 / 权限滥用 | 工信部信管函〔2023〕26号 第七条 | 静态声明 + 动态频度统计 |
| `RULE_009` | 强制、频繁、过度索取权限 | 工信部信管函〔2020〕164号 / 26号文 | 静态 + 动态联合裁定 |
| `RULE_010` | 隐蔽后台读取剪贴板 | 《个人信息保护法》/ 工信部26号文 第七条 | 动态 AppOps 后台探针 |
| `RULE_011` | 无感知录音与麦克风偷跑 | 《个人信息保护法》第28条（敏感信息） | 动态 AppOps 静默录音监测 |
| `RULE_012` | 偷拍与后台相机隐秘调用 | 《个人信息保护法》第28条（敏感信息） | 动态 AppOps 摄像头监测 |

---

## 🚀 快速开始 (Quick Start)

### 1. 环境准备
- **操作系统**：macOS / Linux / Windows
- **Python 版本**：Python 3.9+
- **Android 工具**：安装并配置好 `adb`（Android Debug Bridge）至环境变量
- **测试设备**（可选）：Android 8.0 ~ 16.0 真实设备或模拟器（开启“开发者选项”及“USB 调试”）

### 2. 克隆与安装依赖
```bash
git clone https://github.com/jkahsbs/AppGuard.git
cd AppGuard

pip install -r requirements.txt
```

### 3. 启动审计服务
```bash
python server.py
```
服务默认启动在 `http://127.0.0.1:8080`。

### 4. 访问与测试
打开浏览器访问 `http://127.0.0.1:8080`：
- **通道 A（APK 上传）**：直接将 `.apk` 安装包拖拽至页面上传区，系统将自动解构并执行动静双轨审计。
- **通道 B（真机即测）**：通过 USB 连接 Android 设备并信任调试授权，控制台将自动枚举设备已安装的第三方应用，点击目标应用即可一键启动真机探针测试。

---

## 📂 仓库目录结构 (Repository Structure)

```text
AppGuard/
├── app_guard_scanner.py     # 静态 AST 逆向引擎与 12 大工信部合规红线规则库
├── sandbox_runner.py        # 免 Root 动态沙箱探针（AppOps、传感器注入、后台监控）
├── app_names_db.py          # 知名应用特征库与耗时动态预估模型
├── report_generator.py      # 高保真合规诊断存证 HTML 报告生成器
├── server.py                # 端云调度后端与 Web RESTful 控制接口
├── templates/
│   └── index.html           # Apple 微晶毛玻璃风格前端交互控制台
├── requirements.txt         # 核心运行依赖清单
├── LICENSE                  # Apache 2.0 开源协议
└── README.md                # 项目架构与使用文档
```

---

## ⚖️ 免责声明 (Disclaimer)

1. 本项目仅供应用开发者进行自身产品的隐私合规自查、高校科研教学及安全合规技术研究使用。
2. 严禁利用本项目从事任何非法逆向破解、漏洞利用或侵犯他人知识产权与个人隐私的活动。对于使用者因违反当地法律法规所导致的任何直接或间接后果，本项目维护者不承担任何责任。

---

## 📄 开源许可证 (License)

本项目基于 [Apache-2.0 License](LICENSE) 协议开源。
