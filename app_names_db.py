# -*- coding: utf-8 -*-
"""
AppGuard-AI 移动应用中文/品牌名称知识库
覆盖主流应用、逆向开发工具、以及测试机常用包名
"""

APP_NAMES_MAP = {
    # 常用开发与逆向神器
    "mark.via": "Via 浏览器 (极速轻量标杆)",
    "com.lemurbrowser.exts": "狐猴浏览器 (双核/扩展支持)",
    "bin.mt.plus": "MT 管理器 (移动逆向分析)",
    "bin.mt.termex": "MT 终端 (Termex)",
    "com.catchingnow.andfiles.helper": "AndroMeld 传输助手",
    "com.junge.algorithmAide": "算法助手 (Hook动态分析)",
    "com.tsng.hidemyapplist": "隐秘应用列表 (Hide My Applist)",
    "github.tornaco.android.thanos": "灭霸 (Thanos 后台管理)",
    "org.lsposed.manager": "LSPosed 框架管理器",
    "io.github.chsbuffer.revancedxposed": "ReVanced Xposed",
    "io.github.vvb2060.magisk": "Magisk (面具管理)",
    "moe.shizuku.privileged.api": "Shizuku (系统API授权)",
    "ru.zdevs.zarchiver.pro": "ZArchiver Pro (专业解压)",
    "com.rarlab.rar": "RAR 压缩工具",
    "com.fileunzip.zxwknight": "极速解压专家",
    "com.github.android": "GitHub Mobile",
    "com.techbajao.htmleditor": "HTML 代码编辑器",
    "com.omarea.vtools": "Scene 工具箱 (性能调度)",
    "x.muxue.pro": "慕雪工具箱",
    "com.coderstory.toolkit": "开发者箱",
    "com.luckyzyx.luckytool": "LuckyTool 系统增强",
    "icu.nullptr.polyglot": "Polyglot 多语言环境",
    "gr.nikolasspyr.integritycheck": "Play 完整性检测器",
    "org.samo_lego.canta": "Canta 卸载清理工具",
    "top.hookvip.pro": "VIP 注入器",
    "com.jsxposed.x": "JS Xposed 模块",
    "com.github.tianma8023.xposed.smscode": "验证码自动提取模块",
    "lzlnb.cnm.hook": "玩偶 Hook 模块",
    "com.close.hook.ads": "开屏广告跳过 (Hook助手)",
    "chti.helper.cozyhookassistant": "CozyHook 辅助助手",
    "me.teble.xposed.autodaily": "自动日常签到助手",
    "com.noobexon.xposedfakelocation": "模拟定位助手",
    "dev.fzer0x.pokegocontrole": "虚拟摇杆定位",
    "com.surcumference.fingerprintpay": "指纹支付助手",
    "com.reveny.vbmetafix.service": "VBMeta 修复服务",
    "ru.bluecat.novpndetectenhanced": "VPN 探测增强版",
    "com.install.appinstall.xl": "极速安装器",
    "cn.xyner.tools": "芯语工具箱",
    "com.tudou.tool": "土豆工具箱",
    "me.build": "Build 构造工具",

    # 网络工具与代理
    "com.kunk.singbox": "Sing-Box (网络代理)",
    "com.github.metacubex.clash.meta": "Clash Meta",
    "com.nebula.clashmi": "ClashMi 代理工具",
    "com.follow.clash": "Follow Clash",
    "me.neko.lotus": "Lotus (NekoBox Core)",
    "moe.nb4a": "NekoBox for Android",
    "org.torproject.torbrowser": "Tor 洋葱隐私浏览器",
    "com.brave.browser": "Brave 隐私浏览器",
    "org.zwanoo.android.speedtest": "Speedtest 测速大师",
    "com.shcm.jscsy": "极速测速仪",
    "io.github.wifi_password_manager": "WiFi 密码管理器",
    "org.telegram.messenger": "Telegram",
    "org.telegram.auxiliary": "Telegram 辅助助手",
    "com.discord": "Discord",
    "com.twitter.android": "X (原 Twitter)",
    "com.whatsapp": "WhatsApp",
    "com.facebook.katana": "Facebook",
    "com.instagram.android": "Instagram",
    "com.reddit.frontpage": "Reddit",

    # 电商购物与本地生活
    "com.shizhuang.duapp": "得物 (Dewu)",
    "com.jingdong.app.mall": "京东商城",
    "com.taobao.taobao": "手机淘宝",
    "com.xunmeng.pinduoduo": "拼多多",
    "com.taobao.idlefish": "闲鱼 (二手交易)",
    "com.cainiao.wireless": "菜鸟裹裹 (电商物流)",
    "com.hd.hdshop": "华润万家 (万象商业)",
    "com.eg.android.AlipayGphone": "支付宝",
    "hk.alipay.wallet": "AlipayHK (支付宝香港)",
    "com.tongcheng.android": "同程旅行",
    "ctrip.android.view": "携程旅行",
    "com.greenpoint.android.mc10086.activity": "中国移动营业厅",
    "com.sinovatech.unicom.ui": "中国联通营业厅",
    "com.chinamobile.mcloud": "中国移动和彩云",
    "com.hbsclj.uth": "联通沃家庭",
    "com.cststaxinquiry.queryt": "个人所得税助手",
    "com.icbc": "中国工商银行",
    "cn.com.henansoft.tripbus.mj.jm": "公交地铁乘车码",

    # 社交、资讯与短视频
    "com.tencent.mm": "微信 (WeChat)",
    "com.tencent.mobileqq": "腾讯 QQ",
    "com.tencent.androidqqmail": "QQ 邮箱",
    "com.sina.weibo": "新浪微博",
    "com.xingin.xhs": "小红书",
    "com.ss.android.ugc.aweme": "抖音",
    "com.zhiliaoapp.musically": "TikTok (国际版)",
    "com.smile.gifmaker": "快手",
    "tv.danmaku.bili": "哔哩哔哩 (Bilibili)",
    "me.iacn.biliroaming": "哔哩漫游 (BiliRoaming)",
    "com.bilibili.comic": "哔哩哔哩漫画",
    "bc.bzmh": "包子漫画",
    "jp.pxv.android": "Pixiv (插画艺术社区)",
    "com.pinterest": "Pinterest",
    "com.jina.todayanimeimage": "今日动漫",

    # 影音娱乐与云盘
    "com.tencent.qqmusic": "QQ 音乐",
    "com.luna.music": "汽水音乐 (抖音音乐)",
    "com.google.android.apps.youtube.music": "YouTube Music",
    "com.lemon.lv": "剪映 (专业视频剪辑)",
    "com.xunlei.downloadprovider": "迅雷 (高速下载)",
    "com.baidu.netdisk": "百度网盘",
    "com.pikcloud.pikpak": "PikPak 私密云盘",
    "com.mfcloudcalculate.networkdisk": "魔方云盘",
    "com.xiaofeiji.app.disk": "小飞机网盘",
    "com.wn.app.np": "玩偶网盘",
    "com.xproducer.yingshiai": "影视 AI 大师",
    "com.xa.ba": "追剧达人",
    "me.feimeng.vip": "追剧影视 VIP",
    "ru.tech.imageresizershrinker": "Image Toolbox (图片处理)",
    "com.zhenxiang.superimage.pro": "SuperImage Pro (画质超分辨率)",
    "com.drdisagree.colorblendr": "ColorBlendr (主题配色)",

    # 阅读与学习办公
    "com.qidian.QDReader": "起点读书",
    "com.dragon.read": "番茄免费小说",
    "com.xigua.reader": "西瓜免费小说",
    "com.faloo.BookReader4Android": "飞卢小说",
    "com.suqi8.oshin": "欧神小说",
    "cn.wps.moffice_eng": "WPS Office (办公套件)",
    "com.microsoft.office.outlook": "Microsoft Outlook",
    "com.One.WoodenLetter": "纯纯写作 (Markdown)",
    "com.able.wisdomtree": "智慧树 (知到在线教育)",
    "com.chaoxing.mobile": "超星学习通",
    "com.yinshibai.chaoxingx": "学习通辅助工具",
    "cn.com.chsi.chsiapp": "学信网 (官方学历查询)",
    "com.wisedu.cpdaily": "今日校园",
    "com.klcxkj.zqxy": "掌上校园",
    "cn.com.yunma.school.app": "云马智慧校园",
    "org.wikipedia": "维基百科 (Wikipedia)",
    "com.canva.editor": "Canva 可画 (平面设计)",

    # AI 人工智能与前沿模型
    "com.deepseek.chat": "DeepSeek (深度求索 AI)",
    "com.moonshot.kimichat": "Kimi 智能助手 (月之暗面)",
    "ai.perplexity.comet": "Perplexity Comet AI",
    "ai.perplexity.app.android": "Perplexity 智能搜索",
    "ai.x.grok": "Grok AI (xAI)",
    "com.google.android.apps.labs.language.tailwind": "NotebookLM (Google AI)",

    # 金融量化与 Web3
    "com.tradingview.tradingviewapp": "TradingView (行情图表分析)",
    "com.okinc.okex.gp": "OKX (欧易数字资产)",
    "com.binance.dev": "Binance (币安)",
    "com.bybit.app": "Bybit (数字交易)",
    "com.gateio.gateio": "Gate.io (芝麻开门)",
    "com.gate.web3dex": "Gate Web3 DEX",
    "io.metamask": "MetaMask (小狐狸 Web3 钱包)",

    # 手机游戏与应用中心
    "com.tencent.qqgame.xq": "天天象棋 (腾讯互动娱乐)",
    "com.tencent.tmgp.supercell.clashofclans": "部落冲突 (Clash of Clans)",
    "com.neowizgames.game.browndust2": "棕色尘埃2 (BrownDust 2)",
    "com.RoamingStar.BlueArchive.bilibili": "碧蓝档案 (Blue Archive)",
    "com.taptap": "TapTap 游戏社区",
    "com.xmcy.hykb": "好游快爆",
    "com.upgadata.up7723": "7723 游戏盒",
    "com.coolapk.market": "酷安 (数码极客社区)",
    "com.wandoujia.phoenix2": "豌豆荚应用市场",
    "cm.aptoide.pt": "Aptoide 国际应用商店",
    "org.fdroid.fdroid": "F-Droid 开源应用中心",
    "com.aurora.store": "Aurora Store (Google镜像)",
    "com.uptodown": "Uptodown 应用商店",
    "com.nearme.gamecenter": "欢太游戏中心",
    "com.kooapps.pianotiles2gp": "钢琴块2 (Piano Tiles 2)",
    "com.easybrain.sudoku.android": "经典数独 (Sudoku)",
    "com.fortress.sim": "要塞战争模拟",

    # 系统增强与厂商功能
    "net.oneplus.widget": "一加桌面天气小组件",
    "com.oneplus.note": "一加便签",
    "com.oneplus.soundrecorder": "一加录音机",
    "com.photo.android.camera": "一加哈苏影像相机",
    "com.oplus.consumerIRApp": "ColorOS 红外遥控",
    "com.coloros.translate": "欢太智能翻译",
    "com.oplus.riderMode": "ColorOS 骑行模式",
    "com.byyoung.setting": "系统深度设置增强",
    "fun.fpa": "面具快应用伴侣 (FPA)",
    "have.fun": "欢喜盒子",
    "xmnh.soulfrog": "灵魂青蛙",
    "com.lockscreenfy.keyking": "锁屏密码管家",
    "com.findphonefy.clap": "拍手寻机助手",
    "com.samruston.buzzkill": "BuzzKill 通知管理器",
    "com.wander.android.wallpaper": "星空动态壁纸",
    "com.viewblocker.jrsen": "弹窗拦截大师",
    "com.bycalendar.mfrl": "随手万年历",
    "com.audio.shesheng": "舍声录音剪辑",
    "eu.hxreborn.phdp": "Pixel 原生增强插件",
    "com.rezvorck.tiktokplugin": "TikTok 换区插件",
    "info.muge.appshare": "AppShare 应用互传",
    "com.huotan.tianji": "天机排盘",
    "com.xtl.qxzhtdgj": "奇门乾坤罗盘",
    "com.zhulu.zhulubazipaipan": "逐鹿八字排盘",
    "com.shcm.sjthjlc": "通话记录助手",
    "com.h3110w0r1d.phoenix": "Phoenix 极速内核",
    "com.UCMobile": "UC 浏览器",
    "com.quark.browser": "夸克浏览器",
    "com.autonavi.minimap": "高德地图",
    "com.google.android.safetycore": "Google Play 安全核心",
    "com.google.android.apps.authenticator2": "Google 身份验证器",
    "com.google.android.apps.translate": "Google 翻译",
    "com.google.android.deskclock": "Google 时钟",
    "com.google.android.apps.magazines": "Google 新闻与杂志",
    "com.google.android.apps.docs": "Google 云端硬盘",
    "com.google.android.apps.docs.editors.docs": "Google 文档",
    "com.google.android.apps.subscriptions.red": "YouTube 会员服务",
    "com.google.android.contactkeys": "Google 联系人密匙",
    "com.google.android.verifier": "Google Play 安全验证",
    "com.google.android.apps.adm": "Google 查找我的设备",
    "com.google.android.apps.accessibility.voiceaccess": "Voice Access 语音控制",
    "com.tencent.android.marvis": "腾讯 Marvis 研发助手",
    "com.qq.qcloud": "腾讯云助手",
    "com.huati": "话题网客户端",
    "me.neko.fckvip": "净化去广告工具",
    "uni.UNI58B2D89": "五音助手 (无损音乐下载播放)",
    "com.commercepro.and": "商户管家 (CommercePro 移动收银)",
    "com.larus.nova": "ColorOS 桌面智能组件 (Nova)",
    "com.larus.wolf": "ColorOS 桌面智能组件 (Wolf)",
    "com.xjs.ehviewer": "EhViewer" 
}

def resolve_app_name(pkg: str) -> str:
    """根据包名解析易读的应用品牌名称"""
    if pkg in APP_NAMES_MAP:
        return APP_NAMES_MAP[pkg]
    
    # 针对 WebAPK 处理
    if "webapk" in pkg:
        return "WebAPK PWA 轻应用"
    
    # 智能启发式推导
    parts = pkg.split('.')
    last_seg = parts[-1]
    second_seg = parts[-2] if len(parts) > 1 else ""
    
    # 去除无意义的包名后缀 (如 app, android, pro, lite)
    candidate = last_seg
    if candidate.lower() in ["app", "android", "mobile", "client", "ui", "main", "release"] and second_seg:
        candidate = second_seg
    
    # 格式化为词组
    formatted = candidate.replace('_', ' ').replace('-', ' ').title()
    return formatted

def estimate_audit_time(pkg: str, file_size_mb: float = 0.0, mode: str = "deep") -> int:
    """
    基于待审核心载荷 (DEX 字节码 + 清单) 与反编译真实计算复杂度测算耗时 (秒)
    实测标定模型：
    - Via 极简 (2.1MB DEX, 1 DEX, 3.4k类): ~4s
    - 天天象棋 资源型轻量 (7.5MB DEX, 2 DEX, 9k类): ~14s
    - 拼多多 复杂电商 (17.2MB DEX, 4 DEX, 2.8w类): ~28s
    - 菜鸟裹裹 重度混淆 (33.9MB DEX, 6 DEX, 4.5w类): ~1分15秒 (75s)
    - 航母级超大型 Super-App (15~30+ DEX, 10w~20w类, 200MB+ 展开字节码):
      - 支付宝 (21 DEX, 17.7w类, 260MB解压字节码): 全量深度 ~5分钟 (300s) / 答辩速检 ~30s
      - 微信 (28 DEX, 21w类): 全量深度 ~4分50秒 (290s) / 答辩速检 ~30s
      - 手机淘宝 (22 DEX, 18w类): 全量深度 ~4分30秒 (270s) / 答辩速检 ~30s
      - 抖音 / TikTok (35+ DEX): 全量深度 ~4分40秒 (280s) / 答辩速检 ~30s
    """
    # A. 答辩路演速检模式 (聚焦 classes1~3.dex 核心入口与 SDK 载荷)
    if mode == "quick":
        if pkg in ["mark.via", "com.drdisagree.colorblendr", "org.zwanoo.android.speedtest", "fun.fpa", "net.oneplus.widget"]:
            return 4
        if pkg == "com.tencent.qqgame.xq":
            return 14
        if pkg == "com.xunmeng.pinduoduo":
            return 22
        if pkg == "com.cainiao.wireless":
            return 32
        if pkg in ["com.eg.android.AlipayGphone", "com.tencent.mm", "com.taobao.taobao", "com.ss.android.ugc.aweme", "com.zhiliaoapp.musically", "com.jingdong.app.mall"]:
            return 30
        payload_info = estimate_audit_payload(pkg, file_size_mb)
        payload_mb = payload_info.get("payload_mb", 4.0)
        return max(4, min(35, int(4 + payload_mb * 0.8)))

    # B. 全量深度代码审计模式 (全 DEX 语法树深度反编译与 XRef 图谱交联)
    calibrated_deep_times = {
        "mark.via": 4,
        "com.drdisagree.colorblendr": 5,
        "org.zwanoo.android.speedtest": 4,
        "fun.fpa": 4,
        "net.oneplus.widget": 4,
        "com.tencent.qqgame.xq": 14,
        "com.xunmeng.pinduoduo": 28,
        "com.cainiao.wireless": 75,
        "tv.danmaku.bili": 95,
        "com.xingin.xhs": 85,
        "com.jingdong.app.mall": 230,
        "com.taobao.taobao": 270,
        "com.ss.android.ugc.aweme": 280,
        "com.zhiliaoapp.musically": 280,
        "com.tencent.mm": 290,
        "com.eg.android.AlipayGphone": 300, # 支付宝实测 5 分钟 (21 个 DEX，17.7 万类)
    }
    if pkg in calibrated_deep_times:
        return calibrated_deep_times[pkg]
    
    # 未知应用基于有效载荷非线性阶梯测算 (彻底移除 120s 虚假封顶)
    payload_info = estimate_audit_payload(pkg, file_size_mb)
    payload_mb = payload_info.get("payload_mb", 4.0)
    
    if payload_mb <= 3.0:
        sec = 4 + int(payload_mb * 1.2)
    elif payload_mb <= 10.0:
        sec = 8 + int(payload_mb * 1.5)
    elif payload_mb <= 25.0:
        sec = 16 + int(payload_mb * 1.6)
    elif payload_mb <= 40.0:
        sec = 30 + int(payload_mb * 1.8)
    elif payload_mb <= 60.0:
        sec = 120 + int((payload_mb - 40) * 8.5)
    else:
        sec = 270 + int((payload_mb - 60) * 2.0)
    
    return max(4, sec)

def format_estimate_time(seconds: int) -> str:
    """将秒数格式化为人类友好的预估时间 (如 ~4秒, ~38秒, ~1分15秒, ~5分钟)"""
    if seconds < 60:
        return f"~{seconds}秒"
    minutes = seconds // 60
    rem = seconds % 60
    if rem > 0:
        return f"~{minutes}分{rem}秒"
    else:
        return f"~{minutes}分钟"

def estimate_audit_payload(pkg: str, file_size_mb: float = 0.0) -> dict:
    """
    测算应用中真正需要进行合规静态反编译的核心有效载荷 (DEX 字节码 + AndroidManifest.xml)
    自动过滤占全包 70%~90% 的音视频、3D 贴图与 Native .so 素材
    """
    # 实测真机解包精确载荷表 (压缩传输载荷 / 解压字节码)
    calibrated = {
        "mark.via": 2.1,
        "com.drdisagree.colorblendr": 2.1,
        "com.tencent.qqgame.xq": 7.5,
        "com.xunmeng.pinduoduo": 17.2,
        "com.cainiao.wireless": 33.9,
        "com.zhiliaoapp.musically": 89.2,
        "com.ss.android.ugc.aweme": 88.5,
        "com.tencent.mm": 65.4,
        "com.eg.android.AlipayGphone": 58.2,
        "com.taobao.taobao": 62.0,
        "tv.danmaku.bili": 45.8,
        "com.xingin.xhs": 38.6
    }
    
    if pkg in calibrated:
        payload_mb = calibrated[pkg]
    elif file_size_mb > 0:
        if file_size_mb <= 5:
            payload_mb = round(file_size_mb * 0.75, 1)
        elif file_size_mb <= 30:
            payload_mb = round(file_size_mb * 0.50, 1)
        elif file_size_mb <= 80:
            payload_mb = round(file_size_mb * 0.35, 1)
        elif file_size_mb <= 150:
            payload_mb = round(file_size_mb * 0.28, 1)
        else:
            payload_mb = round(min(92.0, file_size_mb * 0.25), 1)
    else:
        payload_mb = 4.5
    
    filter_ratio = "0%"
    if file_size_mb > payload_mb and file_size_mb > 0:
        pct = int((1 - payload_mb / file_size_mb) * 100)
        filter_ratio = f"{pct}%"
        
    return {
        "payload_mb": payload_mb,
        "total_mb": round(file_size_mb, 1),
        "filter_ratio": filter_ratio
    }
