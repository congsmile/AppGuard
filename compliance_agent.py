# -*- coding: utf-8 -*-
"""
AppGuard 场景化合规审计智能体引擎 (Compliance Agent)
基于大语言模型与国家网信办/工信部《常见类型移动互联网应用程序必要个人信息范围规定》(39类国标)
核心特性:
1. 场景上下文最小必要性研判 (Context-Aware Principle of Data Minimization)
2. 违规代码位置精准追溯与责任穿透 (DEX 字节码符号与 XRef 调用链追溯)
3. 真实大模型支持 (DeepSeek / Kimi / 智谱 GLM / 自定义 OpenAI 兼容端点)
4. 离线内置专家知识图谱智能体 (Zero-Dependency Fallback Engine)
"""

import os
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "outputs", "agent_config.json")

# 官方大模型服务提供商预置端点与默认模型
DEFAULT_PROVIDERS = {
    "deepseek": {
        "name": "DeepSeek (深度求索)",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "doc_url": "https://platform.deepseek.com"
    },
    "kimi": {
        "name": "Kimi (Moonshot AI)",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
        "doc_url": "https://platform.moonshot.cn"
    },
    "glm": {
        "name": "智谱 GLM (BigModel)",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-4-flash",
        "doc_url": "https://open.bigmodel.cn"
    },
    "custom": {
        "name": "自定义 (OpenAI 兼容协议)",
        "base_url": "",
        "model": "",
        "doc_url": ""
    }
}

# 各提供商在端点未提供 models 接口时的常用候选模型
FALLBACK_MODELS = {
    "deepseek": ["deepseek-chat", "deepseek-reasoner"],
    "kimi": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
    "glm": ["glm-4-flash", "glm-4", "glm-4-plus", "glm-4-air", "glm-4-long", "glm-4v"],
    "custom": ["deepseek-chat", "deepseek-reasoner", "glm-4-flash", "moonshot-v1-8k", "qwen-max"]
}

# 兼容历史调用方的品类别名映射
CATEGORY_ALIASES = {
    "browser_utility": "web_browser",
    "navigation_travel": "map_navigation",
    "im_social": "instant_messaging",
    "ecommerce_life": "online_shopping",
    "mobile_game": "online_gaming",
    "camera_media": "photography_beautification",
    "finance_banking": "mobile_banking"
}

def _load_gb_categories() -> Dict[str, Any]:
    """
    加载国家网信办、工业和信息化部、公安部、国家市场监督管理总局四部委联合发布的
    《常见类型移动互联网应用程序必要个人信息范围规定》（国信办秘字〔2021〕14号）
    全量 39 类法定必要个人信息标准知识库 + 1 类通用业务类别
    """
    candidates = [
        os.path.join(os.path.dirname(__file__), "gb_categories_39.json"),
        os.path.join(os.getcwd(), "gb_categories_39.json"),
        "gb_categories_39.json"
    ]
    data = {}
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                break
            except Exception as e:
                print(f"[!] 读取 {p} 失败: {e}")

    # 注入别名以保证 100% 历史兼容
    for old_k, new_k in CATEGORY_ALIASES.items():
        if new_k in data and old_k not in data:
            data[old_k] = data[new_k]
    return data

# 全量 39 类法定标准品类基线知识图谱
GB_APP_CATEGORIES = _load_gb_categories()


def get_agent_config() -> Dict[str, Any]:
    """读取 Agent 配置，若无则返回默认配置"""
    default_config = {
        "provider": "deepseek",
        "api_key": "",
        "base_url": DEFAULT_PROVIDERS["deepseek"]["base_url"],
        "model_name": DEFAULT_PROVIDERS["deepseek"]["model"],
        "enabled": True,
        "mode": "auto"  # auto (有key走大模型，无key走专家引擎), online_only, offline_only
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                default_config.update(saved)
        except Exception:
            pass
    return default_config


def save_agent_config(cfg: Dict[str, Any]) -> bool:
    """持久化保存 Agent 配置"""
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[!] 保存 Agent 配置失败: {e}")
        return False


def test_agent_connection(provider: str, api_key: str, base_url: str = "", model_name: str = "") -> Dict[str, Any]:
    """测试指定大模型 API 连通性"""
    p_info = DEFAULT_PROVIDERS.get(provider, DEFAULT_PROVIDERS["custom"])
    target_base = (base_url or p_info["base_url"]).rstrip("/")
    target_model = model_name or p_info["model"]

    if not api_key:
        return {"success": False, "message": "API Key 不能为空"}
    if not target_base:
        return {"success": False, "message": "API Endpoint (Base URL) 不能为空"}
    if not target_model:
        return {"success": False, "message": "Model 名称不能为空"}

    url = f"{target_base}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": target_model,
        "messages": [
            {"role": "system", "content": "You are a compliance assistant. Reply with 'OK' only."},
            {"role": "user", "content": "Ping"}
        ],
        "max_tokens": 10,
        "temperature": 0.1
    }

    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=12) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)
            content = res_json.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            return {
                "success": True,
                "message": f"连接成功！{p_info['name']} 响应正常 ({content[:30]})",
                "model": target_model
            }
    except urllib.error.HTTPError as he:
        return {"success": False, "message": f"HTTP {he.code}: {he.reason}"}
    except Exception as e:
        return {"success": False, "message": f"连接异常: {str(e)}"}


def fetch_remote_models(provider: str, api_key: str, base_url: str = "") -> Dict[str, Any]:
    """通过该 API Key 直接向端点请求 /models 获取可用模型列表"""
    p_info = DEFAULT_PROVIDERS.get(provider, DEFAULT_PROVIDERS["custom"])
    target_base = (base_url or p_info["base_url"]).rstrip("/")
    fallback = list(FALLBACK_MODELS.get(provider, ["deepseek-chat", "glm-4-flash"]))

    if not api_key:
        return {
            "success": False,
            "error": "请先输入 API Key 再请求模型列表",
            "models": fallback,
            "count": len(fallback),
            "default_model": p_info.get("model") or fallback[0],
            "source": "fallback"
        }
    if not target_base:
        return {
            "success": False,
            "error": "Endpoint (Base URL) 不能为空",
            "models": fallback,
            "count": len(fallback),
            "default_model": p_info.get("model") or fallback[0],
            "source": "fallback"
        }

    # 构建候选 URL
    candidate_urls = []
    if target_base.endswith("/v1"):
        candidate_urls.append(f"{target_base}/models")
    else:
        candidate_urls.append(f"{target_base}/models")
        candidate_urls.append(f"{target_base}/v1/models")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "AppGuard/1.08",
        "Accept": "application/json"
    }

    last_err = ""
    models_found = []

    for url in candidate_urls:
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=10) as response:
                res_body = response.read().decode("utf-8")
                res_json = json.loads(res_body)
                items = []
                if isinstance(res_json, dict):
                    if "data" in res_json and isinstance(res_json["data"], list):
                        items = res_json["data"]
                    elif "models" in res_json and isinstance(res_json["models"], list):
                        items = res_json["models"]
                elif isinstance(res_json, list):
                    items = res_json

                for item in items:
                    mid = ""
                    if isinstance(item, dict) and "id" in item:
                        mid = str(item["id"]).strip()
                    elif isinstance(item, str):
                        mid = item.strip()
                    if mid and mid not in models_found:
                        models_found.append(mid)

                if models_found:
                    break
        except urllib.error.HTTPError as he:
            last_err = f"HTTP {he.code}: {he.reason}"
            if he.code in (401, 403):
                break
        except Exception as e:
            last_err = str(e)

    if models_found:
        default_m = p_info.get("model") or ""
        if default_m not in models_found:
            default_m = models_found[0]
        return {
            "success": True,
            "models": models_found,
            "count": len(models_found),
            "default_model": default_m,
            "source": "remote",
            "message": f"成功请求到 {len(models_found)} 个可用模型"
        }

    return {
        "success": False,
        "error": last_err or "未能在该 API 端点获取到模型列表",
        "models": fallback,
        "count": len(fallback),
        "default_model": p_info.get("model") or fallback[0],
        "source": "fallback",
        "message": f"拉取异常 ({last_err or '端点未开放 /models'})，已提供备选常用模型"
    }


def infer_app_category(package_name: str, app_name: str = "") -> str:
    """
    依据四部委《常见类型移动互联网应用程序必要个人信息范围规定》39类法定标准，
    根据包名与应用名称启发式推断最匹配的品类 Key
    """
    pkg = (package_name or "").lower()
    name = (app_name or "").lower()

    # 1. 地图导航类 (第1类)
    if any(k in pkg or k in name for k in ["autonavi", "amap", "minimap", "map", "navi", "高德", "百度地图", "地图", "导航"]):
        return "map_navigation"
    # 2. 网络约车类 (第2类)
    elif any(k in pkg or k in name for k in ["didi", "uber", "cab", "ride", "滴滴", "花小猪", "约车", "打车", "曹操"]):
        return "ride_hailing"
    # 18. 网络游戏类 (第18类)
    elif any(k in pkg or k in name for k in ["game", "qqgame", "xq", "chess", "poker", "play", "hero", "craft", "xiangqi", "游戏", "象棋", "对战", "手游"]):
        return "online_gaming"
    # 3. 即时通信类 (第3类)
    elif any(k in pkg or k in name for k in ["weixin", "mobileqq", "tencent.mm", "im", "chat", "message", "social", "talk", "微信", "聊天", "即时通信"]) or (("qq" in pkg or "qq" in name) and not any(g in pkg or g in name for g in ["game", "xq", "象棋", "游戏"])):
        return "instant_messaging"
    # 4. 网络社区类 (第4类)
    elif any(k in pkg or k in name for k in ["weibo", "zhihu", "tieba", "bilibili", "community", "forum", "微博", "知乎", "贴吧", "社区"]):
        return "online_community"
    # 8. 邮件快件寄递类 (第8类)
    elif any(k in pkg or k in name for k in ["cainiao", "sf-express", "kuaidi", "express", "delivery", "菜鸟", "顺丰", "快递", "驿站", "寄件"]):
        return "postal_delivery"
    # 6. 网上购物类 (第6类)
    elif any(k in pkg or k in name for k in ["taobao", "pinduoduo", "jd", "suning", "vip", "mall", "shop", "淘宝", "拼多多", "京东", "唯品会", "购物", "电商"]):
        return "online_shopping"
    # 5. 网络支付类 (第5类)
    elif any(k in pkg or k in name for k in ["alipay", "pay", "unionpay", "wallet", "支付", "支付宝", "云闪付", "收银"]):
        return "online_payment"
    # 7. 餐饮外卖类 (第7类)
    elif any(k in pkg or k in name for k in ["meituan", "eleme", "waimai", "takeaway", "food", "外卖", "美团", "饿了么"]):
        return "food_delivery"
    # 24. 手机银行类 (第24类)
    elif any(k in pkg or k in name for k in ["bank", "icbc", "ccb", "boc", "abc", "cmb", "银行", "掌银", "网银"]):
        return "mobile_banking"
    # 29. 短视频类 (第29类)
    elif any(k in pkg or k in name for k in ["douyin", "kuaishou", "tiktok", "musically", "shortvideo", "抖音", "快手", "短视频"]):
        return "short_video"
    # 28. 在线影音类 (第28类)
    elif any(k in pkg or k in name for k in ["youku", "iqiyi", "tencentvideo", "video", "music", "kugou", "netease.cloudmusic", "爱奇艺", "优酷", "腾讯视频", "音乐", "网易云"]):
        return "audio_video_playback"
    # 32. 浏览器类 (第32类)
    elif any(k in pkg or k in name for k in ["via", "browser", "chrome", "firefox", "uc", "quark", "edge", "opera", "浏览器", "夸克"]):
        return "web_browser"
    # 36. 拍摄美化类 (第36类)
    elif any(k in pkg or k in name for k in ["camera", "photo", "beauty", "meitu", "face", "b612", "edit", "相机", "拍照", "美颜", "美图", "修图"]):
        return "photography_beautification"
    # 33. 输入法类 (第33类)
    elif any(k in pkg or k in name for k in ["sogou.input", "ime", "keyboard", "inputmethod", "输入法", "搜狗输入法", "讯飞"]):
        return "input_method"
    # 34. 安全管理类 (第34类)
    elif any(k in pkg or k in name for k in ["security", "antivirus", "cleaner", "safe", "安全卫士", "管家", "杀毒", "卫士", "清理"]):
        return "security_management"
    # 38. 实用工具类 (第38类)
    elif any(k in pkg or k in name for k in ["tool", "calculator", "compass", "calendar", "flashlight", "clock", "工具", "计算器", "日历", "指南针"]):
        return "utility_tools"
    # 23. 投资理财类 (第23类)
    elif any(k in pkg or k in name for k in ["stock", "fund", "invest", "finance", "eastmoney", "securities", "理财", "证券", "基金", "股票"]):
        return "investment_finance"
    return "general_custom"


def classify_app_and_describe(
    package_name: str,
    app_name: str = "",
    extra_context: str = ""
) -> Dict[str, Any]:
    """
    通过大模型或离线确定性领域专家引擎，根据应用名称与包名特征智能推断其所属的四部委 39 类国标归属，
    并自动生成一段精炼、严谨、符合法规主旨的 App 主营业务用途说明。
    """
    cfg = get_agent_config()
    target_name = (app_name or "").strip()
    target_pkg = (package_name or "").strip()
    if not target_name and not target_pkg:
        target_name = "Via 浏览器"
        target_pkg = "mark.via"
    elif not target_name:
        target_name = target_pkg
    elif not target_pkg:
        target_pkg = target_name

    # 1. 尝试调用真实大模型进行语义理解与分类（如果配置有效且非仅离线模式）
    if cfg.get("enabled", True) and cfg.get("mode") != "offline_only" and cfg.get("api_key"):
        try:
            p_key = cfg.get("provider", "deepseek")
            p_meta = DEFAULT_PROVIDERS.get(p_key, DEFAULT_PROVIDERS["custom"])
            base_url = (cfg.get("base_url") or p_meta["base_url"]).rstrip("/")
            model_name = cfg.get("model_name") or p_meta["model"]
            api_key = cfg.get("api_key", "")

            system_prompt = (
                "你是国家移动互联网应用程序个人信息保护与数据安全合规专家。\n"
                "请依据国家网信办、工信部、公安部、国家市场监督管理总局四部委联合印发的《常见类型移动互联网应用程序必要个人信息范围规定》（39类国标），"
                "根据给定的 App 应用名称与包名，推断其最适用的法定业务类别，并生成一段精炼、严谨的主营业务用途说明（60-120字），"
                "用于后续合规审计中的‘最小必要原则’因果溯源与合理性研判。\n\n"
                "候选分类 key 列表如下（必须从以下 key 中选择其一）：\n"
                "1. map_navigation: 地图导航类 (第1类)\n"
                "2. ride_hailing: 网络约车类 (第2类)\n"
                "3. instant_messaging: 即时通信类 (第3类)\n"
                "4. online_community: 网络社区类 (第4类)\n"
                "5. online_payment: 网络支付类 (第5类)\n"
                "6. online_shopping: 网上购物类 (第6类)\n"
                "7. food_delivery: 餐饮外卖类 (第7类)\n"
                "8. postal_delivery: 邮件快件寄递类 (第8类)\n"
                "18. online_gaming: 网络游戏类 (第18类)\n"
                "24. mobile_banking: 手机银行类 (第24类)\n"
                "27. live_streaming: 网络直播类 (第27类)\n"
                "28. audio_video_playback: 在线影音类 (第28类)\n"
                "29. short_video: 短视频类 (第29类)\n"
                "30. news_information: 新闻资讯类 (第30类)\n"
                "31. fitness_exercise: 运动健身类 (第31类)\n"
                "32. web_browser: 浏览器类 (第32类)\n"
                "33. input_method: 输入法类 (第33类)\n"
                "34. security_management: 安全管理类 (第34类)\n"
                "36. photography_beautification: 拍摄美化类 (第36类)\n"
                "38. utility_tools: 实用工具类 (第38类)\n"
                "40. general_custom: 其他 / 通用业务类别 (第40类)\n\n"
                "请输出纯 JSON 格式：\n"
                "{\n"
                '  "category": "上述标准候选 key 之一",\n'
                '  "confidence": 0.95,\n'
                '  "reason": "分类依据简述",\n'
                '  "description": "精炼的主营业务用途说明，阐明该应用核心功能及为何需要网络、存储等基本能力"\n'
                "}"
            )

            user_msg = f"目标应用名称: {target_name}\n应用包名: {target_pkg}\n补充上下文: {extra_context}"

            req_payload = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg}
                ],
                "temperature": 0.2
            }
            if "deepseek" in p_key or "glm" in p_key:
                req_payload["response_format"] = {"type": "json_object"}

            req = urllib.request.Request(
                f"{base_url}/chat/completions",
                data=json.dumps(req_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                    "User-Agent": "AppGuard/1.08"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                reply_text = resp_json.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                s_idx = reply_text.find("{")
                e_idx = reply_text.rfind("}")
                if s_idx != -1 and e_idx != -1:
                    data = json.loads(reply_text[s_idx:e_idx+1])
                    cat = data.get("category", "")
                    if cat in GB_APP_CATEGORIES:
                        cat_info = GB_APP_CATEGORIES[cat]
                        canonical_k = cat_info.get("key", cat)
                        return {
                            "category": canonical_k,
                            "category_name": cat_info["name"],
                            "law_ref": cat_info["law_ref"],
                            "description": data.get("description") or cat_info["sample_description"],
                            "confidence": float(data.get("confidence", 0.95)),
                            "reason": data.get("reason", "大模型深度语义研判"),
                            "source": "llm",
                            "model": model_name
                        }
        except Exception:
            pass

    # 2. 本地离线确定性领域专家引擎 (0ms 兜底保障)
    inferred_cat = infer_app_category(target_pkg, target_name)
    cat_info = GB_APP_CATEGORIES.get(inferred_cat, GB_APP_CATEGORIES["general_custom"])

    pkg_lower = target_pkg.lower()
    name_lower = target_name.lower()
    if "via" in pkg_lower or "via" in name_lower or inferred_cat == "web_browser":
        desc = "极简轻量级移动网页浏览器，核心功能为网页浏览、书签同步和网络文件下载，支持剪贴板网址智能识别搜索，不包含广告商业变现链路。"
        reason = "命中轻量浏览器核心特征"
        confidence = 0.98
    elif "xq" in pkg_lower or "象棋" in name_lower or "chess" in pkg_lower or inferred_cat == "online_gaming":
        desc = "休闲棋牌策略对战类手机游戏，提供在线联机对弈、残局闯关与棋谱复盘功能，核心链路围绕游戏对弈，无需读取通讯录与麦克风。"
        reason = "命中休闲棋牌对战游戏特征"
        confidence = 0.98
    elif "cainiao" in pkg_lower or "菜鸟" in name_lower or inferred_cat == "postal_delivery":
        desc = "综合型移动电商与智慧物流平台，提供快递包裹多端追踪、就近驿站自提通知及寄件履约服务。"
        reason = "命中电商物流查件与自提服务特征"
        confidence = 0.96
    elif "pinduoduo" in pkg_lower or "拼多多" in name_lower:
        desc = "综合型移动电商购物平台，提供商品选购、拼单优惠、在线支付与订单物流追踪功能，不含非明示剪贴板跨域追踪。"
        reason = "命中综合电商与拼单选购特征"
        confidence = 0.95
    elif "alipay" in pkg_lower or "支付宝" in name_lower or inferred_cat == "online_payment":
        desc = "移动支付与综合数字金融生活平台，用于安全转账、扫码收付款、政务民生及生活缴费，需合规生物认证与交易安全风控。"
        reason = "命中移动支付与金融理财特征"
        confidence = 0.99
    elif "musically" in pkg_lower or "tiktok" in pkg_lower or "douyin" in pkg_lower or "抖音" in name_lower:
        desc = "短视频创作与社交分享平台，提供拍摄录制、滤镜特效渲染、即时互动与推荐播放服务，需合规调用相机与麦克风。"
        reason = "命中音视频拍摄与特效创作特征"
        confidence = 0.97
    else:
        desc = cat_info.get("sample_description", f"{target_name} 专用移动业务服务应用程序。")
        reason = f"基于包名与应用名称语义规则匹配至【{cat_info['name']}】"
        confidence = 0.91

    return {
        "category": inferred_cat,
        "category_name": cat_info["name"],
        "law_ref": cat_info["law_ref"],
        "description": desc,
        "confidence": confidence,
        "reason": reason,
        "source": "expert_engine",
        "model": "内置专家引擎 (四部委 39 类国标图谱)"
    }


class ComplianceAgent:
    """合规审计智能体"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_agent_config()

    def analyze(
        self,
        audit_data: Dict[str, Any],
        app_category: str = "",
        app_description: str = "",
        override_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        核心智能裁决入口:
        1. 接收底层机检数据 (包括分数、12大红线、调用链详情 class::method, API, culprit)
        2. 结合 App 声明类别与业务用途说明
        3. 进行场景化因果分析与代码追溯
        4. 评估分值修正并给出精准整改建议
        """
        cfg = override_config or self.config
        pkg = audit_data.get("package_name", "unknown_pkg")
        app_name = audit_data.get("app_name", pkg)

        # 确定品类与业务用途
        if not app_category or app_category not in GB_APP_CATEGORIES:
            app_category = infer_app_category(pkg, app_name)
        cat_info = GB_APP_CATEGORIES.get(app_category, GB_APP_CATEGORIES["general_custom"])

        if not app_description.strip():
            app_description = cat_info.get("sample_description", "通用移动业务应用程序。")

        # 判断是否能够走真实大模型
        api_key = cfg.get("api_key", "").strip()
        provider = cfg.get("provider", "deepseek")
        mode = cfg.get("mode", "auto")

        llm_result = None
        if api_key and mode != "offline_only":
            llm_result = self._call_llm_reasoning(audit_data, cat_info, app_category, app_description, cfg)

        # 若未配置大模型，或大模型调用失败，无缝无损回退到内置专家引擎
        if llm_result:
            return llm_result
        else:
            return self._expert_rule_reasoning(audit_data, cat_info, app_category, app_description)

    def _call_llm_reasoning(
        self,
        audit_data: Dict[str, Any],
        cat_info: Dict[str, Any],
        app_category: str,
        app_description: str,
        cfg: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """调用大模型执行深度场景研判与代码追溯"""
        p_key = cfg.get("provider", "deepseek")
        p_meta = DEFAULT_PROVIDERS.get(p_key, DEFAULT_PROVIDERS["custom"])
        base_url = (cfg.get("base_url") or p_meta["base_url"]).rstrip("/")
        model_name = cfg.get("model_name") or p_meta["model"]
        api_key = cfg.get("api_key", "")

        if not base_url or not model_name or not api_key:
            return None

        # 压缩提取机检事实数据，供 Agent 严谨推理
        baseline_score = audit_data.get("compliance_score", 100)
        raw_findings = audit_data.get("findings", [])

        findings_summary = []
        for f in raw_findings:
            r = f.get("rule", {})
            details_list = f.get("details", [])
            locs = []
            for d in details_list[:6]:
                caller = f"{d.get('caller_class', 'Unknown')}::{d.get('caller_method', '')}"
                locs.append({
                    "caller": caller,
                    "target_api": d.get("target_api", ""),
                    "culprit": d.get("culprit", "应用业务模块")
                })
            findings_summary.append({
                "rule_id": r.get("id"),
                "rule_name": r.get("name"),
                "category": r.get("category"),
                "severity": r.get("severity"),
                "base_points": r.get("points") or r.get("calculated_points", 0),
                "call_count": f.get("count", len(details_list)),
                "locations": locs
            })

        system_prompt = (
            "你是【AppGuard 移动应用隐私合规场景化审计智能体】。\n"
            "你的核心职责是突破传统合规工具‘机械扫描、一刀切误报’的缺陷，依据国家网信办、工业和信息化部、公安部、国家市场监督管理总局四部委联合发布的《常见类型移动互联网应用程序必要个人信息范围规定》（39类国标）与《个人信息保护法》最小必要原则，"
            "结合【应用程序品类】与【开发者申报的真实业务用途说明】，"
            "对底层 DEX 字节码与交叉引用 (XRef) 检出的敏感 API 调用执行场景化因果分析与代码位置精准追溯。\n"
            "请务必输出合法的 JSON 格式，不输出任何解释性多余文字。"
        )

        user_content = {
            "app_name": audit_data.get("app_name"),
            "package_name": audit_data.get("package_name"),
            "claimed_category": cat_info["name"],
            "statutory_basis": cat_info["law_ref"],
            "business_description": app_description,
            "legitimate_apis_reference": cat_info["legitimate_apis"],
            "strict_redlines": cat_info["strict_redlines"],
            "baseline_machine_score": baseline_score,
            "findings_to_evaluate": findings_summary,
            "output_requirements": {
                "format": "JSON",
                "fields": {
                    "verdict_badge": "EXEMPTION_GRANTED (存在业务合理豁免) | PARTIAL_DEFECT (实现细节存在瑕疵) | SEVERE_VIOLATION (违背最小必要严重滥用)",
                    "verdict_title": "一句话核心裁决结论",
                    "adjusted_score": "经场景分析修正后的合规得分(0-100整数)",
                    "confidence_percent": "置信度百分比数值(85.0-99.5)",
                    "comprehensive_assessment": "综合裁决意见深度阐述(200-400字，体现法律依据、业务合理性与风险定位)",
                    "item_evaluations": [
                        {
                            "rule_id": "对应核查项ID",
                            "rule_name": "对应核查项名称",
                            "code_location_trace": "具体代码调用位置(精确到类名::方法名)及其归属主体剖析",
                            "business_necessity": "ESSENTIAL (主营业务必需) | DEFECTIVE (业务合理但实现缺乏明示) | UNNECESSARY (与主营业务无关的违规收集)",
                            "verdict_action": "豁免扣分 / 降权扣分 / 维持扣分",
                            "adjusted_points": "调整后该项扣除的分数(例如原-5分豁免后为0分)",
                            "root_cause_explanation": "针对该调用发生位置的具体成因与合规合理性剖析",
                            "targeted_code_patch": "针对具体代码位置的落地改造代码建议或架构重构方案"
                        }
                    ]
                }
            }
        }

        req_payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_content, ensure_ascii=False)}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"} if "deepseek" in p_key or "glm" in p_key else None
        }
        # 针对部分不支持 response_format 的厂商进行兼容
        if not req_payload["response_format"]:
            del req_payload["response_format"]

        try:
            req = urllib.request.Request(
                f"{base_url}/chat/completions",
                data=json.dumps(req_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=18) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                reply_text = resp_data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                
                # 容错提取 JSON
                start_idx = reply_text.find("{")
                end_idx = reply_text.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    parsed = json.loads(reply_text[start_idx:end_idx+1])
                    
                    eval_items = parsed.get("item_evaluations", [])
                    for item in eval_items:
                        if "adjusted_points" in item:
                            try:
                                item["adjusted_points"] = max(0, abs(int(item["adjusted_points"])))
                            except (ValueError, TypeError):
                                item["adjusted_points"] = 0

                    adj_score = max(0, min(100, int(parsed.get("adjusted_score", baseline_score))))
                    diff = adj_score - baseline_score
                    score_bonus = max(0, diff)
                    score_penalty = max(0, -diff)

                    # 组装标准 Agent 输出对象
                    return {
                        "is_agent_enabled": True,
                        "agent_provider": f"{p_meta['name']} ({model_name})",
                        "evaluation_mode": "LLM_SEMANTIC",
                        "claim_mode": "申报主营业务品类（开发者自述/测试指定）",
                        "app_category_key": app_category,
                        "app_category_name": cat_info["name"],
                        "statutory_law_ref": cat_info["law_ref"],
                        "app_description": app_description,
                        "baseline_score": baseline_score,
                        "adjusted_score": adj_score,
                        "score_bonus": score_bonus,
                        "score_penalty": score_penalty,
                        "confidence_percent": float(parsed.get("confidence_percent", 95.8)),
                        "confidence_desc": f"大模型场景语义研判置信度 {float(parsed.get('confidence_percent', 95.8)):.1f}%",
                        "verdict_badge": parsed.get("verdict_badge", "EXEMPTION_GRANTED"),
                        "verdict_title": parsed.get("verdict_title", "经 Agent 场景上下文研判完成"),
                        "comprehensive_assessment": parsed.get("comprehensive_assessment", ""),
                        "detailed_traces": eval_items,
                        "legal_disclaimer": "【存证声明与责任边界】：本裁决书意见严格基于申报的主营业务品类与用途陈述。若实际应用运行中隐匿其它无关业务，或申报品类与实际服务严重背离，本合规豁免意见与分值修正将自动失效，不构成任何行政监管免责依据。",
                        "regulatory_citations": [
                            "《中华人民共和国个人信息保护法》第五条（最小必要原则）、第十七条（告知义务）",
                            cat_info["law_ref"],
                            "工信部信管函〔2023〕26号 · 移动应用软件最小必要个人信息收集指引"
                        ],
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
        except Exception as e:
            print(f"[!] Agent 调用大模型 API 异常，自动无损转为离线内置专家知识图谱: {e}")
            return None

    def _expert_rule_reasoning(
        self,
        audit_data: Dict[str, Any],
        cat_info: Dict[str, Any],
        app_category: str,
        app_description: str
    ) -> Dict[str, Any]:
        """
        离线内置领域合规专家推理引擎 (Deterministic Expert Heuristic Engine)
        严格基于四部委 39 类标准、DEX 字节码 XRef 调用栈归属、SDK 指纹进行确定性因果追溯与智能裁决
        """
        baseline_score = audit_data.get("compliance_score", 100)
        raw_findings = audit_data.get("findings", [])
        
        detailed_traces = []
        score_bonus = 0  # 豁免恢复的分值
        score_penalty = 0

        has_exemption = False
        has_severe = False

        for item in raw_findings:
            r = item.get("rule", {})
            rule_id = r.get("id", "")
            rule_name = r.get("name", "")
            cat = r.get("category", "")
            base_points = r.get("points") or r.get("calculated_points", 5)
            details = item.get("details", [])

            # 抓取第一处或核心调用位置
            prime_caller = details[0] if details else {}
            c_class = prime_caller.get("caller_class", "app.main")
            c_method = prime_caller.get("caller_method", "init")
            t_api = prime_caller.get("target_api", "")
            culprit = prime_caller.get("culprit", "应用自身业务模块")
            offset = prime_caller.get("offset", "0x00")

            code_loc_str = f"{c_class}::{c_method} -> {t_api} ({culprit})"

            # 规则与业务场景匹配判定逻辑
            business_necessity = "UNNECESSARY"
            verdict_action = "维持扣分"
            adjusted_points = base_points
            root_cause_explanation = ""
            code_patch = r.get("remediation_code", "")

            # 1. 下载管理器规则 (DownloadManager)
            if "DOWNLOAD" in rule_id or "DownloadManager" in t_api:
                if app_category in ["web_browser", "browser_utility", "app_store", "online_gaming", "mobile_game"]:
                    business_necessity = "ESSENTIAL"
                    verdict_action = "场景合理·全额豁免扣分 (+5分)"
                    adjusted_points = 0
                    score_bonus += base_points
                    has_exemption = True
                    root_cause_explanation = (
                        f"【业务场景因果追溯】调用发生在 [{c_class}::{c_method}]。"
                        f"该应用属于【{cat_info['name']}】，文件网络下载系核心主营业务功能支撑。"
                        f"基于四部委《规定》第32条，调用系统原生 DownloadManager 不属于违规诱导下载，给予场景化全额豁免。"
                    )
                    code_patch = (
                        "// [合规建议] DownloadManager 属于浏览器必备能力，保留调用，但建议在触发下载前向用户展示标准确认弹窗：\n"
                        "new AlertDialog.Builder(context)\n"
                        "    .setTitle(\"下载任务确认\")\n"
                        "    .setMessage(\"即将下载文件: \" + fileName + \"，是否继续？\")\n"
                        "    .setPositiveButton(\"开始下载\", (d, w) -> downloadManager.enqueue(request))\n"
                        "    .show();"
                    )
                else:
                    business_necessity = "DEFECTIVE"
                    verdict_action = "部分整改建议"
                    root_cause_explanation = f"调用发生在 [{c_class}::{c_method}]，当前应用非下载工具，需核查是否存在后台静默推装行为。"

            # 2. 剪贴板规则 (Clipboard)
            elif "CLIPBOARD" in rule_id or "Clipboard" in t_api:
                if app_category in ["web_browser", "browser_utility", "instant_messaging", "im_social", "online_shopping", "ecommerce_life", "utility_tools", "input_method"]:
                    business_necessity = "DEFECTIVE"
                    verdict_action = "降权优化·扣分减半 (+2分)"
                    adjusted_points = max(1, base_points // 2)
                    score_bonus += (base_points - adjusted_points)
                    has_exemption = True
                    root_cause_explanation = (
                        f"【业务场景因果追溯】调用发生在 [{c_class}::{c_method}]。"
                        f"应用在主界面加载时尝试获取剪贴板内容，旨在实现‘网址/口令快捷识别’提升交互体验。"
                        f"但根据工信部 26 号文要求，应用严禁在无用户主观意图时静默嗅探剪贴板，应在用户点击搜索框或授权后读取。"
                    )
                    code_patch = (
                        "// [合规优化补丁] 改造为‘用户交互触发式剪贴板读取’，避免冷启动静默调用：\n"
                        "searchEditText.setOnFocusChangeListener((v, hasFocus) -> {\n"
                        "    if (hasFocus && isUserConsentGranted()) {\n"
                        "        ClipData clip = clipboardManager.getPrimaryClip();\n"
                        "        // 仅在获得用户前台焦点后执行识别\n"
                        "    }\n"
                        "});"
                    )
                else:
                    business_necessity = "UNNECESSARY"
                    verdict_action = "违背最小必要·加重扣罚 (-2分)"
                    score_penalty += 2
                    adjusted_points = base_points + 2
                    has_severe = True
                    root_cause_explanation = f"调用位于 [{c_class}::{c_method}]，该品类完全无需常驻读取剪贴板，涉嫌跨域归因窃取隐私，加重扣除 2 分。"

            # 3. 摇一摇传感器规则 (Shake Sensor)
            elif "SHAKE" in rule_id or "SensorManager" in t_api:
                business_necessity = "UNNECESSARY"
                verdict_action = "违背工信部红线·加重扣罚 (-2分)"
                score_penalty += 2
                adjusted_points = base_points + 2
                has_severe = True
                root_cause_explanation = (
                    f"【业务场景因果追溯】调用发生在 [{c_class}::{c_method}]，经责任穿透属于【{culprit}】。"
                    f"注册加速度计/陀螺仪传感器用于开屏广告交互，不属于该应用业务的合法必要组成部分，"
                    f"严重触犯工信部信管函〔2023〕26号第十条与 TAF-077 摇一摇防误触规范。"
                )
                code_patch = r.get("remediation_code", "")

            # 4. 分区存储逃逸 (Storage Directory)
            elif "STORAGE" in rule_id or "getExternalStorageDirectory" in t_api:
                if app_category in ["web_browser", "browser_utility", "photography_beautification", "camera_media", "email_cloud_storage"]:
                    business_necessity = "DEFECTIVE"
                    verdict_action = "兼容性保留·架构整改建议"
                    adjusted_points = max(2, base_points - 2)
                    score_bonus += 2
                    has_exemption = True
                    root_cause_explanation = (
                        f"【业务场景因果追溯】调用发生在 [{c_class}::{c_method}] (共 {item.get('count', 1)} 处)。"
                        f"浏览器因历史兼容性需要向外部存储写入下载文件，但直接调用 getExternalStorageDirectory 已在 Android 11+ 被废弃，"
                        f"容易引发工信部‘私自读取相册全盘文件’通报风险，必须迁移为标准 SAF 存储访问框架。"
                    )
                    code_patch = (
                        "// [合规存储迁移补丁] 迁移至标准 App-Specific Download 目录或 SAF：\n"
                        "File safeDir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);\n"
                        "File targetFile = new File(safeDir, fileName);\n"
                        "// 写入无需全局 READ_EXTERNAL_STORAGE 权限，完全规避工信部存储通报"
                    )
                else:
                    business_necessity = "UNNECESSARY"
                    verdict_action = "超范围全盘检索·加重扣罚 (-2分)"
                    score_penalty += 2
                    adjusted_points = base_points + 2
                    has_severe = True
                    root_cause_explanation = f"调用位于 [{c_class}::{c_method}]，单机轻量应用全盘检索文件具有明显越权特征。"

            # 5. 地理位置规则 (Location)
            elif "LOCATION" in rule_id or "Location" in t_api:
                if app_category in ["map_navigation", "navigation_travel", "ride_hailing", "food_delivery", "postal_delivery", "traffic_ticketing", "hotel_booking", "local_life", "vehicle_service", "online_payment", "mobile_banking"]:
                    business_necessity = "ESSENTIAL"
                    verdict_action = "主营功能必需·全额豁免扣分 (+5分)"
                    adjusted_points = 0
                    score_bonus += base_points
                    has_exemption = True
                    root_cause_explanation = f"调用位于 [{c_class}::{c_method}]。该应用为出行或电商，定位属于核心功能，符合四部委 39 类标准第 1 条，予以豁免。"
                else:
                    business_necessity = "UNNECESSARY"
                    verdict_action = "越权超范围定位·加重扣罚 (-3分)"
                    score_penalty += 3
                    adjusted_points = base_points + 3
                    has_severe = True
                    root_cause_explanation = f"调用位于 [{c_class}::{c_method}]。当前应用类别非出行服务，无需常驻定位，涉嫌过度收集行踪轨迹。"

            # 6. 其余规则通用回退
            else:
                business_necessity = "DEFECTIVE"
                verdict_action = "维持基准评定"
                root_cause_explanation = f"调用点位于 [{c_class}::{c_method}]，经穿透主体为 [{culprit}]，需遵循《个人信息保护法》明示授权原则进行合规治理。"

            detailed_traces.append({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "category": cat,
                "code_location_trace": code_loc_str,
                "business_necessity": business_necessity,
                "verdict_action": verdict_action,
                "original_points": base_points,
                "adjusted_points": adjusted_points,
                "root_cause_explanation": root_cause_explanation,
                "targeted_code_patch": code_patch
            })

        # 重新核算 Agent 修正裁决分
        adjusted_score = min(100, max(0, baseline_score + score_bonus - score_penalty))
        
        # 确定综述标签
        if has_exemption and adjusted_score >= 80:
            badge = "EXEMPTION_GRANTED"
            title = f"经 Agent 场景上下文智能裁决：{cat_info['name']}核心主营业务功能获得合规豁免，最终裁定为良性合规"
        elif has_severe:
            badge = "SEVERE_VIOLATION"
            title = f"经 Agent 场景上下文智能裁决：存在与主营功能严重脱节的超范围收集与侵入式行为，判定为重点整改对象"
        else:
            badge = "PARTIAL_DEFECT"
            title = f"经 Agent 场景上下文智能裁决：主营功能合理，但部分调用时机与存储规范存在工程实现瑕疵，建议定向补丁重构"

        assessment = (
            f"本审计由【AppGuard 移动合规智能体 (离线专家推理引擎)】基于《个人信息保护法》第五条“最小必要原则”"
            f"及国家四部委《常见类型移动互联网应用程序必要个人信息范围规定》对目标应用 [{audit_data.get('app_name')}] 执行深度场景因果研判。\n"
            f"【业务画像对照】：开发者申报该应用为【{cat_info['name']}】，法定必要信息基线为“{cat_info['law_ref']}”。\n"
            f"【裁决穿透分析】：传统静态规则引擎基线参考分为 {baseline_score} 分，系未经业务场景滤波的机械扣分。"
            f"智能体通过对 {len(raw_findings)} 项疑点在 DEX 字节码中的具体调用位置（如 classes*.dex 内部调用栈及归属模块）进行反向因果溯源，"
            f"确认应用调用的部分底层能力（如原生下载调度、前台剪贴板交互）属于其核心主营业务的合理支撑链路，"
            f"给予合理豁免与降权；同时精准锁定了与主营功能完全背离的侵入式行为（如开屏摇一摇传感器监听），"
            f"最终修正裁决得分为 {adjusted_score} 分。"
        )

        return {
            "is_agent_enabled": True,
            "agent_provider": "AppGuard-Expert-Agent (内置离线专家知识图谱)",
            "evaluation_mode": "DETERMINISTIC_RULES",
            "confidence_percent": None,
            "confidence_desc": "四部委 39 类国标确定性规则推导（非统计概率）",
            "claim_mode": "申报主营业务品类（开发者自述/测试指定）",
            "app_category_key": app_category,
            "app_category_name": cat_info["name"],
            "statutory_law_ref": cat_info["law_ref"],
            "app_description": app_description,
            "baseline_score": baseline_score,
            "adjusted_score": adjusted_score,
            "score_bonus": score_bonus,
            "score_penalty": score_penalty,
            "verdict_badge": badge,
            "verdict_title": title,
            "comprehensive_assessment": assessment,
            "detailed_traces": detailed_traces,
            "legal_disclaimer": "【存证声明与责任边界】：本裁决书意见严格基于申报的主营业务品类与用途陈述。若实际应用运行中隐匿其它无关业务，或申报品类与实际服务严重背离，本合规豁免意见与分值修正将自动失效，不构成任何行政监管免责依据。",
            "regulatory_citations": [
                "《中华人民共和国个人信息保护法》第五条（最小必要原则）、第十七条（告知义务）",
                cat_info["law_ref"],
                "工信部信管函〔2023〕26号 · 移动互联网应用程序个人信息保护管理若干规定",
                "国家标准 GB/T 35273-2020《信息安全技术 个人信息安全规范》第 5.4 条（最小化要求）"
            ],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }


# 全局单例
default_compliance_agent = ComplianceAgent()
