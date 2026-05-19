package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.deception.WebDeceptionController;
import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.util.DefenderService; // ✨ 引入防卫大臣
import com.skuldlens.top.ninganx.honeypot.util.IPLookupService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

/**
 *
 * 动态加载页、LRU缓存、指纹采集、交互劫持、以及防扫描封禁逻辑。
 */
@Controller
public class PhantomStreamEngine implements ErrorController {

    private static final Logger log = LoggerFactory.getLogger(PhantomStreamEngine.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private final AuditService auditService;
    private final IPLookupService ipLookupService;
    private final WebDeceptionController webHoneypot;
    private final DefenderService defenderService;

    private static final String LONGCAT_API_KEY = ""; // 大模型的token令牌
    private static final String LONGCAT_URL = ""; // 大模型的接口地址
    private static final int HONEYPOT_PORT = 8080;

    public PhantomStreamEngine(AuditService auditService,
                               IPLookupService ipLookupService,
                               WebDeceptionController webHoneypot,
                               DefenderService defenderService) {
        this.auditService = auditService;
        this.ipLookupService = ipLookupService;
        this.webHoneypot = webHoneypot;
        this.defenderService = defenderService;
    }

    private final Map<String, String> phantomLruCache = Collections.synchronizedMap(new LinkedHashMap<String, String>(16, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, String> eldest) { return size() > 10; }
    });

    /**
     * 加载页 快速返回
     */
    @RequestMapping(value = "/error", produces = "text/html;charset=UTF-8")
    @ResponseBody
    public String catchAllBait(HttpServletRequest request, HttpServletResponse response) {
        int port = request.getServerPort();
        if (port != HONEYPOT_PORT || !webHoneypot.isRunning()) {
            response.setStatus(404);
            return "<html><body style='text-align:center;padding:50px;'><h1>404 Not Found</h1></body></html>";
        }

        // 如果IP已经被封禁，直接切断连接
        String ip = getClientIp(request);
        if (defenderService.isBanned(ip)) {
            response.setStatus(403);
            return "<html><body style='background:#000;color:red;padding:50px;font-family:monospace;'>" +
                    "<h1>[ACCESS DENIED]</h1><p>访问频率过高，稍后再试</p></body></html>";
        }

        String uri = (String) request.getAttribute("jakarta.servlet.error.request_uri");
        if (uri == null) uri = request.getRequestURI();

        log.info("路径探测: {} | 发起者 IP: {}", uri, ip);

        return "<html><head><title>加载中...</title>" +
                "<link href='https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/css/bootstrap.min.css' rel='stylesheet'>" +
                "<style>body{background:#fff;display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;margin:0;}" +
                ".spinner-border{width:3rem;height:3rem;color:#0d6efd;}.text{margin-top:15px;color:#666;font-family:sans-serif;}</style></head><body>" +
                "<div class='spinner-border' role='status'></div><div class='text'>系统资源初始化中，请稍候...</div>" +
                "<script>" +
                "  fetch('/public/api/phantom/generate?uri=' + encodeURIComponent('" + uri + "'))" +
                "    .then(r => r.text())" +
                "    .then(html => { if(html) { document.open(); document.write(html); document.close(); } });" +
                "</script></body></html>";
    }

    /**
     * 受保护的动态生成接口
     */
    @GetMapping(value = "/public/api/phantom/generate", produces = "text/html;charset=UTF-8")
    @ResponseBody
    public String generateBaitContent(@RequestParam String uri, HttpServletRequest request) throws Exception {
        if (!webHoneypot.isRunning()) return "";

        String ip = getClientIp(request);

        // 如果扫描过快，限制该ip的访问
        if (defenderService.checkAndBan(ip)) {
            log.warn("检测到恶意扫描，IPS已将其拦截", ip);
            return "<div class='container mt-5 text-center'><h3 class='text-danger'>403 Forbidden</h3><p>Security Policy Triggered.</p></div>";
        }

        if (phantomLruCache.containsKey(uri)) {
            log.info("缓存命中，正在构建: {}", uri);
            return phantomLruCache.get(uri);
        }

        log.info("正在消耗 Token 为 IP {} 编织诱捕页面: {}", ip, uri);
        String systemPrompt = "你是一个精通全栈开发与社会工程学的心理专家。请根据提供的 URL 路径，为该业务场景编织一个逻辑自洽、极其真实且【高度可交互】的后台管理页面。\n" +
                "【核心任务】：\n" +
                "1. 场景对齐：必须根据路径内容（如 /blog, /order, /user, /cloud）决定页面功能。如果是 /blog，应编织博客评论管理或敏感草稿审核；如果是 /cloud，应编织云资源调度面板。\n" +
                "2. 诱导策略：严禁生搬硬套 SSH 或 API Key。必须根据【当前业务逻辑】设计最合理的陷阱。例如：\n" +
                "   - 博客类：引诱其输入常用的‘社交账号’以同步评论，或提供‘外部数据库备份’引诱其输入常用凭据。\n" +
                "   - 用户类：提供‘二级管理员授权’界面，引诱其输入常用的密保手机或备份邮箱。\n" +
                "   - 电商类：提供‘支付接口测试’或‘退款审计’，引诱其输入常用的支付 Token 或密钥。\n" +
                "3. UI 架构：必须使用现代化的 Bootstrap 5 布局（包含 Sidebar 和 Navbar），且必须包含 ECharts 渲染的【数据看板】（统计图表占位符），营造高价值系统的视觉压迫感。\n" +
                "4. 交互细节：按钮必须带 hover 效果（card-hover），输入框必须带 Placeholder。页面要看起来不仅能看，而且真的能点。\n" +
                "5. 隐秘彩提醒：在 HTML 注释或隐藏的文本中，留下暗示‘当前系统存在配置不当’的线索，引导攻击者在表单中进行特定尝试。\n" +
                "6. 技术限制：仅输出 <body> 内部代码。绝对禁止 Markdown 标记，不准有任何解释文字，直接输出 HTML ！";
        try {
            String aiBody = callAiSync(systemPrompt, "攻击路径：" + uri);
            String fullHtml = buildFullHtml(uri, aiBody);
            phantomLruCache.put(uri, fullHtml);
            return fullHtml;
        } catch (Exception e) {
            log.error("页面构建失败: {}", e.getMessage());
            return "<div class='container mt-5'><div class='alert alert-danger'>Critical System Error: Resource Exhausted</div></div>";
        }
    }

    private String buildFullHtml(String title, String bodyContent) {
        // 净化标题逻辑
        String cleanTitle = title.startsWith("/") ? title.substring(1) : title;
        if (cleanTitle.isEmpty()) cleanTitle = "System_Terminal";

        // 编织核心 HTML 结构
        return "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <meta charset='UTF-8'>\n" +
                "    <title>" + cleanTitle + "</title>\n" +
                "    \n" +
                "    <link href='https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/css/bootstrap.min.css' rel='stylesheet'>\n" +
                "    <style>body{background:#f8f9fa;min-height:100vh;padding:40px; font-family: sans-serif;}</style>\n" +
                "    <script>\n" +
                "        // 数据遥测上报逻辑\n" +
                "        const report = async (action, data) => {\n" +
                "            const dpr = window.devicePixelRatio || 1;\n" +
                "            const w = Math.floor(screen.width * dpr); \n" +
                "            const h = Math.floor(screen.height * dpr);\n" +
                "            const fp = {res: w + 'x' + h, dpr, lang: navigator.language, tz: Intl.DateTimeFormat().resolvedOptions().timeZone};\n" +
                "            try {\n" +
                "                await fetch('/public/api/phantom/telemetry', {\n" +
                "                    method: 'POST',\n" +
                "                    headers: {'Content-Type': 'application/json'},\n" +
                "                    body: JSON.stringify({action, uri: window.location.pathname, fingerprint: JSON.stringify(fp), data: JSON.stringify(data)})\n" +
                "                });\n" +
                "            } catch(e) {}\n" +
                "        };\n" +
                "        \n" +
                "        // 自动上报页面载入事件\n" +
                "        window.onload = () => report('PAGE_LOAD', {uri: window.location.pathname});\n" +
                "        \n" +
                "        // 劫持点击事件，捕获表单输入\n" +
                "        document.addEventListener('click', async (e) => {\n" +
                "            const btn = e.target.closest('button') || (e.target.tagName === 'BUTTON' ? e.target : null);\n" +
                "            if (btn) {\n" +
                "                const allInputs = {};\n" +
                "                document.querySelectorAll('input, select, textarea').forEach(el => {\n" +
                "                    if (el.id || el.name) allInputs[el.id || el.name] = el.value;\n" +
                "                });\n" +
                "                const actionName = 'CLICK_' + (btn.id || btn.innerText.trim().substring(0, 10));\n" +
                "                await report(actionName, allInputs);\n" +
                "            }\n" +
                "        }, true);\n" +
                "    </script>\n" +
                "</head>\n" +
                "<body>\n" +
                "    \n" +
                "    " + bodyContent.replaceAll("(?i)<(/?)(!DOCTYPE|html|head|body|meta|title)([^>]*)>", "") + "\n" +
                "</body>\n" +
                "</html>";
    }

    @PostMapping("/public/api/phantom/telemetry")
    @ResponseBody
    public Map<String, Object> captureTelemetry(@RequestBody Map<String, Object> payload, HttpServletRequest request) {
        if (!webHoneypot.isRunning()) return Map.of("status", "error");

        String ip = getClientIp(request);
        String location = ipLookupService.getLocationStr(ip);
        double[] coords = ipLookupService.getCoordinates(ip);

        String detail = String.format("PHANTOM_INTEL | Path: %s | Action: %s | Fingerprint: %s | Input: %s",
                payload.get("uri"), payload.get("action"), payload.get("fingerprint"), payload.get("data"));

        auditService.addLog(AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .protocol("WEB")
                .remoteIp(ip)
                .location(location)
                .lng(coords[0])
                .lat(coords[1])
                .detail(detail)
                .time(LocalDateTime.now())
                .level(2)
                .build());

        return Map.of("status", "ok");
    }

    private String callAiSync(String system, String user) throws Exception {
        Map<String, Object> rb = new HashMap<>();

        // 模型类别
        rb.put("model", "LongCat-Flash-Chat");

        rb.put("messages", Arrays.asList(
                Map.of("role", "system", "content", system),
                Map.of("role", "user", "content", user)
        ));

        // 根据文档建议微调参数
        rb.put("temperature", 0.7);
        rb.put("max_tokens", 4096);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(LONGCAT_URL))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + LONGCAT_API_KEY.trim())
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(rb)))
                .build();

        HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString());

        if (res.statusCode() != 200) {
            log.error("通信故障 [{}]: {}", res.statusCode(), res.body());
            throw new RuntimeException("模型暂时拒绝了连接...");
        }

        return objectMapper.readTree(res.body()).get("choices").get(0).get("message").get("content").asText()
                .replace("```html", "").replace("```", "").trim();
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) ip = request.getRemoteAddr();
        return ip.equals("0:0:0:0:0:0:0:1") ? "127.0.0.1" : (ip.contains(",") ? ip.split(",")[0] : ip);
    }
}