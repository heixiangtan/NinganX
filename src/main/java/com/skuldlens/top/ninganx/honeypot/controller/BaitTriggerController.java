package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/public/api/verify")
public class BaitTriggerController {

    @Autowired
    private AuditService auditService;

    @GetMapping("/license")
    public Map<String, Object> verifyToken(@RequestParam String key, HttpServletRequest request) {
        String remoteIp = request.getRemoteAddr();        // 尝试从 Header 获取真实 IP
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            remoteIp = xForwardedFor.split(",")[0];
        }

        String userAgent = request.getHeader("User-Agent");

        // 识别诱饵特征码
        if (key != null && key.startsWith("NX-")) {
            System.out.println("诱饵被引爆！捕获到真实 IP: " + remoteIp);
            
            // 调用审计中枢发送钉钉战报和入库
            auditService.reportBaitTriggered(remoteIp, key, userAgent);
            
            return Map.of(
                "status", "error",
                "code", 403,
                "msg", "Token valid but connection restricted to internal subnet.",
                "trace_id", "TR-" + System.currentTimeMillis()
            );
        }

        return Map.of("status", "invalid", "msg", "Invalid product key.");
    }
}