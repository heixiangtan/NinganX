package com.skuldlens.top.ninganx.honeypot.security;

import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.http.HttpStatus;

/**
 * 局封禁拦截器
 * 在请求到达 Controller 之前，先判定 IP 是否在黑名单
 */
@Component
public class BanInterceptor implements HandlerInterceptor {

    @Autowired
    private DefenderService defenderService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取真实 IP
        String ip = getClientIp(request);

        if (defenderService.isBanned(ip)) {
            System.out.println("[全局拦截] 已封禁 IP 试图渗透 Web 层，已物理劝返: " + ip);
            
            // 返回 403 状态码
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED: Your IP (" + ip + ") is blacklisted.");
            return false; // 拦截请求，不再往下走
        }

        return true;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if ("0:0:0:0:0:0:0:1".equals(ip)) ip = "127.0.0.1";
        return ip.contains(",") ? ip.split(",")[0] : ip;
    }
}