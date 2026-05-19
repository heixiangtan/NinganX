package com.skuldlens.top.ninganx.honeypot.deception;

import com.skuldlens.top.ninganx.honeypot.core.AuditLogger;
import com.skuldlens.top.ninganx.honeypot.core.Honeypot;
import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.util.DefenderService; //
import com.skuldlens.top.ninganx.honeypot.util.IPLookupService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.UUID;

@Controller
public class WebDeceptionController implements Honeypot {

    private final AuditLogger auditLogger;
    private final AuditService auditService;
    private final IPLookupService ipLookupService;
    private final DefenderService defenderService;
    private boolean isRunning = true;

    public WebDeceptionController(AuditLogger auditLogger,
                                  AuditService auditService,
                                  IPLookupService ipLookupService,
                                  DefenderService defenderService) {
        this.auditLogger = auditLogger;
        this.auditService = auditService;
        this.ipLookupService = ipLookupService;
        this.defenderService = defenderService;
    }

    @Override public String getName() { return "WEB"; }
    @Override public boolean isRunning() { return isRunning; }

    @Override public void start() { this.isRunning = true; }
    @Override public void stop() { this.isRunning = false; }

    @GetMapping({"/", "/admin", "/login.html"})
    public String showLoginPage(HttpServletRequest request) {
        checkStatus(request); // 传入 request 检查 IP
        return "login";
    }

    @PostMapping("/admin/login")
    public String captureLogin(@RequestParam String username,
                               @RequestParam String password,
                               @RequestParam(required = false) String fingerprint,
                               HttpServletRequest request) {
        checkStatus(request);

        String remoteIp = getClientIp(request);

        // 自动化频率防御
        if (defenderService.checkAndBan(remoteIp)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "IP BANNED");
        }

        String location = ipLookupService.getLocationStr(remoteIp);
        double[] coords = ipLookupService.getCoordinates(remoteIp);

        String detail = String.format("LOGIN_TRY | User: %s | Pass: %s | UA: %s",
                username, password, request.getHeader("User-Agent"));

        reportToHeadquarters(remoteIp, location, coords, detail);
        return "redirect:/admin?error=maintenance";
    }

    private void checkStatus(HttpServletRequest request) {
        if (!isRunning) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "System Offline");

        // 业务层拦截逻辑
        String ip = getClientIp(request);
        if (defenderService.isBanned(ip)) {
            System.out.println("🔨 [Web 拦截] 已封禁 IP 试图访问 Web 蜜罐: " + ip);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access Denied");
        }
    }

    private void reportToHeadquarters(String ip, String location, double[] coords, String detail) {
        auditLogger.logEvent("web", String.format("IP: %s (%s) | %s", ip, location, detail));
        AuditLog log = AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .protocol("WEB")
                .remoteIp(ip)
                .location(location)
                .lng(coords[0])
                .lat(coords[1])
                .detail(detail)
                .time(LocalDateTime.now())
                .build();
        auditService.addLog(log);
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) ip = request.getRemoteAddr();
        if (ip.equals("0:0:0:0:0:0:0:1")) ip = "127.0.0.1";
        return ip.contains(",") ? ip.split(",")[0] : ip;
    }
}