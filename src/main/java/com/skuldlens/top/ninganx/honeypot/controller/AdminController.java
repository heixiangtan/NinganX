package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.model.AlarmConfig;
import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import com.skuldlens.top.ninganx.honeypot.model.DashboardDTO;
import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.service.HoneypotManager;
import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin
public class AdminController {

    @Value("${ningan.admin.username}")
    private String adminUser;

    @Value("${ningan.admin.password}")
    private String adminPass;

    @Autowired
    private HoneypotManager manager;
    @Autowired
    private AuditService auditService;
    @Autowired
    private DefenderService defenderService;

    @PostMapping("/do-admin-login")
    public RedirectView manualLogin(@RequestParam String username,
                                    @RequestParam String password,
                                    HttpServletRequest request) {

        if (adminUser.equals(username) && adminPass.equals(password)) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(auth);

            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("管理员验证通过，指挥中心已就绪");
            return new RedirectView("/dashboard.html");
        }
        return new RedirectView("/admin_auth.html?error");
    }

    @PostMapping("/api/admin/honeypot/toggle")
    public String toggle(@RequestParam String name, @RequestParam boolean action) {
        manager.control(name, action);
        return "报告，" + name + (action ? " 已启动！" : " 已停止！") + "️";
    }

    @GetMapping("/api/admin/dashboard/stats")
    public DashboardDTO getStats() {
        return auditService.calculateDashboardData();
    }

    @GetMapping("/api/admin/logs/live")
    public List<AuditLog> getLiveLogs() {
        return auditService.getLatestLogs(20);
    }

    @GetMapping("/api/admin/config/defender")
    public Map<String, Object> getDefenderConfig() {
        return Map.of("enabled", defenderService.isEnabled());
    }

    @PostMapping("/api/admin/config/defender/toggle")
    public String toggleDefender(@RequestParam boolean enabled) {
        defenderService.setEnabled(enabled);
        return "防御策略已更新！";
    }

    @GetMapping("/api/admin/logs/search")
    public Map<String, Object> searchLogs(
            @RequestParam(required = false) String protocol,
            @RequestParam(required = false) String ip,
            @RequestParam(defaultValue = "1") int page) {
        return auditService.getLogsByPage(protocol, ip, page, 30);
    }

    @PostMapping("/api/admin/defender/ban")
    public String manualBan(@RequestParam String ip) {
        defenderService.banIpManual(ip);
        return "IP " + ip + " 已封禁，全线防区同步生效";
    }

    @GetMapping("/api/admin/config/alarm")
    public AlarmConfig getAlarmConfig() {
        return auditService.getAlarmConfig();
    }

    @PostMapping("/api/admin/config/alarm/save")
    public String saveAlarmConfig(@RequestBody AlarmConfig config) {
        auditService.saveAlarmConfig(config);
        return "SUCCESS！告警中心已加固！";
    }
}