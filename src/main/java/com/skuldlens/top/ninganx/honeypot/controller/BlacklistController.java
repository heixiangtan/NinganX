package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/admin/blacklist")
public class BlacklistController {

    private final DefenderService defenderService;

    public BlacklistController(DefenderService defenderService) {
        this.defenderService = defenderService;
    }

    // 获取所有封禁 IP 及其详情
    @GetMapping("/list")
    public List<Map<String, Object>> getBlacklist() {
        // 这里返回 IP、封禁时间、原因等
        List<Map<String, Object>> list = new ArrayList<>();
        defenderService.getBannedIpsWithDetails().forEach((ip, detail) -> {
            Map<String, Object> map = new HashMap<>();
            map.put("ip", ip);
            map.put("reason", detail.getReason());
            map.put("time", detail.getBannedTime());
            list.add(map);
        });
        return list;
    }

    // 手动解封
    @PostMapping("/pardon")
    public Map<String, String> pardon(@RequestParam String ip) {
        defenderService.unban(ip);
        return Map.of("status", "success", "msg", "该 IP 已被特赦！");
    }
}