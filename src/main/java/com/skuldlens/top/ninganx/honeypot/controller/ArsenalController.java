package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.mapper.HoneyToken;
import com.skuldlens.top.ninganx.honeypot.service.ArsenalService;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/arsenal")
public class ArsenalController {

    private final ArsenalService arsenalService;

    public ArsenalController(ArsenalService arsenalService) {
        this.arsenalService = arsenalService;
    }

    @GetMapping("/list")
    public List<HoneyToken> list() {
        return arsenalService.getAllActiveTokens();
    }

    @PostMapping("/deploy")
    public Map<String, String> deploy(@RequestBody Map<String, String> req) {
        String token = arsenalService.deployNewBait(req.get("type"), req.get("comment"));
        return Map.of("status", "success", "token", token);
    }

    @PostMapping("/remove")
    public Map<String, Object> remove(@RequestBody Map<String, String> req) {
        String id = req.get("id");
        boolean success = arsenalService.removeBait(id);
        return Map.of("status", success ? "success" : "error");
    }
}