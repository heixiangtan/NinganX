package com.skuldlens.top.ninganx.honeypot.monitoring;

import com.skuldlens.top.ninganx.honeypot.core.AuditLogger;
import org.springframework.stereotype.Service;

@Service
public class KeystrokeLogger implements AuditLogger {

    @Override
    public void logEvent(String category, String event) {
        // 分类
        System.out.println("[" + category.toUpperCase() + "_KEYSTROKE] Logged: " + event);
    }

    @Override
    public void logTraffic(byte[] trafficData) {
        // todo
    }
}