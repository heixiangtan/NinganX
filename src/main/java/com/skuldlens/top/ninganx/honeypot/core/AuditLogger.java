package com.skuldlens.top.ninganx.honeypot.core;

public interface AuditLogger {
    // 允许传入 category，比如 "ssh" 或 "redis"
    void logEvent(String category, String event);
    void logTraffic(byte[] trafficData);
}