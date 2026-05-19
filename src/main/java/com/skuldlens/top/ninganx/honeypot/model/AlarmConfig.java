package com.skuldlens.top.ninganx.honeypot.model;

import lombok.Data;
import java.util.Map;

@Data
public class AlarmConfig {
    private boolean enabled;
    private String token;
    private String secret;
    private Map<String, Boolean> rules; // highRisk, ipsBan, dailySummary
}