package com.skuldlens.top.ninganx.honeypot.util;

import com.skuldlens.top.ninganx.honeypot.model.AlarmConfig;
import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.mapper.AuditMapper;
import com.skuldlens.top.ninganx.honeypot.service.DingTalkService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class AlarmTask {

    @Autowired
    private AuditService auditService;
    @Autowired
    private DingTalkService dingTalkService;
    @Autowired
    private AuditMapper auditMapper;

    @Scheduled(cron = "0 0 9 * * ?") // 每天早 9 点执行
    public void sendDailySummary() {
        AlarmConfig config = auditService.getAlarmConfig();
        if (!config.isEnabled() || !Boolean.TRUE.equals(config.getRules().get("dailySummary"))) return;

        long total = auditMapper.countRecentAttacks(24);
        long high = auditMapper.countRecentHighRisk(24);

        String md = "### 柠安 X - 24小时运行简报\n" +
                "--- \n" +
                "**战果汇总**：\n" +
                "* **总捕获次数**：`" + total + "` 次\n" +
                "* **高危拦截 (Lv2)**：`" + high + "` 起 \n\n" +
                "系统正常运转中，一切安好\n";

        dingTalkService.sendMarkdown(config, "运行简报", md);
    }
}