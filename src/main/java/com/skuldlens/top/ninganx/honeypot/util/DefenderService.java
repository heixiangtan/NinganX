package com.skuldlens.top.ninganx.honeypot.util;

import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * IPS
 * 自动化频率监测 + 管理员解禁接口 + 罪名详细记录 + IP审计
 */
@Service
public class DefenderService {

    // 系统配置
    private boolean enabled = true;            // 防御策略总开关
    private final int MAX_ATTEMPTS = 100;       // 阈值：1分钟内允许的最大尝试次数
    private final int BAN_MINUTES = 30;        // 自动封禁的默认刑期（分钟）

    @Lazy
    @Autowired
    private AuditService auditService;         // 引入审计中心

    // 运行数据容器
    private final ConcurrentHashMap<String, AtomicInteger> accessCount = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, BannedDetail> blackListMap = new ConcurrentHashMap<>();

    private LocalDateTime lastResetTime = LocalDateTime.now();

    /**
     * 内部类：定义封禁IP详情，记录罪名和时间
     */
    public static class BannedDetail {
        private final String reason;
        private final LocalDateTime bannedTime;
        private final LocalDateTime expireTime;

        public BannedDetail(String reason, LocalDateTime expireTime) {
            this.reason = reason;
            this.bannedTime = LocalDateTime.now();
            this.expireTime = expireTime;
        }
        public String getReason() { return reason; }
        public LocalDateTime getBannedTime() { return bannedTime; }
        public LocalDateTime getExpireTime() { return expireTime; }
    }

    /**
     * 自动化核心防御：检查并记录 IP 行为
     */
    public boolean checkAndBan(String ip) {
        if (!enabled || ip == null) return false;

        // 定时清理计数器
        if (LocalDateTime.now().isAfter(lastResetTime.plusMinutes(1))) {
            accessCount.clear();
            lastResetTime = LocalDateTime.now();
        }

        // 先检查是否已在黑名单
        if (isBanned(ip)) {
            return true;
        }

        // 累加攻击计数
        accessCount.putIfAbsent(ip, new AtomicInteger(0));
        int current = accessCount.get(ip).incrementAndGet();

        // 实时追踪日志
        System.out.printf("[IPS] 流量监测 -> IP: %s | 计数进度: [%d/%d] ！\n", ip, current, MAX_ATTEMPTS);

        // 判定是否触发自动化封禁
        if (current >= MAX_ATTEMPTS) {
            // 判处自动封禁
            ban(ip, "检测到高频暴力访问（1分钟内超额 " + MAX_ATTEMPTS + " 次）", BAN_MINUTES);
            return true;
        }

        return false;
    }

    /**
     * 支持记录原因和时长
     */
    public void ban(String ip, String reason, int minutes) {
        LocalDateTime expire = LocalDateTime.now().plusMinutes(minutes);
        blackListMap.put(ip, new BannedDetail(reason, expire));

        System.out.println("[IPS] 已封禁 IP: " + ip + " | 原因: " + reason + " ！");

        // 发送战报
        try {
            auditService.notifyIpsBan(ip, reason + "，IPS防御模块已强制驱逐该 IP ！");
        } catch (Exception e) {
            System.err.println("[IPS] 发射战报失败！");
        }
    }

    /**
     * 手动永久封禁接口
     */
    public void banIpManual(String ip) {
        ban(ip, "手动封禁", 52560000); // 约99年
    }

    /**
     * 判断 IP 是否在黑名单且未过期
     */
    public boolean isBanned(String ip) {
        if (!enabled || ip == null) return false;

        BannedDetail detail = blackListMap.get(ip);
        if (detail == null) return false;

        if (LocalDateTime.now().isBefore(detail.getExpireTime())) {
            return true;
        } else {
            System.out.println("[ISP] 封禁时间到期IP: " + ip + "，已从封禁列表移除！");
            unban(ip);
            return false;
        }
    }

    /**
     * 获取全量封禁详情
     */
    public Map<String, BannedDetail> getBannedIpsWithDetails() {
        return blackListMap;
    }

    /**
     * 手动解封
     */
    public void unban(String ip) {
        if (ip == null) return;
        blackListMap.remove(ip);
        accessCount.remove(ip);
        System.out.println("[IPS] 管理员操作！IP: " + ip + " 已从封禁列表移除！");
    }

    /**
     * 开关接口
     */
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * 解封所有IP
     */
    public void clearBlackList() {
        blackListMap.clear();
        accessCount.clear();
        System.out.println("🕊[IPS] 封禁列表已清空");
    }
}