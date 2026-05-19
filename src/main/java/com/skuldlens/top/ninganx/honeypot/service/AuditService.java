package com.skuldlens.top.ninganx.honeypot.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.skuldlens.top.ninganx.honeypot.mapper.AuditMapper;
import com.skuldlens.top.ninganx.honeypot.model.AlarmConfig;
import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import com.skuldlens.top.ninganx.honeypot.model.DashboardDTO;
import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import com.skuldlens.top.ninganx.honeypot.util.IPLookupService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 核心审计与告警中枢
 * 使用正则矩阵对入侵行为进行深度判定
 */
@Service
@Slf4j
public class AuditService {

    private final List<AuditLog> hotCache = new CopyOnWriteArrayList<>();
    private static final int CACHE_SIZE = 50;
    private static final String CONFIG_PATH = "alarm_config.json";

    private boolean alarmEnabled;

    @Autowired
    private IPLookupService ipLookupService;

    @Autowired
    private AuditMapper auditMapper;

    @Autowired
    private DingTalkService dingTalkService;

    @Lazy
    @Autowired
    private DefenderService defenderService;

    private AlarmConfig currentAlarmConfig;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * LEVEL 1: 扫描、搜集与边界嗅探
     * 涵盖：系统环境搜集(env, export)、目录遍历初探(ls -a)、用户发现(whoami, id)、网络连接搜集(netstat, ifconfig)。
     */
    private static final Pattern ORANGE_PATTERN = Pattern.compile("(?i)(" +
            "whoami|id|hostname|pwd|ifconfig|ip\\s+a|netstat|uname|ps\\s+|" +
            "ls(\\s+-[a-zA-Z]+)?\\s+/|cat\\s+/(proc|sys|dev)/|grep|find|history|" +
            "export|env|df\\s+-h|last|uptime|PING|CLIENT|INFO|SCAN|DBSIZE)");

    /**
     * LEVEL 2: 毁灭、提权、窃密与 RCE (高危攻击模式)
     * 持久化后门、破坏性命令以及 Web 漏洞利用全数捕获。
     */
    private static final Pattern RED_PATTERN = Pattern.compile("(?i)(" +
            "id_rsa|id_dsa|authorized_keys|known_hosts|\\.ssh|" +                 // 凭据窃取
            "/etc/(passwd|shadow|group|sudoers|hostname|issue)|" +              // 核心隐私
            "rm\\s+-rf|mkfs|dd\\s+if=/dev/|shred|truncate|" +                    // 破坏性行为
            "chmod|chown|chgrp|visudo|sudo\\s+|crontab\\s+|" +                   // 提权与持久化
            "wget|curl\\s+.*\\|\\s*(bash|sh)|python\\s+-c|perl\\s+-e|nc\\s+-e|" + // 反弹 Shell/恶意下载
            "CONFIG\\s+SET|SLAVEOF|EVAL|SAVE|FLUSHALL|FLUSHDB|" +                // Redis 提权/毁灭
            "\\.env|\\.git|\\.config|\\.bash_history|/var/log/|" +               // 敏感目录搜刮
            "UNION\\s+SELECT|SLEEP\\(|OR\\s+1=1|<script|document\\.cookie" +      // Web 注入
            ")");

    public AlarmConfig getAlarmConfig() {
        if (currentAlarmConfig != null) {
            currentAlarmConfig.setEnabled(defenderService.isEnabled());
            return currentAlarmConfig;
        }

        synchronized (this) {
            // 二次检查防止并发冲突
            if (currentAlarmConfig != null) return currentAlarmConfig;

            try {
                File file = new File(CONFIG_PATH);
                if (file.exists()) {
                    currentAlarmConfig = objectMapper.readValue(file, AlarmConfig.class);

                    if (currentAlarmConfig != null) {
                        defenderService.setEnabled(currentAlarmConfig.isEnabled());
                    }
                } else {
                    // 文件不存在时，建立默认档案
                    currentAlarmConfig = new AlarmConfig();
                    currentAlarmConfig.setEnabled(false); // 默认关闭
                    currentAlarmConfig.setRules(new HashMap<>());

                    // 状态同步
                    defenderService.setEnabled(false);
                }

                if (currentAlarmConfig.getRules() == null) {
                    currentAlarmConfig.setRules(new HashMap<>());
                }
            } catch (Exception e) {
                log.error("档案读取失败！内容可能已损坏。", e);
                currentAlarmConfig = new AlarmConfig();
                currentAlarmConfig.setRules(new HashMap<>());
                defenderService.setEnabled(false);
            }
        }
        return currentAlarmConfig;
    }

    /**
     * 配置存档指令
     */
    public void saveAlarmConfig(AlarmConfig config) {
        if (config == null) return;


        if (defenderService != null) {
            defenderService.setEnabled(config.isEnabled());
            log.info("IPS状态已更新为: {} ！", config.isEnabled());
        }

        // 更新当前内存缓存
        this.currentAlarmConfig = config;

        // 将配置锁入磁盘文件 (alarm_config.json)
        try {
            objectMapper.writeValue(new File(CONFIG_PATH), config);
            log.info("[持久化] 告警中心配置已成功存入磁盘！");
        } catch (Exception e) {
            log.error("[持久化] 糟糕！档案写入失败: {}", e.getMessage());
            throw new RuntimeException("无法保存配置文件，请检查磁盘权限！");
        }
    }

    @Async("taskExecutor")
    public void addLog(AuditLog log) {
        if (log == null) return;
        if (log.getId() == null) log.setId(UUID.randomUUID().toString());
        if (log.getTime() == null) log.setTime(LocalDateTime.now());

        if (log.getRemoteIp() != null) {
            String loc = ipLookupService.getLocationStr(log.getRemoteIp());
            double[] coords = ipLookupService.getCoordinates(log.getRemoteIp());
            log.setLng(coords[0]);
            log.setLat(coords[1]);
            log.setLocation(loc);
            log.setFullLocation(loc);
        }

        String detail = log.getDetail() != null ? log.getDetail() : "";

        // 优先匹配红色高危
        if (RED_PATTERN.matcher(detail).find()) {
            log.setLevel(2);
        } else if (ORANGE_PATTERN.matcher(detail).find()) {
            log.setLevel(1);
        } else {
            log.setLevel(0);
        }

        checkAndTriggerAlarm(log);

        try {
            auditMapper.insert(log);
        } catch (Exception e) {
            System.err.println("数据库归档失败：" + e.getMessage());
        }

        hotCache.add(0, log);
        if (hotCache.size() > CACHE_SIZE) hotCache.remove(hotCache.size() - 1);
    }

    @Async("taskExecutor")
    public void reportBaitTriggered(String remoteIp, String tokenValue, String userAgent) {
        try {
            auditMapper.incrementTriggerCount(tokenValue);
        } catch (Exception e) {
            System.err.println("诱饵计数更新失败：" + e.getMessage());
        }

        // 获取地理位置信息
        String loc = ipLookupService.getLocationStr(remoteIp);
        double[] coords = ipLookupService.getCoordinates(remoteIp);

        AuditLog baitLog = AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .protocol("TOKEN") // 特殊协议标识，前端会显示为蓝色标签
                .remoteIp(remoteIp)
                .location(loc)
                .lng(coords[0])
                .lat(coords[1])
                .detail("[诱饵触发] 捕获到真实 IP 尝试使用诱饵: " + tokenValue + " | 环境: " + userAgent)
                .time(LocalDateTime.now())
                .level(2) // 红色最高警戒
                .build();

        // 存入数据库并进入热缓存推送前端
        addLog(baitLog);

        // 发送钉钉告警
        AlarmConfig config = getAlarmConfig();
        if (config.isEnabled()) {
            String md = "### 柠安 X - 诱饵溯源成功报告\n" +
                    "--- \n" +
                    "**触发特征码**：`" + tokenValue + "`\n\n" +
                    "**真实出口 IP**：`" + remoteIp + "` (" + loc + ")\n\n" +
                    "**环境指纹**：`" + userAgent + "`\n\n" +
                    "**情报**：黑客已下载并打开诱饵文件！隐形雷达回传：“职工信息表.xlsx” 已在其真实物理设备上引爆！目标本机的 User-Agent 与 物理路径 已解析，猎物已入网！";
            dingTalkService.sendMarkdown(config, "诱饵溯源成功", md);
        }

        System.out.println("诱饵溯源成功！已锁定攻击者 IP: " + remoteIp);
    }

    private void checkAndTriggerAlarm(AuditLog log) {
        AlarmConfig config = getAlarmConfig();
        if (config.isEnabled() && log.getLevel() == 2) {
            if (Boolean.TRUE.equals(config.getRules().get("highRisk"))) {
                String timeStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                String rawDetail = log.getDetail().toUpperCase();

                String reportTitle = "柠安 X - 高危入侵告警";
                String reportComment = "检测到严重的 入侵行为，黑客意图控制系统或窃取核心机密！";

                // 精准语义分类
                if (rawDetail.contains("ID_RSA") || rawDetail.contains(".SSH") || rawDetail.contains("AUTHORIZED_KEYS")) {
                    reportTitle = "柠安 X - 凭据窃取尝试告警";
                    reportComment = "攻击者正在尝试获取您的 SSH 私钥！";
                } else if (rawDetail.contains("CONFIG SET") || rawDetail.contains("SLAVEOF") || rawDetail.contains("PYTHON -C")) {
                    reportTitle = "柠安 X - RCE 提权攻击告警";
                    reportComment = "攻击者正在尝试执行远程代码(RCE)以获取系统 Root 权限！";
                } else if (rawDetail.contains("FLUSHALL") || rawDetail.contains("RM -RF")) {
                    reportTitle = "柠安 X - 破坏性命令执行告警";
                    reportComment = "攻击者正在尝试彻底清空数据或删除核心系统文件！";
                } else if (rawDetail.contains("/ETC/PASSWD") || rawDetail.contains(".ENV")) {
                    reportTitle = "柠安 X - 核心隐私泄露告警";
                    reportComment = "攻击者正在读取系统账户文件或环境变量 尝试进行横向渗透！";
                }

                String md = "### " + reportTitle + "\n" +
                        "--- \n" +
                        "**风险等级**：`LEVEL 2 (CRITICAL)`\n\n" +
                        "**目标协议**：`" + log.getProtocol() + "`\n\n" +
                        "**攻击来源**：`" + log.getRemoteIp() + "` (" + log.getLocation() + ")\n\n" +
                        "**罪证详情**：`" + log.getDetail() + "`\n\n" +
                        "**发生时间**：`" + timeStr + "`\n" +
                        "--- \n" +
                        "**情报**：" + reportComment + "\n\n" +
                        "系统建议：此 IP 恶意极高，建议立即执行物理封禁！";

                dingTalkService.sendMarkdown(config, "高危入侵告警", md);
            }
        }
    }

    public void notifyIpsBan(String ip, String reason) {
        AlarmConfig config = getAlarmConfig();
        if (config.isEnabled() && Boolean.TRUE.equals(config.getRules().get("ipsBan"))) {
            String timeStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String md = "### IPS 自动封禁通知\n" +
                    "--- \n" +
                    "**🛡防御动作**：`自动封禁 (PERMANENT BAN)`\n\n" +
                    "**封禁对象**：`" + ip + "`\n\n" +
                    "**⚖理由**：`" + reason + "`\n\n" +
                    "**执行时间**：`" + timeStr + "`\n" +
                    "--- \n" +
                    "该IP已被纳入黑名单！";
            dingTalkService.sendMarkdown(config, "IPS 封禁动作通知", md);
        }
    }

    @Scheduled(cron = "0 0 0 * * ?") // 统计报告时间
    public void sendDailySummary() {
        AlarmConfig config = getAlarmConfig();
        if (config.isEnabled() && Boolean.TRUE.equals(config.getRules().get("dailySummary"))) {
            System.out.println("[审计中枢] 正在整理战情简报...");

            long total24h = auditMapper.countRecentAttacks(24);
            long highRisk24h = auditMapper.countRecentHighRisk(24);
            List<Map<String, Object>> topIps = auditMapper.selectTopAttackersWithCount(5);
            List<Map<String, Object>> hotLocs = auditMapper.selectRecentHotLocations();

            StringBuilder sb = new StringBuilder();
            sb.append("### 柠安 X - 战场实时周报\n");
            sb.append("--- \n");
            sb.append("**累计截获**：`").append(total24h).append("` 次攻击\n\n");
            sb.append("**致命预警**：`").append(highRisk24h).append("` 起高危攻击\n\n");

            sb.append("**活跃攻击IP (TOP 5)**：\n");
            for (Map<String, Object> entry : topIps) {
                sb.append("- `").append(entry.get("remote_ip")).append("` (攻击 ").append(entry.get("count")).append(" 次)\n");
            }

            sb.append("\n**火力热度排行**：\n");
            for (Map<String, Object> loc : hotLocs) {
                sb.append("- `").append(loc.get("location")).append("` (").append(loc.get("count")).append(" 次)\n");
            }

            sb.append("\n--- \n");
            sb.append("防线运转良好");

            dingTalkService.sendMarkdown(config, "战情简报", sb.toString());
        }
    }

    /**
     * 态势感知数据计算枢纽
     * 汇总全线战报，并实时联动状态
     */
    public DashboardDTO calculateDashboardData() {
        DashboardDTO dto = new DashboardDTO();

        // 统计战报总数
        dto.setTotalAttacks(auditMapper.countTotalAttacks());

        // 统计各协议分布情况
        List<Map<String, Object>> protocolList = auditMapper.countByProtocol();
        Map<String, Long> protocolMap = new HashMap<>();
        for (Map<String, Object> map : protocolList) {
            protocolMap.put((String) map.get("protocol"), ((Number) map.get("count")).longValue());
        }
        dto.setProtocolStats(protocolMap);

        // 锁定TOP 10攻击者
        dto.setTopIps(auditMapper.selectTopAttackersWithCount(10).stream()
                .map(m -> (String) m.get("remote_ip"))
                .collect(Collectors.toList()));

        // 只有当 alarm_config.json 开启 且 DefenderService 在线时，才返回 true
        AlarmConfig config = getAlarmConfig();
        boolean isLinked = config != null && config.isEnabled() && defenderService.isEnabled();

        dto.setAlarmEnabled(isLinked);

        // 渲染攻击热力图
        dto.setHeatMap(hotCache.stream()
                .filter(log -> log.getLng() != null && log.getLng() != 0)
                .map(log -> new DashboardDTO.AttackLocation(log.getLng(), log.getLat()))
                .collect(Collectors.toList()));

        return dto;
    }

    /**
     * 获取最新战报列表
     */
    public List<AuditLog> getLatestLogs(int count) {
        return auditMapper.selectLatestLogs().stream()
                .limit(count)
                .collect(Collectors.toList());
    }

    /**
     * 分页查询历史战报 (支持协议与 IP 筛选)
     */
    public Map<String, Object> getLogsByPage(String protocol, String ip, int page, int size) {
        int offset = (page - 1) * size;
        List<AuditLog> list = auditMapper.selectFilteredLogs(protocol, ip, offset, size);

        // 为每一条记录补充该 IP 的历史累计攻击次数
        for (AuditLog log : list) {
            log.setAttackCount(auditMapper.countByIp(log.getRemoteIp()));
        }

        Map<String, Object> res = new HashMap<>();
        res.put("list", list);
        res.put("hasMore", list.size() == size); // 简单有效的瀑布流分页逻辑
        return res;
    }
}