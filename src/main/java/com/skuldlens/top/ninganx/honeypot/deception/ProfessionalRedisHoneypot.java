package com.skuldlens.top.ninganx.honeypot.deception;

import com.skuldlens.top.ninganx.honeypot.core.AuditLogger;
import com.skuldlens.top.ninganx.honeypot.core.Honeypot;
import com.skuldlens.top.ninganx.honeypot.mapper.HoneyToken;
import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import com.skuldlens.top.ninganx.honeypot.service.ArsenalService;
import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import com.skuldlens.top.ninganx.honeypot.util.IPLookupService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class ProfessionalRedisHoneypot implements Honeypot {

    private final AuditLogger auditLogger;
    private final AuditService auditService;
    private final IPLookupService ipLookupService;
    private final DefenderService defenderService;

    private static final int PORT = 6379;
    private ServerSocket serverSocket;
    private boolean isRunning = false;
    private final ExecutorService executor = Executors.newCachedThreadPool();

    private final Map<String, Long> lastRequestTimeMap = new ConcurrentHashMap<>();
    private static final Map<String, String> fakeDb = new ConcurrentHashMap<>();
    private static final String REDIS_LOG_DIR = "logs/redis";
    private static final String PAYLOAD_DIR = REDIS_LOG_DIR + "/payloads";

    private final ArsenalService arsenalService;

    // 🕵️‍♂️ 扩展后的高危特征库
    private static final List<String> DANGER_KEYWORDS = Arrays.asList(
            "/bin/bash", "cron", "authorized_keys", "eval", "<?php", "exec",
            "python", "import", "nc -e", "sh -i", "powershell", "curl", "wget"
    );

    public ProfessionalRedisHoneypot(AuditLogger auditLogger,
                                     AuditService auditService,
                                     IPLookupService ipLookupService,
                                     DefenderService defenderService,
                                     ArsenalService arsenalService) {
        this.auditLogger = auditLogger;
        this.auditService = auditService;
        this.ipLookupService = ipLookupService;
        this.defenderService = defenderService;
        this.arsenalService = arsenalService; // 赋值
        try {
            Files.createDirectories(Paths.get(PAYLOAD_DIR));
        } catch (IOException e) {
            System.err.println("文件夹创建失败：" + e.getMessage());
        }
    }

    @Override public String getName() { return "REDIS"; }
    @Override public boolean isRunning() { return isRunning; }



    @Override
    @PostConstruct
    public void start() {
        if (isRunning) return;
        new Thread(() -> {
            try {
                serverSocket = new ServerSocket(PORT);
                isRunning = true;
                System.out.println("Redis 蜜罐已出击！");
                while (isRunning) {
                    Socket client = serverSocket.accept();
                    String remoteIp = client.getInetAddress().getHostAddress();
                    if (defenderService.isBanned(remoteIp)) {
                        client.close();
                        continue;
                    }
                    executor.execute(() -> handleClient(client, remoteIp));
                }
            } catch (IOException e) {
                if (isRunning) System.err.println("Redis 异常：" + e.getMessage());
            }
        }).start();
    }

    private void handleClient(Socket socket, String ip) {
        lastRequestTimeMap.put(ip, System.currentTimeMillis());
        String location = ipLookupService.getLocationStr(ip);
        double[] coords = ipLookupService.getCoordinates(ip);

        try (InputStream input = socket.getInputStream();
             OutputStream output = socket.getOutputStream();
             Scanner scanner = new Scanner(input)) {

            while (scanner.hasNextLine()) {
                String rawLine = scanner.nextLine().trim();
                if (defenderService.checkAndBan(ip)) break;

                // 过滤 RESP 协议的长度描述符，只处理实际指令
                if (rawLine.isEmpty() || rawLine.startsWith("*") || rawLine.startsWith("$")) continue;

                long currentTime = System.currentTimeMillis();
                long delta = currentTime - lastRequestTimeMap.getOrDefault(ip, currentTime);
                lastRequestTimeMap.put(ip, currentTime);

                String[] parts = rawLine.split("\\s+");
                String cmd = parts[0].toUpperCase();
                String clientGuess = guessClientType(cmd, delta, rawLine);
                String detail = String.format("[%s] Cmd: %s", clientGuess, rawLine);
                reportToHeadquarters(ip, location, coords, detail);

                // 准备诱饵：抓取最新的 REDIS_PASS 令牌
                List<HoneyToken> tokens = arsenalService.getAllActiveTokens();
                String redisBait = tokens.stream()
                        .filter(t -> "REDIS_PASS".equals(t.getTokenType()))
                        .map(HoneyToken::getTokenValue)
                        .findFirst()
                        .orElse("NX-REDIS-DEFAULT-999");

                String serverIp = "8.138.176.255";

                String response;
                switch (cmd) {
                    case "SET":
                        if (parts.length >= 3) {
                            String key = parts[1];
                            String value = rawLine.substring(rawLine.indexOf(parts[2]));
                            if (DANGER_KEYWORDS.stream().anyMatch(value::contains)) {
                                savePayload(ip, "SET_" + key, value);
                            }
                            fakeDb.put(key, value);
                        }
                        response = "+OK\r\n";
                        break;
                    case "SAVE":
                    case "BGSAVE":
                        exportSuspiciousData(ip);
                        response = "+OK\r\n";
                        break;
                    case "CONFIG":
                        if (rawLine.toUpperCase().contains("SET") && rawLine.toUpperCase().contains("DIR")) {
                            reportToHeadquarters(ip, location, coords, "[CRITICAL] 黑客试图修改保存目录！");
                        }
                        response = "+OK\r\n";
                        break;
                    case "PING": response = "+PONG\r\n"; break;

                    case "GET":
                        String key = parts.length > 1 ? parts[1] : "";
                        // 如果黑客尝试读取管理相关的键，直接给诱饵
                        if (key.toLowerCase().contains("admin") || key.toLowerCase().contains("pass") || key.toLowerCase().contains("config")) {
                            String payload = "{\"user\":\"admin\",\"pass\":\"" + redisBait + "\",\"auth_url\":\"http://" + serverIp + ":9999/public/api/verify/license\"}";
                            response = "$" + payload.length() + "\r\n" + payload + "\r\n";
                        } else {
                            String val = fakeDb.get(key);
                            response = (val == null) ? "$-1\r\n" : "$" + val.length() + "\r\n" + val + "\r\n";
                        }
                        break;

                    case "INFO":
                        // 模拟真实 Redis 的 KEYS 列表，引导黑客去执行 GET 指令
                        String info = "# Server\r\nredis_version:6.2.6\r\nos:Linux\r\n" +
                                "# Keyspace\r\ndb0:keys=" + (fakeDb.size() + 1) + ",expires=0,avg_ttl=0\r\n" +
                                "# Warning: Local access restricted. Auth key required for cluster nodes.\r\n";
                        response = "$" + info.length() + "\r\n" + info + "\r\n";
                        break;

                    case "KEYS":
                        // 展示现有的键和我们伪造的诱饵键
                        response = "*2\r\n$19\r\nconfig:admin:creds\r\n$17\r\nuser:session:logs\r\n";
                        break;

                    case "AUTH":
                        response = "+OK\r\n";
                        break;

                    case "QUIT":
                        output.write("+OK\r\n".getBytes());
                        socket.close();
                        return;
                    default:
                        response = String.format("-(error) ERR unknown command '%s'\r\n", cmd.toLowerCase());
                        break;
                }
                output.write(response.getBytes());
                output.flush();
            }
        } catch (Exception ignored) {}
    }

    /**
     * 当收到 SAVE 指令时，将内存中所有包含特征的内容一次性导出
     */
    private void exportSuspiciousData(String ip) {
        fakeDb.forEach((k, v) -> {
            if (DANGER_KEYWORDS.stream().anyMatch(v::contains)) {
                savePayload(ip, "SAVE_TRIGGERED_" + k, v);
            }
        });
    }

    private void savePayload(String ip, String key, String content) {
        // 增加 UUID 防止并发覆盖
        String fileName = String.format("%s/%s_%s_%s.bin", PAYLOAD_DIR, ip, System.currentTimeMillis(), UUID.randomUUID().toString().substring(0, 8));
        try {
            String logContent = "Time: " + LocalDateTime.now() + "\nSource_IP: " + ip + "\nKey: " + key + "\nPayload: " + content;
            Files.writeString(Paths.get(fileName), logContent);
            System.out.println("已捕获可疑物证，安全锁死在：" + fileName + " ！️");
        } catch (IOException ignored) {}
    }

    private void reportToHeadquarters(String ip, String location, double[] coords, String detail) {
        auditLogger.logEvent("redis", "IP: " + ip + " | " + detail);
        AuditLog log = AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .protocol("REDIS")
                .remoteIp(ip)
                .location(location)
                .lng(coords[0])
                .lat(coords[1])
                .detail(detail)
                .time(LocalDateTime.now())
                .build();
        auditService.addLog(log);
    }

    private String guessClientType(String cmd, long interval, String rawLine) {
        if (interval < 100) return "🤖 Automated_Scanner";
        if (rawLine.contains("<?php") || rawLine.contains("bash")) return "😈 Attacker_Payload";
        if (interval > 4000) return "👨‍💻 Human_Attacker";
        return "Unknown_Client";
    }

    @Override @PreDestroy public void stop() { isRunning = false; try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {} }
}