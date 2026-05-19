package com.skuldlens.top.ninganx.honeypot.monitoring;

import com.skuldlens.top.ninganx.honeypot.core.AuditLogger;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
@Primary
public class FileAuditLogger implements AuditLogger {

    private static final String BASE_LOG_DIR = "./logs";
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public void logEvent(String category, String event) {
        // 动态构建目录，比如 ./logs/ssh 或 ./logs/redis ！
        String targetDir = BASE_LOG_DIR + "/" + category.toLowerCase();
        String targetFile = targetDir + "/" + category.toLowerCase() + ".log";

        File directory = new File(targetDir);
        if (!directory.exists()) {
            directory.mkdirs();
        }

        String timestamp = LocalDateTime.now().format(formatter);
        // 这里的标签也变成动态的！
        String logEntry = String.format("[%s] [%s_ATTACK] %s", timestamp, category.toUpperCase(), event);

        System.out.println(logEntry);

        try (FileWriter fw = new FileWriter(targetFile, true);
             PrintWriter out = new PrintWriter(fw)) {
            out.println(logEntry);
        } catch (IOException e) {
            System.err.println("❌ 报告管理员，分流写日志失败了：" + e.getMessage());
        }
    }

    @Override
    public void logTraffic(byte[] trafficData) {}
}