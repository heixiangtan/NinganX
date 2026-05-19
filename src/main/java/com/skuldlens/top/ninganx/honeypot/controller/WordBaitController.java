package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.service.WordBaitService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@Slf4j
public class WordBaitController {

    @Autowired
    private AuditService auditService;

    @Autowired
    private WordBaitService wordBaitService;


    @GetMapping(value = "/public/api/v1/trace/assets/{baitToken}.jpg", produces = MediaType.IMAGE_GIF_VALUE)
    public byte[] track(HttpServletRequest request, @PathVariable String baitToken) {
        // 抓取多重 IP，尝试穿透代理
        String remoteIp = request.getHeader("X-Forwarded-For");
        if (remoteIp == null || remoteIp.isEmpty() || "unknown".equalsIgnoreCase(remoteIp)) {
            remoteIp = request.getHeader("Proxy-Client-IP");
        }
        if (remoteIp == null || remoteIp.isEmpty() || "unknown".equalsIgnoreCase(remoteIp)) {
            remoteIp = request.getRemoteAddr();
        }

        // 抓取核心身份特征
        String userAgent = request.getHeader("User-Agent");
        String referer = request.getHeader("Referer");
        String acceptLang = request.getHeader("Accept-Language");

        // 构建全量指纹
        StringBuilder fingerprint = new StringBuilder();
        request.getHeaderNames().asIterator().forEachRemaining(headerName -> {
            fingerprint.append(headerName).append(": ").append(request.getHeader(headerName)).append("|");
        });

        // 汇总上报
        String detailedReport = String.format(
                "TRACED | Ref: %s | Lang: %s | FullFingerprint: %s",
                referer != null ? referer : "DIRECT_OPEN",
                acceptLang != null ? acceptLang : "UNKNOWN",
                fingerprint.toString()
        );

        log.info("[战报] 诱饵引爆！Token: {}, IP: {}, 详情: {}", baitToken, remoteIp, detailedReport);

        // 这里的 reportBaitTriggered 建议增加一个存储详细信息的字段
        auditService.reportBaitTriggered(remoteIp, "EXCEL-" + baitToken, userAgent + " | " + detailedReport);

        // 返回 1x1 透明像素点
        return new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x21, (byte) 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b};
    }

    /**
     * Excel 诱饵
     */
    @GetMapping("/api/admin/bait/download/excel")
    public ResponseEntity<byte[]> downloadExcelBait() {
        try {
            log.info("正在提取“职工信息表”...");
            byte[] fileContent = wordBaitService.getPredefinedExcelBait();

            // 对中文文件名进行编码，防止浏览器下载时乱码
            String encodedFileName = URLEncoder.encode("职工信息表.xlsx", StandardCharsets.UTF_8);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename*=UTF-8''" + encodedFileName)
                    .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                    .body(fileContent);
        } catch (Exception e) {
            log.error("提取失败：", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}