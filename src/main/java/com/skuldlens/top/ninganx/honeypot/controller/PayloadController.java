package com.skuldlens.top.ninganx.honeypot.controller;

import com.skuldlens.top.ninganx.honeypot.model.PayloadInfo;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/payloads")
public class PayloadController {

    private static final String PAYLOAD_DIR = "logs/redis/payloads";

    @GetMapping("/list")
    public List<PayloadInfo> listPayloads() {
        File dir = new File(PAYLOAD_DIR);
        if (!dir.exists()) return Collections.emptyList();

        return Arrays.stream(Objects.requireNonNull(dir.listFiles()))
                .filter(File::isFile)
                .map(f -> {
                    String name = f.getName();
                    String[] parts = name.split("_");
                    return PayloadInfo.builder()
                            .id(name)
                            .remoteIp(parts.length > 0 ? parts[0] : "Unknown")
                            .time(parts.length > 1 ? parts[1] : "")
                            .size(f.length())
                            .protocol("REDIS")
                            .build();
                })
                .sorted((a, b) -> b.getTime().compareTo(a.getTime()))
                .collect(Collectors.toList());
    }

    @GetMapping("/detail")
    public Map<String, String> getDetail(@RequestParam String id) throws Exception {
        Path path = Paths.get(PAYLOAD_DIR, id);
        if (!Files.exists(path)) throw new RuntimeException("恶意代码已销毁！");

        // 将内容转为 Base64，防止前端渲染时发生意外
        byte[] content = Files.readAllBytes(path);
        String base64Content = Base64.getEncoder().encodeToString(content);
        
        Map<String, String> res = new HashMap<>();
        res.put("raw", base64Content);
        res.put("fileName", id);
        return res;
    }
}