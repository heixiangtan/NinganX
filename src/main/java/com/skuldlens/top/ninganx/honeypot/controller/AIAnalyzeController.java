package com.skuldlens.top.ninganx.honeypot.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

@RestController
@RequestMapping("/api/admin/ai")
public class AIAnalyzeController {

    private static final String PAYLOAD_DIR = "logs/redis/payloads";
    // 密钥
    private static final String API_KEY = ""; // 大模型令牌
    private static final String API_URL = ""; // 大模型接口地址

    // 异步任务执行池，确保流式输出不阻塞主业务
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 极速分析接口：采用 SSE 流式输出
     * 响应头必须是 text/event-stream ！
     */
    @PostMapping(value = "/analyze", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter analyze(@RequestBody Map<String, String> req) {
        SseEmitter emitter = new SseEmitter(0L);
        String id = req.get("id");

        executor.execute(() -> {
            try {
                // 读取物证
                byte[] content = Files.readAllBytes(Paths.get(PAYLOAD_DIR, id));
                String rawContent = new String(content, StandardCharsets.UTF_8);

                // 构建请求载荷
                Map<String, Object> requestBody = new HashMap<>();
                requestBody.put("model", "deepseek-chat");
                requestBody.put("stream", true); // 开启流式开关
                requestBody.put("messages", Arrays.asList(
                        Map.of("role", "system", "content", "你是柠安数据安全系统的安全审计员。请对载荷进行极简审计，直接输出重点，不要废话。"),
                        Map.of("role", "user", "content", "分析此载荷: " + rawContent)
                ));

                String jsonBody = objectMapper.writeValueAsString(requestBody);

                // 使用 Java 现代 HttpClient 发起异步请求
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(API_URL))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + API_KEY)
                        .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                        .build();

                // 解析流式响应
                client.sendAsync(request, HttpResponse.BodyHandlers.ofLines())
                        .thenAccept(response -> {
                            response.body().forEach(line -> {
                                try {
                                    if (line.startsWith("data: ")) {
                                        String data = line.substring(6);
                                        if (data.equals("[DONE]")) {
                                            emitter.complete(); // 分析结束
                                            return;
                                        }

                                        // 提取 AI 吐出的字符
                                        JsonNode node = objectMapper.readTree(data);
                                        String text = node.get("choices").get(0).get("delta").path("content").asText("");

                                        if (!text.isEmpty()) {
                                            emitter.send(text); // 实时推送到前端
                                        }
                                    }
                                } catch (Exception e) {

                                }
                            });
                        }).join();

            } catch (Exception e) {
                try {
                    emitter.send(" 分析模块遭遇干扰: " + e.getMessage());
                    emitter.complete();
                } catch (Exception ex) {
                    emitter.completeWithError(ex);
                }
            }
        });

        return emitter;
    }
}