package com.skuldlens.top.ninganx.honeypot.service;

import com.skuldlens.top.ninganx.honeypot.model.AlarmConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 钉钉战报发射器
 * 负责即时告警和每日简报的发射
 */
@Service
public class DingTalkService {

    @Autowired
    private RestTemplate restTemplate;

    /**
     * 异步发射 Markdown 格式的战报
     * 即时入侵告警、IPS 判刑通知、24小时全域简报
     */
    @Async("taskExecutor")
    public void sendMarkdown(AlarmConfig config, String title, String markdown) {
        // 基础防线检查：配置不全或未开启则原地待命
        if (config == null || !config.isEnabled() || config.getToken() == null || config.getToken().isEmpty()) {
            return;
        }

        try {
            long timestamp = System.currentTimeMillis();
            String url = "https://oapi.dingtalk.com/robot/send?access_token=" + config.getToken();

            // 加签密钥校验逻辑
            if (config.getSecret() != null && !config.getSecret().isEmpty()) {
                String stringToSign = timestamp + "\n" + config.getSecret();
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(config.getSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                byte[] signData = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));

                String base64Sign = Base64.getEncoder().encodeToString(signData);
                String sign = URLEncoder.encode(base64Sign, StandardCharsets.UTF_8.name());

                url += "&timestamp=" + timestamp + "&sign=" + sign;
            }

            // 组装 Markdown 报文
            Map<String, Object> body = new HashMap<>();
            body.put("msgtype", "markdown");
            Map<String, String> markdownContent = new HashMap<>();
            markdownContent.put("title", title);
            markdownContent.put("text", markdown);
            body.put("markdown", markdownContent);

            // 配置 HTTP 协议头
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            String resultBody = response.getBody();

            if (response.getStatusCode() == HttpStatus.OK) {
                if (resultBody != null && resultBody.contains("\"errcode\":0")) {
                    System.out.println("[钉钉中心] 「" + title + "」已穿透公网，准确送达管理员个人终端！");
                } else {
                    System.err.println("[钉钉中心] 握手成功但推送受阻！钉钉回复原始码：" + resultBody);
                    System.err.println("随从提示：");
                    System.err.println("   - errcode 310000：管理员，钉钉机器人后台的「关键词」里得加上“柠安”或“告警”！");
                    System.err.println("   - errcode 40014：加签密钥（Secret）可能输错了，请管理员检查！");
                }
            } else {
                System.err.println("[钉钉中心] 网络链路中断！HTTP 响应码: " + response.getStatusCode());
            }

        } catch (Exception e) {
            System.err.println("[钉钉中心] 发射舱发生突发逻辑崩溃：" + e.getMessage());
            e.printStackTrace();
        }
    }
}