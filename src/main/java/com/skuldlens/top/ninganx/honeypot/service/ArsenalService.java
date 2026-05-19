package com.skuldlens.top.ninganx.honeypot.service;

import com.skuldlens.top.ninganx.honeypot.mapper.AuditMapper;
import com.skuldlens.top.ninganx.honeypot.mapper.HoneyToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class ArsenalService {

    @Autowired
    private AuditMapper auditMapper;

    /**
     * 生成并埋设一个唯一的诱饵
     * @param type 诱饵类型 (SSH_KEY / REDIS_PASS / AWS_ACCESS)
     * @param comment 备注
     */
    public String deployNewBait(String type, String comment) {
        String tokenValue = "NX-" + type.toUpperCase() + "-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        
        // 构建诱饵实体存档
        HoneyToken token = new HoneyToken();
        token.setId(UUID.randomUUID().toString());
        token.setTokenValue(tokenValue);
        token.setTokenType(type);
        token.setCreatedTime(LocalDateTime.now());
        token.setComment(comment);
        token.setIsActive(1);
        token.setTriggeredCount(0);

        // 写入数据库档案库
        auditMapper.insertHoneyToken(token);
        
        System.out.println("诱饵已埋设: " + tokenValue + " ！");
        return tokenValue;
    }

    public boolean removeBait(String id) {
        try {
            auditMapper.deleteHoneyToken(id);
            System.out.println("编号为 " + id + " 的诱饵已被物理销毁！");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取所有活跃诱饵的状态
     */
    public List<HoneyToken> getAllActiveTokens() {
        return auditMapper.selectAllHoneyTokens();
    }
}