package com.skuldlens.top.ninganx.honeypot.mapper;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class HoneyToken {
    private String id;
    private String tokenValue;    // 诱饵特征码 (如 NX-SSH-KEY-XXXX)
    private String tokenType;     // 类型 (CREDENTIAL/CONFIG/SSH_KEY)
    private LocalDateTime createdTime;
    private int triggeredCount;   // 被触发次数
    private int isActive;         // 是否启用 (1:启用, 0:停用)
    private String comment;       // 管理员备注
}