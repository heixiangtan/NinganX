package com.skuldlens.top.ninganx.honeypot.model;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PayloadInfo {
    private String id;        // 文件名
    private String remoteIp;  // 来源IP
    private String time;      // 捕获时间
    private long size;        // 大小
    private String protocol;  // 协议 (REDIS/SSH)
}