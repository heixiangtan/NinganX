package com.skuldlens.top.ninganx.honeypot.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {
    private String id;
    private String protocol;
    private String remoteIp;
    private String location;
    private String fullLocation;
    private Double lng;
    private Double lat;
    private String detail;
    private LocalDateTime time;
    private Integer level;      // 0:蓝, 1:橙, 2:红
    private Integer attackCount;
}