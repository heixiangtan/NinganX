USE ninganx;

-- ️ 审计日志表
CREATE TABLE IF NOT EXISTS `audit_log` (
                                           `id` varchar(64) NOT NULL COMMENT 'UUID主键',
                                           `protocol` varchar(10) NOT NULL COMMENT '协议：WEB/SSH/REDIS',
                                           `remote_ip` varchar(45) NOT NULL COMMENT '攻击者IP',
                                           `location` varchar(255) DEFAULT 'Unknown' COMMENT '地理位置',
                                           `lng` double DEFAULT '0' COMMENT '经度',
                                           `lat` double DEFAULT '0' COMMENT '纬度',
                                           `detail` text COMMENT '攻击详情(账号/密码/指令等)',
                                           `time` datetime NOT NULL COMMENT '时间',
                                           `level` int DEFAULT '0',
                                           `full_location` varchar(255) DEFAULT NULL,
                                           PRIMARY KEY (`id`),
                                           KEY `idx_time` (`time`),
                                           KEY `idx_ip` (`remote_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `honey_tokens` (
                                              `id` varchar(64) NOT NULL COMMENT 'UUID主键',
                                              `token_value` varchar(128) NOT NULL COMMENT '诱饵唯一标识/特征码',
                                              `token_type` varchar(20) NOT NULL COMMENT '诱饵类型：CREDENTIAL/CONFIG/SSH_KEY',
                                              `created_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              `is_active` tinyint(1) DEFAULT '1',
                                              `triggered_count` int DEFAULT '0' COMMENT '被触发次数',
                                              `comment` varchar(255) DEFAULT NULL COMMENT '诱饵备注',
                                              PRIMARY KEY (`id`),
                                              UNIQUE KEY `idx_token` (`token_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;