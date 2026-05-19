package com.skuldlens.top.ninganx;

import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DefenderBattleTest {

    @Autowired
    private DefenderService defenderService;

    @Test
    void simulateEnemyAttack() {
        // 伪造一个来自外部的敌军 IP
        String enemyIp = "103.210.20.144"; 
        System.out.println("⚔️ 警告！发现敌军 IP: " + enemyIp + " 正在尝试突破防线！");

        // 模拟连续攻击，直到触发封禁阈值（假设阈值为 10）
        for (int i = 1; i <= 12; i++) {
            boolean isBanned = defenderService.checkAndBan(enemyIp);
            if (isBanned) {
                System.out.println("🔨 [第 " + i + " 次] 捕捉成功！防卫大臣已将该 IP 扭送至【战俘收容所】！️");
                break;
            } else {
                System.out.println("📊 [第 " + i + " 次] 正在记录攻击特征...");
            }
        }
    }
}