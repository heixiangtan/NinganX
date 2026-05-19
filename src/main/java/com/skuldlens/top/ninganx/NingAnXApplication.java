package com.skuldlens.top.ninganx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.amqp.RabbitAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestTemplate;

/**
 * 管理中心启动入口
 * 异步告警、定时简报、ORM 映射与全域资源调度
 */
@SpringBootApplication(exclude = {
        RabbitAutoConfiguration.class
})
@EnableAsync         // 异步通道：钉钉战报
@EnableScheduling    // 定时引擎：24小时每日简报
@MapperScan("com.skuldlens.top.ninganx.honeypot.mapper")
public class NingAnXApplication {

    public static void main(String[] args) {
        SpringApplication.run(NingAnXApplication.class, args);

        System.out.println("====================================================");
        System.out.println("[柠安 X] 指挥中心已全线通电，正在同步卫星数据...");
        System.out.println(" 全域告警雷达：已就绪 (ACTIVE)");
        System.out.println(" 24H 每日简报：已装载 (SCHEDULED)");
        System.out.println(" IPS 防御矩阵：已上线 (DEFENDER ONLINE)");
        System.out.println("====================================================");
        System.out.println("报告管理员！「柠安 X」已经接管该防区，请下达后续指令！️");
    }

    /**
     * 公网穿透
     */
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}