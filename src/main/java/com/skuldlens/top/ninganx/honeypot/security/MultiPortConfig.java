package com.skuldlens.top.ninganx.honeypot.security;

import org.apache.catalina.connector.Connector;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MultiPortConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> servletContainer() {
        return server -> {
            // 给 Tomcat 增加一个额外的 8080 端口，专门用来捕获攻击流量
            Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
            connector.setPort(8080);
            server.addAdditionalTomcatConnectors(connector);
        };
    }
}