package com.skuldlens.top.ninganx.honeypot.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${ningan.admin.username}")
    private String adminUser;

    @Value("${ningan.admin.password}")
    private String adminPass;

    // 管理后台监听的物理端口9999
    private static final int ADMIN_PORT = 9999;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)

                // 路由授权规则
                .authorizeHttpRequests(auth -> auth
                        // 公共资源 & 登录入口放行
                        .requestMatchers(
                                new AntPathRequestMatcher("/admin_auth.html"),
                                new AntPathRequestMatcher("/do-admin-login"),
                                new AntPathRequestMatcher("/css/**"),
                                new AntPathRequestMatcher("/js/**"),
                                new AntPathRequestMatcher("/*.js"),
                                new AntPathRequestMatcher("/favicon.ico"),
                                new AntPathRequestMatcher("/public/**")
                        ).permitAll()

                        .requestMatchers(request -> {
                            int port = request.getServerPort();
                            String uri = request.getRequestURI();
                            return port != ADMIN_PORT && (uri.contains("dashboard") || uri.endsWith(".html"));
                        }).denyAll()

                        // 常规路径放行
                        .requestMatchers(request -> request.getServerPort() != ADMIN_PORT).permitAll()

                        // 管理端口9999的受限区域保护
                        .requestMatchers(new AntPathRequestMatcher("/dashboard.html")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/api/admin/**")).hasRole("ADMIN")

                        // 9999的所有其他路径必须认证
                        .requestMatchers(request -> request.getServerPort() == ADMIN_PORT).authenticated()
                )

                // 登出逻辑配置
                .logout(logout -> logout
                        .logoutUrl("/admin-logout")
                        .logoutSuccessUrl("/admin_auth.html")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                // 异常处理：根据端口决定是重定向还是报 404
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            if (request.getServerPort() == ADMIN_PORT) {
                                // 真实后台端口：没登录就去登录
                                response.sendRedirect("/admin_auth.html");
                            } else {
                                // 蜜罐端口：任何鉴权失败或拒绝访问都报 404
                                response.sendError(404);
                            }
                        })
                );

        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.builder()
                .username(adminUser)
                .password(adminPass)
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}