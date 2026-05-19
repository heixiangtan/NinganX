package com.skuldlens.top.ninganx.honeypot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web 配置中心
 * 把拦截器挂载到所有的 URL 路径上
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private BanInterceptor banInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 要排除静态资源，否则大屏的 CSS/JS 可能会加载不出来
        registry.addInterceptor(banInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/css/**", "/js/**", "/img/**", "/favicon.ico");
    }
}