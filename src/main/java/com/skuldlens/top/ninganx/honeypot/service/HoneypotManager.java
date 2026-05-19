package com.skuldlens.top.ninganx.honeypot.service;

import com.skuldlens.top.ninganx.honeypot.core.Honeypot;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class HoneypotManager {
    @Autowired
    private List<Honeypot> allHoneypots;

    // 开启/关闭指定蜜罐
    public void control(String name, boolean start) {
        allHoneypots.stream()
            .filter(h -> h.getName().equalsIgnoreCase(name))
            .findFirst()
            .ifPresent(h -> {
                if (start) h.start(); else h.stop();
            });
    }

    // 获取所有蜜罐的状态列表，发给前端显示开关
    public Map<String, Boolean> getAllStatus() {
        return allHoneypots.stream()
            .collect(Collectors.toMap(Honeypot::getName, Honeypot::isRunning));
    }
}