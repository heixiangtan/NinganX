package com.skuldlens.top.ninganx.honeypot.core;

public interface Honeypot {
    String getName();        // 获取蜜罐名字，比如 "SSH"
    void start();           // 开启监听
    void stop();            // 彻底断开监听
    boolean isRunning();    // 获取当前运行状态
}