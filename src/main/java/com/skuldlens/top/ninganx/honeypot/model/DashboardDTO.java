package com.skuldlens.top.ninganx.honeypot.model;

import java.util.List;
import java.util.Map;

/**
 * 态势感知数据传输对象
 */
public class DashboardDTO {
    private long totalAttacks;
    private Map<String, Long> protocolStats;
    private List<String> topIps;
    private List<AttackLocation> heatMap;

    private boolean alarmEnabled;

    public boolean isAlarmEnabled() {
        return alarmEnabled;
    }

    public void setAlarmEnabled(boolean alarmEnabled) {
        this.alarmEnabled = alarmEnabled;
    }

    public long getTotalAttacks() { return totalAttacks; }
    public void setTotalAttacks(long totalAttacks) { this.totalAttacks = totalAttacks; }

    public Map<String, Long> getProtocolStats() { return protocolStats; }
    public void setProtocolStats(Map<String, Long> protocolStats) { this.protocolStats = protocolStats; }

    public List<String> getTopIps() { return topIps; }
    public void setTopIps(List<String> topIps) { this.topIps = topIps; }

    public List<AttackLocation> getHeatMap() { return heatMap; }
    public void setHeatMap(List<AttackLocation> heatMap) { this.heatMap = heatMap; }

    /**
     * 攻击坐标内部类
     */
    public static class AttackLocation {
        private double lng;
        private double lat;

        public AttackLocation(double lng, double lat) {
            this.lng = lng;
            this.lat = lat;
        }

        public double getLng() { return lng; }
        public void setLng(double lng) { this.lng = lng; }
        public double getLat() { return lat; }
        public void setLat(double lat) { this.lat = lat; }
    }
}