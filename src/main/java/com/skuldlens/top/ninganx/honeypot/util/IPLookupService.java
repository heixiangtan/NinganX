package com.skuldlens.top.ninganx.honeypot.util;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.lionsoul.ip2region.xdb.Searcher;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;

/**
 * 球高精度定位引擎 (GeoLite2 + ip2region)
 */
@Service
public class IPLookupService {

    private Searcher ip2regionSearcher;
    private DatabaseReader geoLiteReader;

    @PostConstruct
    public void init() {
        try {
            // 加载 ip2region：负责输出中文语义化的地名描述
            InputStream v4Stream = new ClassPathResource("data/ip2region_v4.xdb").getInputStream();
            this.ip2regionSearcher = Searcher.newWithBuffer(v4Stream.readAllBytes());
            v4Stream.close();

            // 加载 GeoLite2 City：负责抓取全球几十万城市的经纬度坐标
            InputStream geoStream = new ClassPathResource("data/GeoLite2-City.mmdb").getInputStream();
            this.geoLiteReader = new DatabaseReader.Builder(geoStream).build();

            System.out.println("====================================================");
            System.out.println("[柠安] 全球定位引擎初始化成功！");
            System.out.println("地名解析：ip2region 已就绪");
            System.out.println("坐标追踪：GeoLite2 City 已对齐");
            System.out.println("====================================================");
        } catch (Exception e) {
            System.err.println("[柠安 X] 定位库装载崩溃！请确认 data 目录下有 .xdb 和 .mmdb 文件！");
            e.printStackTrace();
        }
    }

    /**
     * 接口对齐：获取地名描述字符串
     */
    public String getLocationStr(String ip) {
        return getCityInfo(ip);
    }

    /**
     * 地名检索：返回格式化后的中文位置
     */
    public String getCityInfo(String ip) {
        if (isLocal(ip)) return "指挥部内部测试中";
        try {
            String region = ip2regionSearcher.search(ip);
            return region.replace("|0|", " ").replace("|", " ").trim();
        } catch (Exception e) {
            return "来自暗网的未知节点";
        }
    }

    /**
     * 经纬度锁定
     * GeoLite2 二进制索引中抠出精确经纬度
     */
    public double[] getCoordinates(String ip) {
        // 本地回环地址，固定在指挥部坐标
        if (isLocal(ip)) return new double[]{113.26, 23.12};

        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            CityResponse response = geoLiteReader.city(ipAddress);

            if (response != null && response.getLocation() != null) {
                Double lon = response.getLocation().getLongitude(); // 经度
                Double lat = response.getLocation().getLatitude();  // 纬度

                if (lon != null && lat != null && Math.abs(lon) > 0.0001) {
                    return new double[]{lon, lat};
                }
            }
        } catch (Exception e) {
            // 如果 GeoLite2 没查到（比如 IP 为局域网或内网段），会抛出 AddressNotFound 异常
            // 这里我们保持沉默，走下面的 [0,0] 逻辑
        }

        return new double[]{0.0, 0.0};
    }

    private boolean isLocal(String ip) {
        return ip == null || ip.equals("127.0.0.1") || ip.equals("0:0:0:0:0:0:0:1") || ip.equalsIgnoreCase("localhost");
    }

    @PreDestroy
    public void destroy() {
        try {
            if (ip2regionSearcher != null) ip2regionSearcher.close();
            if (geoLiteReader != null) geoLiteReader.close();
        } catch (IOException ignored) {}
    }
}