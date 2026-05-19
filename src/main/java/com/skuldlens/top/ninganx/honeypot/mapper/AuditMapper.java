package com.skuldlens.top.ninganx.honeypot.mapper;

import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Map;

@Mapper
public interface AuditMapper {

    @Insert("INSERT INTO audit_log (id, protocol, remote_ip, location, lng, lat, detail, time, level, full_location) " +
            "VALUES (#{id}, #{protocol}, #{remoteIp}, #{location}, #{lng}, #{lat}, #{detail}, #{time}, #{level}, #{fullLocation})")
    int insert(AuditLog log);

    @Select("SELECT id, protocol, remote_ip as remoteIp, location, lng, lat, detail, time, level, full_location as fullLocation " +
            "FROM audit_log ORDER BY time DESC LIMIT 100")
    List<AuditLog> selectLatestLogs();

    @Select("SELECT COUNT(*) FROM audit_log")
    long countTotalAttacks();

    /**
     *  协议占比统计：让饼图转起来！
     */
    @Select("SELECT protocol, COUNT(*) as count FROM audit_log GROUP BY protocol")
    List<Map<String, Object>> countByProtocol();

    /**
     * TOP 攻击源排行
     */
    @Select("SELECT remote_ip, COUNT(*) as count FROM audit_log " +
            "GROUP BY remote_ip ORDER BY count DESC LIMIT #{limit}")
    List<Map<String, Object>> selectTopAttackersWithCount(@Param("limit") int limit);

    /**
     * 锁定筛选查询
     */
    @Select("<script>" +
            "SELECT id, protocol, remote_ip as remoteIp, location, lng, lat, detail, time, level, full_location as fullLocation " +
            "FROM audit_log " +
            "<where>" +
            "  <if test='protocol != null and protocol != \"ALL\"'> AND protocol = #{protocol} </if>" +
            "  <if test='ip != null and ip != \"\"'> AND remote_ip = #{ip} </if>" +
            "</where>" +
            "ORDER BY time DESC LIMIT #{offset}, #{size}" +
            "</script>")
    List<AuditLog> selectFilteredLogs(@Param("protocol") String protocol,
                                      @Param("ip") String ip,
                                      @Param("offset") int offset,
                                      @Param("size") int size);

    @Select("SELECT COUNT(*) FROM audit_log WHERE remote_ip = #{ip}")
    int countByIp(@Param("ip") String ip);

    /**
     * 统计过去 N 小时的攻击总数
     */
    @Select("SELECT COUNT(*) FROM audit_log WHERE time >= NOW() - INTERVAL #{hours} HOUR")
    long countRecentAttacks(@Param("hours") int hours);

    /**
     * 统计过去 N 小时的 Lv2 高危次数
     */
    @Select("SELECT COUNT(*) FROM audit_log WHERE level = 2 AND time >= NOW() - INTERVAL #{hours} HOUR")
    long countRecentHighRisk(@Param("hours") int hours);

    /**
     * 统计这 24 小时内最活跃的 3 个省份/国家
     */
    @Select("SELECT location, COUNT(*) as count FROM audit_log " +
            "WHERE time >= NOW() - INTERVAL 24 HOUR " +
            "GROUP BY location ORDER BY count DESC LIMIT 3")
    List<Map<String, Object>> selectRecentHotLocations();

    @Insert("INSERT INTO honey_tokens (id, token_value, token_type, created_time, triggered_count, is_active, comment) " +
            "VALUES (#{id}, #{tokenValue}, #{tokenType}, #{createdTime}, #{triggeredCount}, #{isActive}, #{comment})")
    void insertHoneyToken(HoneyToken token);

    @Select("SELECT id, token_value as tokenValue, token_type as tokenType, created_time as createdTime, " +
            "triggered_count as triggeredCount, is_active as isActive, comment FROM honey_tokens " +
            "ORDER BY created_time DESC")
    List<HoneyToken> selectAllHoneyTokens();

    @Update("UPDATE honey_tokens SET triggered_count = triggered_count + 1 WHERE token_value = #{tokenValue}")
    void incrementTriggerCount(@Param("tokenValue") String tokenValue);

    @Delete("DELETE FROM honey_tokens WHERE id = #{id}")
    void deleteHoneyToken(@Param("id") String id);
}