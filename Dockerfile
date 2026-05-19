FROM eclipse-temurin:17-jre-alpine

# 系统环境加固：时区、中文字体编码
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=Asia/Shanghai

RUN apk add --no-cache tzdata curl && \
    ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo ${TZ} > /etc/timezone

# 建立项目目录
WORKDIR /app

# 挂载点声明
# 挂载后，宿主机的配置和数据库文件即使重启也不会丢失！
VOLUME ["/app/config", "/app/logs", "/app/db"]

COPY target/*.jar app.jar

# 开启端口映射
# 8080: Web 诱饵 | 2222: SSH 蜜罐 | 6379: Redis 蜜罐 | 9999: 柠安后台
EXPOSE 8080 2222 6379 9999

# 启动指令
ENTRYPOINT ["java", \
            "-Dfile.encoding=UTF-8", \
            "-Dsun.jnu.encoding=UTF-8", \
            "-Xms256m", "-Xmx512m", \
            "-XX:+UseContainerSupport", \
            "-jar", "app.jar"]