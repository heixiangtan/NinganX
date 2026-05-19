项目界面展示
态势大屏：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/714fc167-86cb-4faf-9f44-7becd92f9b59" />
流量审计：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/67fc8660-aa95-4715-8f4e-a633c42c5255" />
样本分析：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/3ed15102-00db-449b-a560-a75be9774528" />
蜜罐管理：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/9811f9e9-8589-4d75-b7e7-28ff0430bded" />
封禁列表：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/0cacb3e6-e20b-4e56-a912-3770659cd6f3" />
告警/系统设置：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/7ca366c7-932e-4eda-8173-d83c5f6885ff" />
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/4ab4eee8-e8b2-42ac-8289-ab4dcfc97213" />

###  部署指南 (Deployment Guide)

#### 1. 环境配置与脱敏修改
在启动项目前，请务必根据实际运行环境修改以下核心配置文件信息：

* **数据库及基础配置** (`src/main/resources/application.properties`):
<br><img width="1063" height="186" alt="Config" src="https://github.com/user-attachments/assets/99d35611-9986-4de3-b7ac-457658fd63a4" />

* **诱捕引擎配置** (`PhantomStreamEngine`):
<br><img width="962" height="139" alt="Engine" src="https://github.com/user-attachments/assets/42cf8f53-cab7-4c09-91fa-3105005c9ca6" />

* **AI 分析接口配置** (`AIAnalyzeController`):
<br><img width="805" height="123" alt="AI" src="https://github.com/user-attachments/assets/a062b912-3b5a-43ac-8465-53ac778dc30f" />

#### 2. 项目构建
在项目根目录下执行以下 Maven 指令：
```bash
mvn clean package -DskipTests

#### 3. 目录结构
构建完成后，请将生成的 JAR 包与 data（地理位置库）、init（数据库脚本）等资源文件上传至服务器。请务必确保目录结构如下所示：
ningan-x (项目根目录)
├── data (地理位置库文件)
│   ├── GeoLite2-City.mmdb
│   ├── ip2region_v4.xdb
│   └── ip2region_v6.xdb
├── init (数据库初始化配置)
│   └── setup.sql
├── target (构建产物)
│   └── NingAn-X-0.0.1-SNAPSHOT.jar
├── Dockerfile (镜像构建脚本)
└── docker-compose.yml (容器云编排配置文件)

在服务器上执行以下命令构建运行：
```bash
docker-compose up -d --build
