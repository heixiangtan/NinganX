项目界面展示
态势大屏：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/8fd80a8c-c6c1-481b-bb5e-9be6cc12b02a" />
流量审计：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/19d488b3-252f-42f3-b106-4d15d40b10f2" />
样本分析：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/22d05fe5-7512-43c2-856a-ed2f59819ff0" />
蜜罐管理：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/2a64f782-e3c3-42fe-be43-5df98a330cff" />
封禁列表：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/8b0ce214-f63a-4cdd-a572-37c518193999" />
告警/系统设置：
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/91975f54-1092-4e32-b1db-9cb494e456a1" />
<img width="2560" height="1187" alt="image" src="https://github.com/user-attachments/assets/3f37e311-89f4-4b92-aaf2-930e04ffb6d2" />

###  部署指南 (Deployment Guide)

#### 1. 环境配置与脱敏修改
在启动项目前，请务必根据实际运行环境修改以下核心配置文件信息：

* **数据库及基础配置** (`src/main/resources/application.properties`):
<img width="869" height="223" alt="image" src="https://github.com/user-attachments/assets/9f950417-dcea-44f4-aa46-44e80babc9fb" />

* **诱捕引擎配置** (`PhantomStreamEngine`):
<img width="866" height="160" alt="image" src="https://github.com/user-attachments/assets/0d5d3ef9-7c23-4226-a80c-50e7b5cd1427" />

* **AI 分析接口配置** (`AIAnalyzeController`):
<img width="763" height="159" alt="image" src="https://github.com/user-attachments/assets/98e39820-7283-4672-be30-508491bd8dae" />

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
