package com.skuldlens.top.ninganx.honeypot.deception;

import com.skuldlens.top.ninganx.honeypot.core.AuditLogger;
import com.skuldlens.top.ninganx.honeypot.core.Honeypot;
import com.skuldlens.top.ninganx.honeypot.model.AuditLog;
import com.skuldlens.top.ninganx.honeypot.service.ArsenalService;
import com.skuldlens.top.ninganx.honeypot.service.AuditService;
import com.skuldlens.top.ninganx.honeypot.util.DefenderService;
import com.skuldlens.top.ninganx.honeypot.util.IPLookupService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.channel.ChannelSession;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

import org.apache.sshd.core.CoreModuleProperties;

@Service
public class ProfessionalSshHoneypot implements Honeypot {

    private final AuditLogger auditLogger;
    private final AuditService auditService;
    private final IPLookupService ipLookupService;
    private final DefenderService defenderService;
    private final ArsenalService arsenalService;
    private SshServer sshd;
    private static final int PORT = 2222;
    private boolean isRunning = false;

    public ProfessionalSshHoneypot(AuditLogger auditLogger,
                                   AuditService auditService,
                                   IPLookupService ipLookupService,
                                   DefenderService defenderService,
                                   ArsenalService arsenalService) {
        this.auditLogger = auditLogger;
        this.auditService = auditService;
        this.ipLookupService = ipLookupService;
        this.defenderService = defenderService;
        this.arsenalService = arsenalService;
    }

    @Override
    public String getName() { return "SSH"; }

    @Override
    public boolean isRunning() { return isRunning; }

    @Override
    @PostConstruct
    public void start() {
        if (isRunning) return;

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(PORT);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get("hostkey.ser")));

        // 底层拦截逻辑
        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                String remoteIp = getCleanIp(session);
                if (defenderService.isBanned(remoteIp)) {
                    session.close(true);
                }
            }
            @Override public void sessionEvent(Session session, Event event) {}
            @Override public void sessionException(Session session, Throwable t) {}
            @Override public void sessionClosed(Session session) {}
        });

        updateBanner();

        // 身份认证防御
        sshd.setPasswordAuthenticator((username, password, session) -> {
            String remoteIp = getCleanIp(session);
            if (defenderService.checkAndBan(remoteIp)) return false;

            String location = ipLookupService.getLocationStr(remoteIp);
            double[] coords = ipLookupService.getCoordinates(remoteIp);
            reportToHeadquarters(remoteIp, location, coords, "LOGIN_ATTEMPT | User: " + username);

            boolean success = "root".equals(username) && "admin123".equals(password);
            if (!success) { try { Thread.sleep(800); } catch (InterruptedException ignored) {} }
            return success;
        });

        // 仿真Shell交互区
        sshd.setShellFactory(channel -> new Command() {
            private InputStream in;
            private OutputStream out;
            private ExitCallback exitCallback;
            // 虚拟路径状态维护
            private String currentPath = "/root";

            @Override public void setInputStream(InputStream in) { this.in = in; }
            @Override public void setOutputStream(OutputStream out) { this.out = out; }
            @Override public void setErrorStream(OutputStream err) {}
            @Override public void setExitCallback(ExitCallback callback) { this.exitCallback = callback; }
            private final java.util.Set<String> sessionCreatedDirs = new java.util.concurrent.ConcurrentSkipListSet<>();

            private String getPrompt() {
                String displayPath = currentPath.equals("/root") ? "~" : currentPath;
                return "\033[0mroot@ubuntu:" + displayPath + "# ";
            }
            @Override
            public void start(ChannelSession channel, Environment env) throws IOException {
                String remoteIp = getCleanIp(channel.getSession());
                String location = ipLookupService.getLocationStr(remoteIp);
                double[] coords = ipLookupService.getCoordinates(remoteIp);

                out.write(getPrompt().getBytes(StandardCharsets.UTF_8));
                out.flush();

                new Thread(() -> {
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
                        StringBuilder lineBuffer = new StringBuilder();
                        while (isRunning) {
                            int c = reader.read();
                            if (c == -1) break;

                            if (c == 127 || c == 8) {
                                if (lineBuffer.length() > 0) {
                                    lineBuffer.deleteCharAt(lineBuffer.length() - 1);
                                    out.write("\b \b".getBytes());
                                    out.flush();
                                }
                                continue;
                            }

                            if (c == '\r' || c == '\n') {
                                String cmd = lineBuffer.toString().trim();
                                out.write("\r\n".getBytes());

                                if ("exit".equalsIgnoreCase(cmd) || "logout".equalsIgnoreCase(cmd)) {
                                    out.write("logout\r\n".getBytes());
                                    out.flush();
                                    exitCallback.onExit(0);
                                    break;
                                }

                                if (!cmd.isEmpty()) {
                                    if (defenderService.checkAndBan(remoteIp)) {
                                        out.write("\r\nConnection closed by remote host.\r\n".getBytes());
                                        out.flush();
                                        exitCallback.onExit(0);
                                        break;
                                    }
                                    handleCommand(cmd);
                                    reportToHeadquarters(remoteIp, location, coords, "CMD_EXEC | Path: " + currentPath + " | Cmd: " + cmd);
                                }

                                out.write(getPrompt().getBytes());
                                out.flush();
                                lineBuffer.setLength(0);
                            } else {
                                out.write(c);
                                out.flush();
                                lineBuffer.append((char) c);
                            }
                        }
                    } catch (IOException ignored) {}
                }).start();
            }

            private void handleCommand(String rawCmd) throws IOException {
                String trimmed = rawCmd.trim();
                String[] parts = trimmed.split("\\s+");
                String baseCmd = parts[0].toLowerCase();
                StringBuilder sb = new StringBuilder();

                String serverIp = "8.138.176.255";
                String fakeHistory = "   80  ls /etc/nginx/sites-enabled/\r\n   81  cat /etc/nginx/nginx.conf | grep user\r\n   82  df -h\r\n   83  free -m\r\n   84  uptime\r\n   85  ping -c 4 8.8.8.8\r\n   86  cd /var/tmp\r\n   87  ls -la\r\n   88  tar -zxvf update_pkg_202604.tar.gz\r\n   89  rm -f update_pkg_202604.tar.gz\r\n   90  ls -lh\r\n   91  curl -o 职工信息表.xlsx http://" + serverIp + ":8080/职工信息表.xlsx\r\n   92  ls -l 职工信息表.xlsx\r\n   93  chmod 644 职工信息表.xlsx\r\n   94  ls -la\r\n   95  netstat -tunlp | grep 8080\r\n   96  ps aux | grep java\r\n   97  last -n 5\r\n   98  history -c && exit\r\n";

                switch (baseCmd) {
                    case "whoami" -> sb.append("root\r\n");
                    case "pwd" -> sb.append(currentPath).append("\r\n");

                    case "mkdir" -> {
                        if (parts.length < 2) {
                            sb.append("mkdir: missing operand\r\n");
                        } else {
                            String dirName = parts[1];
                            String targetPath = currentPath.endsWith("/") ? currentPath + dirName : currentPath + "/" + dirName;
                            sessionCreatedDirs.add(targetPath.replace("//", "/"));
                        }
                    }

                    case "cat" -> {
                        if (parts.length < 2) sb.append("usage: cat [file]\r\n");
                        else {
                            String fileName = parts[1];
                            if (fileName.contains("职工信息表") || fileName.contains(".xlsx")) {
                                sb.append("PK\003\004\024\000\006\000\010\000\000\000\357\276\255\336\007\007\007\375\377\261\012\022\000\000\000[Content_Types].xml\022\064\126\170\001\002\003\004\020\040\177\133\063\073\061\155\220\253\315\357\000\000\r\n");
                            } else if (fileName.contains("etc/passwd") || (currentPath.equals("/etc") && fileName.equals("passwd"))) {
                                sb.append("root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\r\n");
                            } else if (fileName.contains(".bash_history") || (currentPath.equals("/root") && fileName.equals(".bash_history"))) {
                                sb.append("cd /var/tmp\r\nls -la\r\ncurl -o 职工信息表.xlsx http://8.138.176.255:8080/职工信息表.xlsx\r\nls -la\r\nrm -rf /tmp/*\r\nexit\r\n");
                            } else {
                                sb.append("cat: ").append(fileName).append(": No such file or directory\r\n");
                            }
                        }
                    }

                    case "cd" -> {
                        if (parts.length < 2 || parts[1].equals("~") || parts[1].equals("/root")) currentPath = "/root";
                        else if (parts[1].equals("/") || parts[1].equals("..") && currentPath.length() <= 5) currentPath = "/";
                        else {
                            String target = (parts[1].startsWith("/") ? parts[1] : (currentPath.endsWith("/") ? currentPath + parts[1] : currentPath + "/" + parts[1])).replace("//", "/");
                            List<String> validDirs = List.of("/", "/root", "/var", "/tmp", "/var/tmp", "/home", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/opt", "/mnt", "/srv", "/boot");
                            if (validDirs.contains(target) || sessionCreatedDirs.contains(target)) currentPath = target;
                            else sb.append("-bash: cd: ").append(parts[1]).append(": No such file or directory\r\n");
                        }
                    }

                    case "ls" -> {
                        boolean showAll = trimmed.contains(" -a") || trimmed.contains(" -la");
                        String staticFiles = switch (currentPath) {
                            case "/" -> "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var";
                            case "/home" -> "ubuntu  admin";
                            case "/etc" -> "apt  cron.d  group  hosts  network  passwd  shadow  ssh  sudoers";
                            case "/var" -> "backups  cache  crash  lib  local  lock  log  mail  opt  run  spool  tmp";
                            case "/root" -> showAll ? ".  ..  .bash_history  .bashrc  .profile  .ssh  .cache  .viminfo  anaconda-ks.cfg  scripts  snap" : "anaconda-ks.cfg  scripts  snap";
                            case "/var/tmp", "/tmp" -> "systemd-private-mysql.service-temp-v8  职工信息表.xlsx";
                            default -> List.of("/bin", "/sbin", "/usr", "/lib", "/lib64").contains(currentPath) ? "total " + (40 + (int)(Math.random()*100)) + "\r\ndrwxr-xr-x  2 root root 4096 Apr 19 2026 ." : "total 0";
                        };
                        sb.append(staticFiles);
                        // 动态目录拼接
                        for (String dir : sessionCreatedDirs) {
                            String parent = dir.substring(0, dir.lastIndexOf("/"));
                            if (parent.isEmpty()) parent = "/";
                            if (parent.equals(currentPath)) {
                                String name = dir.substring(dir.lastIndexOf("/") + 1);
                                sb.append("  ").append(name);
                            }
                        }
                        sb.append("\r\n");
                    }

                    case "history" -> sb.append(fakeHistory);
                    default -> sb.append("-bash: ").append(baseCmd).append(": command not found\r\n");
                }

                String result = sb.toString();
                if (!result.isEmpty()) {
                    out.write(result.getBytes(StandardCharsets.UTF_8));
                }
                // 在每次输出结束后强制发送重置信号并清空缓冲区
                out.write("\033[0m".getBytes());
                out.flush();
            }

            @Override public void destroy(ChannelSession channel) {}
        });

        try {
            sshd.start();
            isRunning = true;
            System.out.println("SSH 蜜罐已就绪！端口: " + PORT);
        } catch (IOException e) {
            System.err.println("SSH 启动失败：" + e.getMessage());
        }
    }

    private void updateBanner() {
        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String bannerContent = String.format("\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic)\r\n" +
                "\r\nSystem information as of %s UTC\r\n\r\n", now);
        try {
            Path bannerPath = Paths.get("ssh_banner.txt");
            Files.writeString(bannerPath, bannerContent);
            CoreModuleProperties.WELCOME_BANNER.set(sshd, bannerPath.toUri().toString());
        } catch (IOException ignored) {}
    }

    private String getCleanIp(Session session) {
        String raw = session.getIoSession().getRemoteAddress().toString().replace("/", "");
        return raw.contains(":") ? raw.split(":")[0] : raw;
    }

    @Override
    @PreDestroy
    public void stop() {
        if (!isRunning) return;
        try { sshd.stop(); isRunning = false; } catch (IOException e) { e.printStackTrace(); }
    }

    private void reportToHeadquarters(String ip, String location, double[] coords, String detail) {
        auditLogger.logEvent("ssh", String.format("IP: %s (%s) | %s", ip, location, detail));
        AuditLog log = AuditLog.builder()
                .id(UUID.randomUUID().toString())
                .protocol("SSH")
                .remoteIp(ip)
                .location(location)
                .lng(coords[0])
                .lat(coords[1])
                .detail(detail)
                .time(LocalDateTime.now())
                .build();
        auditService.addLog(log);
    }
}