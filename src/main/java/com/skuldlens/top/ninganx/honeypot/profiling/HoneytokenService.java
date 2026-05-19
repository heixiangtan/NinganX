package com.skuldlens.top.ninganx.honeypot.profiling;

import com.skuldlens.top.ninganx.honeypot.core.AlertService;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

@Service
public class HoneytokenService implements AlertService {
    private static final String HONEYTOKEN_PATH = "./captures/honeytoken-config.json";

    public void generateHoneytoken() {
        try {
            File honeytoken = new File(HONEYTOKEN_PATH);
            if (honeytoken.createNewFile()) {
                try (FileWriter writer = new FileWriter(honeytoken)) {
                    writer.write("{ \"username\": \"admin\", \"password\": \"password123\" }");
                }
                System.out.println("Honeytoken generated at: " + HONEYTOKEN_PATH);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void triggerAlert(String message) {
        System.out.println("ALERT: " + message);
    }
}