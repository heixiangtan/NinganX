package com.skuldlens.top.ninganx.honeypot.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

@Service
@Slf4j
public class WordBaitService {

    /**
     * 提取管理员预制的“职工信息表.xlsx”
     */
    public byte[] getPredefinedExcelBait() throws IOException {
        // 文件名必须与 resources/static 下的文件名完全一致
        String fileName = "static/职工信息表.xlsx";
        ClassPathResource resource = new ClassPathResource(fileName);

        if (!resource.exists()) {
            log.error("[诱饵工厂] 找不到母本！请确保文件已放入：src/main/resources/static/职工信息表.xlsx");
            throw new IOException("Excel 诱饵母本缺失！");
        }

        try (InputStream is = resource.getInputStream();
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int b;
            while ((b = is.read(buffer)) != -1) {
                bos.write(buffer, 0, b);
            }
            log.info("[诱饵工厂] “职工信息表”提取成功，准备分发！");
            return bos.toByteArray();
        }
    }
}