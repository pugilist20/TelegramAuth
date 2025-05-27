package com.example.telegramauth.service;

import com.example.telegramauth.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Service
public class TelegramAuthService {

    @Value("${telegram.bot.token}")
    private String botToken;

    public User validateAndExtract(Map<String, String> initData) throws NoSuchAlgorithmException, InvalidKeyException {
        String hash = initData.get("hash");
        long authDate = Long.parseLong(initData.get("auth_date"));
        if (System.currentTimeMillis()/1000 - authDate > 86400) {
            throw new IllegalArgumentException("Data is too old");
        }

        List<String> keys = new ArrayList<>(initData.keySet());
        keys.remove("hash");
        Collections.sort(keys);
        StringBuilder sb = new StringBuilder();
        for (String key : keys) {
            sb.append(key).append("=").append(initData.get(key)).append("\n");
        }
        String dataCheckString = sb.toString().trim();

        byte[] secretKey = java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(botToken.getBytes());
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
        byte[] computed = mac.doFinal(dataCheckString.getBytes());
        StringBuilder hex = new StringBuilder();
        for (byte b : computed) {
            hex.append(String.format("%02x", b));
        }
        if (!hex.toString().equals(hash)) {
            throw new IllegalArgumentException("Data signature invalid");
        }

        User u = new User();
        u.setId(Long.parseLong(initData.get("id")));
        u.setFirstName(initData.get("first_name"));
        u.setLastName(initData.get("last_name"));
        u.setUsername(initData.get("username"));
        u.setAuthDate(authDate);
        return u;
    }
}
