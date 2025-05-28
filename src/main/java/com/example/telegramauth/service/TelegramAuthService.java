package com.example.telegramauth.service;

import com.example.telegramauth.controller.WebAppAuthController;
import com.example.telegramauth.entity.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Base64;

@Service
public class TelegramAuthService {

    private static final Logger log = LoggerFactory.getLogger(WebAppAuthController.class);

    @Value("${telegram.bot.token}")
    private String botToken;

    public User validateAndExtract(Map<String, String> initData)
            throws NoSuchAlgorithmException, InvalidKeyException {

        String userJsonEncoded = initData.get("user");
        if (userJsonEncoded == null) {
            throw new IllegalArgumentException("Missing initData field: user");
        }
        String userJson = URLDecoder.decode(userJsonEncoded, StandardCharsets.UTF_8);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> userMap;
        try {
            userMap = mapper.readValue(userJson, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid user JSON");
        }

        String id        = String.valueOf(userMap.get("id"));
        String firstName = (String) userMap.get("first_name");
        String lastName  = (String) userMap.get("last_name");
        String username  = (String) userMap.get("username");

        String authDate  = initData.get("auth_date");
        String signature = initData.get("signature");
        if (authDate == null || signature == null) {
            throw new IllegalArgumentException("Missing initData field: auth_date or signature");
        }

        long authTs = Long.parseLong(authDate);
        if (System.currentTimeMillis() / 1000 - authTs > 86400) {
            throw new IllegalArgumentException("Data is too old");
        }

        List<String> keys = new ArrayList<>(initData.keySet());
        keys.remove("signature");
        keys.remove("hash");
        Collections.sort(keys);
        StringBuilder sb = new StringBuilder();
        for (String k : keys) {
            sb.append(k).append("=").append(initData.get(k)).append("\n");
        }
        String dataString = sb.toString().trim();

        Mac keyMac = Mac.getInstance("HmacSHA256");
        keyMac.init(new SecretKeySpec(botToken.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] secretKey = keyMac.doFinal("WebAppData".getBytes(StandardCharsets.UTF_8));

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
        byte[] computed = mac.doFinal(dataString.getBytes(StandardCharsets.UTF_8));

        String generated = Base64.getUrlEncoder().withoutPadding().encodeToString(computed);

        String legacy = initData.get("hash");
        log.info("Data string to sign:\n{}", dataString);
        log.info("Generated signature: {}", generated);
        log.info("Received signature:  {}", signature);
        if (legacy != null) {
            log.info("Received legacy hash: {}", legacy);
        }

        if (!generated.equals(signature)) {
            throw new IllegalArgumentException("Data signature invalid");
        }

        User u = new User();
        u.setId(Long.parseLong(id));
        u.setFirstName(firstName);
        u.setLastName(lastName);
        u.setUsername(username);
        u.setAuthDate(authTs);
        return u;
    }
}
