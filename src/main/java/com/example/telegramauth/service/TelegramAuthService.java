package com.example.telegramauth.service;

import com.example.telegramauth.entity.User;
import com.example.telegramauth.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

@Service
@RequiredArgsConstructor
public class TelegramAuthService {

    private static final Logger log = LoggerFactory.getLogger(TelegramAuthService.class);

    private final UserRepository userRepo;
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${telegram.bot.token}")
    private String botToken;

    public User authenticateAndSave(Map<String, String> initData)
            throws NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
        log.info("Зашёл");

        ensureRequiredFields(initData);

        long authTs = parseAndValidateTimestamp(initData.get("auth_date"));

        verifySignature(initData);

        User user = parseUser(initData.get("user"), authTs);
        return userRepo.save(user);
    }

    private void ensureRequiredFields(Map<String,String> data) {
        List<String> required = List.of("user","auth_date","hash");
        for (String key : required) {
            if (!data.containsKey(key)) {
                throw new IllegalArgumentException("Missing initData field: " + key);
            }
        }
    }

    private long parseAndValidateTimestamp(String authDate) {
        long ts = Long.parseLong(authDate);
        if (Instant.now().getEpochSecond() - ts > 86_400) {
            throw new IllegalArgumentException("Data is too old");
        }
        return ts;
    }

    private void verifySignature(Map<String,String> data)
            throws NoSuchAlgorithmException, InvalidKeyException {

        String received = data.get("hash");

        String dataString = data.entrySet().stream()
                .filter(e -> !"hash".equals(e.getKey()))
                .sorted(Map.Entry.comparingByKey())
                .map(e -> e.getKey() + "=" + URLDecoder.decode(e.getValue(), UTF_8))
                .collect(joining("\n"));

        Mac keyMac = Mac.getInstance("HmacSHA256");
        keyMac.init(new SecretKeySpec("WebAppData".getBytes(UTF_8), "HmacSHA256"));
        byte[] secret = keyMac.doFinal(botToken.getBytes(UTF_8));

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] h = mac.doFinal(dataString.getBytes(UTF_8));

        String generated = bytesToHex(h);

        log.info("Data string to sign:\n{}", dataString);
        log.info("Generated hash      : {}", generated);
        log.info("Received hash       : {}", received);

        if (!generated.equals(received)) {
            throw new IllegalArgumentException("Data signature invalid");
        }
    }

    private User parseUser(String userJsonEncoded, long authTs) throws JsonProcessingException {
        String userJson = URLDecoder.decode(userJsonEncoded, UTF_8);
        Map<String,Object> m = mapper.readValue(userJson, new TypeReference<>(){});
        User u = new User();
        u.setId(((Number)m.get("id")).longValue());
        u.setFirstName((String)m.get("first_name"));
        u.setLastName((String)m.get("last_name"));
        u.setUsername((String)m.get("username"));
        u.setAuthDate(authTs);
        return u;
    }

    private static String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
