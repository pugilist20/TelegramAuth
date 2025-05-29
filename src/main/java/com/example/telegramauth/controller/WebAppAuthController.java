package com.example.telegramauth.controller;

import com.example.telegramauth.entity.User;
import com.example.telegramauth.service.TelegramAuthService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class WebAppAuthController {

    private static final Logger log = LoggerFactory.getLogger(WebAppAuthController.class);

    private final TelegramAuthService authService;

    @PostMapping("/auth")
    public ResponseEntity<?> authenticate(@RequestBody Map<String, String> body) {
        String initData = body.get("initData");
        Map<String, String> params = Arrays.stream(initData.split("&"))
                .map(s -> s.split("=", 2))
                .collect(Collectors.toMap(a -> a[0], a -> a[1]));

        try {
            User saved = authService.authenticateAndSave(params);
            log.info("Authenticated and saved user: {}", saved);
            return ResponseEntity.ok(saved);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            log.error("Crypto error during auth", e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        } catch (Exception e) {
            log.error("Authentication failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
