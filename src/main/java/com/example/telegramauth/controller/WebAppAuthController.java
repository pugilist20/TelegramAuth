package com.example.telegramauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import com.example.telegramauth.entity.User;
import com.example.telegramauth.service.TelegramAuthService;
import com.example.telegramauth.repository.UserRepository;
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
public class WebAppAuthController {

    private static final Logger log = LoggerFactory.getLogger(WebAppAuthController.class);

    private final TelegramAuthService authService;
    private final UserRepository userRepo;

    public WebAppAuthController(TelegramAuthService authService,
                                UserRepository userRepo) {
        this.authService = authService;
        this.userRepo = userRepo;
    }

    @PostMapping("/auth")
    public ResponseEntity<?> authenticate(
            @RequestBody Map<String, String> body,
            HttpServletRequest request
    ) {

        StringBuffer url = request.getRequestURL();
        String qs = request.getQueryString();
        log.info("Incoming request URL: {}{}", url, (qs != null ? "?" + qs : ""));


        String initData = body.get("initData");
        log.info("Received initData string: {}", initData);


        Map<String, String> params = Arrays.stream(initData.split("&"))
                .map(s -> s.split("=", 2))
                .collect(Collectors.toMap(a -> a[0], a -> a[1]));
        log.info("Parsed initData params: {}", params);

        try {
            User user = authService.validateAndExtract(params);
            userRepo.save(user);
            log.info("Authenticated user: {}", user);
            return ResponseEntity.ok(user);
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("Authentication failed: {}", e.getMessage());
            return ResponseEntity
                    .badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }
}
