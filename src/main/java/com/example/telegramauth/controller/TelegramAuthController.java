package com.example.telegramauth.controller;

import com.example.telegramauth.entity.User;
import com.example.telegramauth.repository.UserRepository;
import com.example.telegramauth.service.TelegramAuthService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@Controller
public class TelegramAuthController {

    private final TelegramAuthService authService;
    private final UserRepository userRepo;

    public TelegramAuthController(TelegramAuthService authService, UserRepository userRepo) {
        this.authService = authService;
        this.userRepo = userRepo;
    }

    @GetMapping("/")
    public String index(@RequestParam Map<String, String> initData, Model model) throws NoSuchAlgorithmException, InvalidKeyException {
        User u = authService.validateAndExtract(initData);
        userRepo.save(u);
        model.addAttribute("user", u);
        return "index";
    }
}
