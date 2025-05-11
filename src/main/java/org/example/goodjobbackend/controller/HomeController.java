package org.example.goodjobbackend.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OAuth2User principal, Model model) {
        if (principal != null) {
            model.addAttribute("fullName", principal.getAttribute("fullName"));
        }
        return "home";
    }
    @GetMapping("/verify")
    public String verifyEmail() {
        return "otp-email";
    }
}