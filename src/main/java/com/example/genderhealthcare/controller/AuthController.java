package com.example.genderhealthcare.controller;

import com.example.genderhealthcare.security.CustomUserDetails;
import com.example.genderhealthcare.security.JwtUtil;
import com.example.genderhealthcare.service.CustomUserDetailsService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @GetMapping("/login")
    public String loginPage() {
        return "login-view";
    }

    @PostMapping("/authenticate")
    public String authenticate(@RequestParam String username,
                               @RequestParam String password,
                               HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = jwtUtil.generateToken(username);
            Cookie cookie = new Cookie("jwt", token);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String role = userDetails.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");

            return switch (role) {
                case "CUSTOMER" -> "redirect:/customer/home";
                default -> "redirect:/login?error=true";
            };
        } catch (Exception e) {
            e.printStackTrace(); // Thêm dòng này để in lỗi ra console
            return "redirect:/login?error=true";
        }
    }
}
