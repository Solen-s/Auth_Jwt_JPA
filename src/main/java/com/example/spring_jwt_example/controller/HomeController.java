package com.example.spring_jwt_example.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/home")
@SecurityRequirement(name = "bearerAuth")
@CrossOrigin()
public class HomeController {
    @GetMapping("/home")
    public String home() {
        return "hello";
    }
}
