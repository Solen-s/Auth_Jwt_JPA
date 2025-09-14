package com.example.spring_jwt_example.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/dashboard")
@SecurityRequirement(name = "bearerAuth")
@CrossOrigin()
public class dashboard {
    public String dashboard(){
        return "dashboard";
    }
}
