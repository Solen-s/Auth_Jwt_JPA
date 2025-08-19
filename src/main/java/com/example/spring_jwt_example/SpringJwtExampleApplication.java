package com.example.spring_jwt_example;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
@OpenAPIDefinition(info = @Info(title = "Gamified Habit Tracker API",
        version = "v1",
        description = "API documentation for the Gamified Habit Tracker application"))
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        in = SecuritySchemeIn.HEADER
)
@SpringBootApplication
@EntityScan("com.example.spring_jwt_example.model.entity")
public class SpringJwtExampleApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringJwtExampleApplication.class, args);
    }
}