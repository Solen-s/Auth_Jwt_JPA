package com.example.spring_jwt_example.model.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private HttpStatus httpStatus;
    private T payload;
    @Builder.Default
    private Instant timestamp = Instant.now();
}
