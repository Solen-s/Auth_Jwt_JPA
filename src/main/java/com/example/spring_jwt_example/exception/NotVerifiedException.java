package com.example.spring_jwt_example.exception;

public class NotVerifiedException extends RuntimeException {
    public NotVerifiedException(String message) {
        super(message);
    }
}
