package com.example.spring_jwt_example.exception;

public class InvalidException extends RuntimeException{
    public InvalidException(String message) {
        super(message);
    }
}

