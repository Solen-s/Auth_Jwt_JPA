package com.example.spring_jwt_example.exception;



import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import javax.naming.AuthenticationException;
import java.net.URI;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import org.springframework.http.converter.HttpMessageNotReadableException;

import java.util.Arrays;


@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(NotFoundException.class)
    public ProblemDetail handleNotFoundException(NotFoundException e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler({NotVerifiedException.class, InvalidException.class})
    public ProblemDetail handleNotVerifiedException(Exception e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
        problemDetail.setTitle("Bad Request");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }
    @ExceptionHandler(InvalidFormatException.class)
    public ProblemDetail handleInvalidFormat(InvalidFormatException ex, HttpServletRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setTitle("Bad Request");
        problemDetail.setType(URI.create("about:blank"));
        problemDetail.setStatus(HttpStatus.BAD_REQUEST.value());
        problemDetail.setInstance(URI.create(request.getRequestURI()));
        problemDetail.setProperty("timestamp", OffsetDateTime.now());

        Map<String, String> errors = new HashMap<>();
        if (!ex.getPath().isEmpty()) {
            String fieldName = ex.getPath().get(0).getFieldName();
            errors.put(fieldName, "Invalid value: " + ex.getValue());
        } else {
            errors.put("error", "Invalid input");
        }
        problemDetail.setProperty("error", errors);

        return problemDetail;
    }
    //     Handle validation errors for @Valid
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidationException(MethodArgumentNotValidException ex) {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setTitle("Validation Failed");
        problemDetail.setProperty("timestamp", LocalDateTime.now());

        // Collect field validation errors
        Map<String, String> errors = new HashMap<>();
        int blankFieldErrors = 0;

        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            errors.put(fieldError.getField(), fieldError.getDefaultMessage());

            // Check if the error is specifically "must not be blank"
            if ("must not be blank".equals(fieldError.getDefaultMessage())) {
                blankFieldErrors++;
            }

        }

        // Add errors to ProblemDetail as extra properties
        problemDetail.setProperty("errors", errors);

        return problemDetail;
    }


    @ExceptionHandler(HandlerMethodValidationException.class)
    public ProblemDetail handleMethodValidationException(HandlerMethodValidationException e) {
        Map<String, String> errors = new HashMap<>();

        // Loop through each invalid parameter validation result
        e.getParameterValidationResults().forEach(parameterError -> {
            String paramName = parameterError.getMethodParameter().getParameterName(); // Get parameter name

            // Loop through each validation error message for this parameter
            for (var messageError : parameterError.getResolvableErrors()) {
                errors.put(paramName, messageError.getDefaultMessage()); // Store error message
            }
        });

        // Create structured ProblemDetail response
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setTitle("Method Parameter Validation Failed");
        problemDetail.setProperties(Map.of("timestamp", LocalDateTime.now(), "errors", errors // Attach validation errors
        ));

        return problemDetail;
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        Throwable rootCause = ex.getRootCause();
        String detailMessage = "Data integrity violation.";
        HttpStatus status = HttpStatus.CONFLICT;
        Map<String, String> fields = new HashMap<>();


        String message = rootCause.getMessage();

        if (message.contains("app_users_email_key")) {
            fields.put("email", "Email has already existed.");
        }
        if (message.contains("app_users_username_key")) {
            fields.put("name", "Name has already been taken.");
        }


        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detailMessage);
        problem.setTitle("Duplicate Field");

        problem.setProperty("fields", fields);

        return problem;
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        Throwable cause = ex.getCause();

        if (cause instanceof InvalidFormatException invalidFormatEx) {
            // Check if the cause is specifically an Enum type error
            Class<?> targetType = invalidFormatEx.getTargetType();

            if (targetType.isEnum()) {
                Object[] enumConstants = targetType.getEnumConstants();
                String allowedValues = Arrays.stream(enumConstants)
                        .map(Object::toString)
                        .collect(Collectors.joining(", "));

                String invalidValue = String.valueOf(invalidFormatEx.getValue());

                // Create a ProblemDetail with the custom error message
                ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
                problem.setTitle("Bad Request");
                problem.setDetail(String.format("JSON parse error: Cannot deserialize value of type '%s' from String \"%s\": not one of the values accepted for Enum class: [%s]",
                        targetType.getName(), invalidValue, allowedValues));
                problem.setProperty("timestamp", OffsetDateTime.now());
                return problem;
            }
        }

        // Fallback for other JSON parsing errors
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setTitle("Bad Request");
        problem.setDetail("Invalid request body.");
        problem.setProperty("timestamp", OffsetDateTime.now());
        return problem;
    }


}
