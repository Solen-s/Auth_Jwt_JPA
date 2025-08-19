package com.example.spring_jwt_example.model.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {
  @Email
  private String email;

  @Size(min = 8, message = "Password must be more required or more than 8 characters.")
  private String password;
}
