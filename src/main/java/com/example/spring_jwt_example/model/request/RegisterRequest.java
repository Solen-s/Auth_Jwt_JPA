package com.example.spring_jwt_example.model.request;

import com.example.spring_jwt_example.model.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @Size(min = 3, message = "Username must be required or more than 3 characters.")
    private String username;

    @Size(min=3, message = "First name must be required or more than 3 characters.")
    private String firstName;

    @Size(min=3, message = "Last name must be required or more than 3 character.s")
    private String lastName;

    @Email
    private String email;

    @Size(min=8, message = "Password must be required or more than 8 characters.")
    private String password;

    @NotNull
    private Role role;
}
