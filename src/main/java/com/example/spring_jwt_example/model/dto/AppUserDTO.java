package com.example.spring_jwt_example.model.dto;

import com.example.spring_jwt_example.model.entity.Role;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AppUserDTO {

    private Long id;
    private String username;

    private String firstName;

    private String lastName;

    private String email;

    private Role role;
}