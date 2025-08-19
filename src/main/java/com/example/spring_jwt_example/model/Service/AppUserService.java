package com.example.spring_jwt_example.model.Service;

import com.example.spring_jwt_example.model.dto.AppUserDTO;

import com.example.spring_jwt_example.model.entity.AppUser;
import com.example.spring_jwt_example.model.request.RegisterRequest;
import org.springframework.security.core.userdetails.UserDetailsService;


public interface AppUserService extends UserDetailsService {
    AppUserDTO create(RegisterRequest request);


}
