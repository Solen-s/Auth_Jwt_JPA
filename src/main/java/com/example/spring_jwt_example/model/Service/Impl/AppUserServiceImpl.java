package com.example.spring_jwt_example.model.Service.Impl;


import com.example.spring_jwt_example.exception.InvalidException;
import com.example.spring_jwt_example.model.dto.AppUserDTO;
import com.example.spring_jwt_example.model.entity.AppUser;
import com.example.spring_jwt_example.model.Service.AppUserService;
import com.example.spring_jwt_example.model.entity.Role;
import com.example.spring_jwt_example.model.request.RegisterRequest;
import com.example.spring_jwt_example.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {
    private final AppUserRepository appUserRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        return appUserRepository.findByUsernameOrEmail(login, login)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with email or username: " + login)
                );
    }

    @Override
    public AppUserDTO create(RegisterRequest request, Role role) {
        // Check username exists
        if(appUserRepository.existsByEmail(request.getEmail())) {
            throw new InvalidException( request.getEmail()+ " already exists");
        }
        if(appUserRepository.existsByUsername(request.getUsername())) {
            throw new InvalidException( request.getUsername()+ " already exists");
        }
        AppUser appUser = new AppUser();
        appUser.setUsername(request.getUsername());
        appUser.setPassword(passwordEncoder.encode(request.getPassword()));
        appUser.setEmail(request.getEmail());
        appUser.setFirstName(request.getFirstName());
        appUser.setLastName(request.getLastName());
        appUser.setRole(role);
        request.setPassword(passwordEncoder.encode(request.getPassword()));

        AppUser savedAppUser = appUserRepository.save(appUser);

        return modelMapper.map(savedAppUser, AppUserDTO.class);
    }

    @Override
    public AppUser findByEmailOrUsername(String identify) {
    // Check the input contains '@', treat as email
        if(identify.contains("@")) {
            return appUserRepository.findByEmail(identify)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + identify));
        }
        // Otherwise use username
        return appUserRepository.findByUsername(identify)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + identify));
    }


}
