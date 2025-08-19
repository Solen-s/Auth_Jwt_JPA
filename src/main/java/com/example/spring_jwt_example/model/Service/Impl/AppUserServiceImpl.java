package com.example.spring_jwt_example.model.Service.Impl;


import com.example.spring_jwt_example.model.dto.AppUserDTO;
import com.example.spring_jwt_example.model.entity.AppUser;
import com.example.spring_jwt_example.model.Service.AppUserService;
import com.example.spring_jwt_example.model.request.RegisterRequest;
import com.example.spring_jwt_example.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;



@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {
    private final AppUserRepository appUserRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with email: " + username)
                );
    }

    @Override
    public AppUserDTO create(RegisterRequest request) {
        AppUser appUser = new AppUser();
        appUser.setUsername(request.getUsername());
        appUser.setPassword(passwordEncoder.encode(request.getPassword()));
        appUser.setEmail(request.getEmail());
        appUser.setFirstName(request.getFirstName());
        appUser.setLastName(request.getLastName());
        appUser.setRole(request.getRole());
        request.setPassword(passwordEncoder.encode(request.getPassword()));

        AppUser savedAppUser = appUserRepository.save(appUser);

        return modelMapper.map(savedAppUser, AppUserDTO.class);
    }
}
