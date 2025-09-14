package com.example.spring_jwt_example.controller;

import com.example.spring_jwt_example.jwt.JwtService;
import com.example.spring_jwt_example.model.Service.AppUserService;
import com.example.spring_jwt_example.model.dto.AppUserDTO;
import com.example.spring_jwt_example.model.request.AuthenticationRequest;
import com.example.spring_jwt_example.model.request.RegisterRequest;
import com.example.spring_jwt_example.model.response.ApiResponse;
import com.example.spring_jwt_example.model.response.AuthenticationResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auths")
@RequiredArgsConstructor
public class AppUserController {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AppUserService appUserService;

    private void authenticate(String email, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid  @RequestBody RegisterRequest request ) {
        AppUserDTO appUserDTO = appUserService.create(request);
       return ResponseEntity.ok().body(
               ApiResponse.builder()
                        .success(true)
                        .message("User registered successfully")
                        .payload(appUserDTO)
                        .httpStatus(HttpStatus.CREATED)
                        .build()

       );
    }
    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@Valid @RequestBody AuthenticationRequest request) throws Exception {
        final UserDetails user = appUserService.loadUserByUsername(request.getLogin());
        final String token = jwtService.generateToken(user);
        if(user == null){
            throw new BadCredentialsException("INVALID_CREDENTIALS");
        }
        if(user.getPassword().equals(token)){
            throw new BadCredentialsException("INVALID_CREDENTIALS");
        }
       authenticate(request.getLogin(),request.getPassword());
        try{
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getLogin(),request.getPassword());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        AuthenticationResponse response = new AuthenticationResponse(token);
        return ResponseEntity.ok().body(
                ApiResponse.builder()
                        .success(true)
                        .message("User logged in successfully")
                        .httpStatus(HttpStatus.OK)
                        .payload(response)
                        .build()
        );
    }
}
