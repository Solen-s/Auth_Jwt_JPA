package com.example.spring_jwt_example.controller;

import com.example.spring_jwt_example.model.Service.AppUserService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1")
@SecurityRequirement(name = "bearerAuth")
@CrossOrigin()
@RequiredArgsConstructor
public class HomeController {

    @GetMapping("/home")
    public String home(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        String username ;
        //Check if principal is an instance of UserDetails
        if(auth.getPrincipal() instanceof UserDetails){
            username = ((UserDetails) auth.getPrincipal()).getUsername();
        }else{
            // If not, just use principal.toString();
            username = auth.getPrincipal().toString();
        }
        return "Hello " + username + " you've been login successfully!!😊";

    }
}
