package com.example.spring_jwt_example.jwt;

import com.example.spring_jwt_example.model.Service.AppUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AppUserService appUserService;


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
       final String authHeader = request.getHeader("Authorization");
       final String jwt;
       String email = null;

       if (authHeader == null || !authHeader.startsWith("Bearer ")) {
           filterChain.doFilter(request, response);
           return;
       }

       jwt = authHeader.substring(7).trim();
        // Validate JWT token is not empty and has valid format ( Should contain a least 2 periods for JWS)
       if (jwt == null || jwt.isEmpty() || jwt.isBlank()) {
           log.debug("Empty or blank JWT token in Authorization header");
           filterChain.doFilter(request, response);
           return;
       }

       // Basic format validation: JWT should have at least 2 periods (header.payload.signature)
        if (!jwt.contains(".") || jwt.split("\\.").length < 2) {
            log.warn("Malformed JWT token format (expected at least 2 periods-separated parts)");
            filterChain.doFilter(request, response);
            return;
        }
        // Skip authentication for OPTIONS requests (CORS preflight)
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            email = jwtService.extractUsername(jwt);

            if (email != null) {
                try {
                    UserDetails userDetails = appUserService.loadUserByUsername(email);
                    if (jwtService.validateToken(jwt, userDetails)) {
                        // Create authenticated token - using constructor with authorities makes it authenticated by default
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        userDetails.getAuthorities()
                                );
                        // Always set authentication if token is valid, even if one exists (replace stale auth)
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        // Ensure SecurityContext is stored (important for reactive Mono responses)
                        SecurityContextHolder.setContext(SecurityContextHolder.getContext());
                        log.info("Successfully authenticated user: {} for request: {} {} - SecurityContext set",
                                email, request.getMethod(), request.getRequestURI());
                    } else {
                        log.warn("Invalid JWT token for email: {} - token may be expired or signature invalid", email);
                        // Don't clear context here - let Spring Security handle it naturally
                        // Clearing context might cause issues with reactive Mono responses
                    }
                } catch (Exception e) {
                    log.error("Error processing JWT token for user: {} - {}", email, e.getMessage(), e);
                    // Don't clear context on error - let Spring Security handle it naturally
                    // Clearing context might cause issues with reactive Mono responses
                    // Continue filter chain - Spring Security will handle unauthorized access
                }
            }
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            log.debug("Malformed JWT token in Authorization header: {} - request will be handled by Spring Security", e.getMessage());
            // Continue filter chain - don't block request, let Spring Security handle it
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.debug("Invalid JWT signature: {} - request will be handled by Spring Security", e.getMessage());
            // Continue filter chain
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.debug("Expired JWT token: {} - request will be handled by Spring Security", e.getMessage());
            // Continue filter chain
        } catch (Exception e) {
            // Only log unexpected errors that aren't authentication-related
            String errorMsg = e.getMessage();
            if (errorMsg != null && !errorMsg.contains("JWT") && !errorMsg.contains("token")) {
                log.error("Unexpected error parsing JWT token: {}", errorMsg, e);
            } else {
                log.debug("JWT parsing error (handled by Spring Security): {}", errorMsg);
            }
            // Continue filter chain - Spring Security will handle unauthorized access
        }

        filterChain.doFilter(request, response);
    }
}
