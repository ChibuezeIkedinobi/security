package com.ikedi.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component     // a managed bean
@RequiredArgsConstructor  // a constructor using any final fields
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;  // Locates the user based on the username

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,  // our request
            @NonNull HttpServletResponse response,  // our response
            @NonNull FilterChain filterChain    // list of other filers we need
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");   // header that contains jwtToken
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {   // check for the availability of a token
            filterChain.doFilter(request, response);
            return;
        }

        // next is to extract the token and check if user is present in the database or not
        // first, jwtService will extract the user email

        jwt = authHeader.substring(7);       // bearer is 6 plus the space making it 7
        userEmail =  jwtService.extractUsername(jwt);     // extract the userEmail from JWT token

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {   // check if user is not authenticated yet
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);  // check if we have the user in the database

            if (jwtService.isTokenValid(jwt, userDetails)) {  // if user and token is valid
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);  //update security context holder
            }
            filterChain.doFilter(request, response);
        }
    }


}
