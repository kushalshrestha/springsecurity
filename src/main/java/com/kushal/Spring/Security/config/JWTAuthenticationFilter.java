package com.kushal.Spring.Security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        //1. check JWT token passed
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // passing to the next filter
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);

        /*
          extract the userEmail from JWT token. So we need to extract
          userEmail from JWT token. How? You need to create a class that can manipulate JWT token.
         */
        userEmail = jwtService.extractUsername(jwt);

        // if authentication check is null
        if (userEmail != null && SecurityContextHolder.getContext()
                                                      .getAuthentication() == null) {
            // creating our own loadUserByUsername in ApplicationConfig i.e getting userdetail from database.
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // update the security context and send it to Dispatcher Servlet
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //update the security context
                SecurityContextHolder.getContext()
                                     .setAuthentication(authToken);

            }
        }
        // passing to next filter
        filterChain.doFilter(request, response);
    }
}
