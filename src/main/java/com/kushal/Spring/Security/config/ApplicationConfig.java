package com.kushal.Spring.Security.config;

import com.kushal.Spring.Security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
//        @Override
//        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//            return null;
//        }

        //replacing by lambda and fetch user from database
//        return username -> null
        return username -> userRepository.findByEmail(username)
                                         .orElseThrow(() -> new UsernameNotFoundException("User " + "not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        //AuthenticationProvider is data access object(DAO) to fetch userdetails, encode password
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
