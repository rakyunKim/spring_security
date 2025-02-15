package com.eazybytes.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((request) -> request.anyRequest().authenticated());
        http.authorizeHttpRequests((request) -> request
                .requestMatchers("/myAccount", "/myBalance", "/myCards").authenticated()
                .requestMatchers("/notices", "/contact","/error").permitAll());
        http.formLogin(FormLoginConfigure -> FormLoginConfigure.disable());
        http.httpBasic(withDefaults());
        return http.build();
    }
}
