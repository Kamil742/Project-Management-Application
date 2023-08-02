package com.projectmanagement.security;

import com.projectmanagement.config.CustomSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class AppSecurity {
    @Autowired
    private CustomSuccessHandler successHandler;
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/app/v1/login").permitAll()
                .antMatchers("/forgot-password/**").permitAll()
                .antMatchers("/admin/**").hasAuthority("Employee_Write")
                .antMatchers("/department/**").hasAuthority("Employee_Write")
                .antMatchers("/project/**").hasAuthority("Employee_Write")
                .antMatchers("/employee/**").hasAuthority("Employee_Read")
                .antMatchers("/suggestion/**").hasAnyAuthority("Employee_Write","Employee_Read")
                .and()
                .formLogin()
                .loginPage("/app/v1/login").permitAll()
                .successHandler(successHandler)
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                .clearAuthentication(true).invalidateHttpSession(true)
                .deleteCookies("JSESSIONID").logoutSuccessUrl("/app/v1/login");
        return httpSecurity.build();

    }
}
