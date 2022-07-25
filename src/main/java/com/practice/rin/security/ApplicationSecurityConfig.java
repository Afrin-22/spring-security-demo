package com.practice.rin.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.practice.rin.security.ApplicationUserPermissions.*;
import static com.practice.rin.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder; // configured and registered as bean

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .authorizeRequests()
                // whitelist without having to specify username and password
                .antMatchers("/", "index", "/js/*", "/css/*").permitAll()
                //Role based authentication
                .antMatchers("/api/**").hasRole(SE.name())
                // no need as we use annotations in controller
//                .antMatchers(HttpMethod.DELETE, "/manage/api/**").hasAuthority(CODE_COMMIT.getPermission())
//                .antMatchers(HttpMethod.POST, "/manage/api/**").hasAuthority(CODE_MERGE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/manage/api/**").hasAuthority(CODE_MERGE.getPermission())
//                .antMatchers("/manage/api/**").hasAnyRole(ADMIN.name(), SSE.name())
                .anyRequest()
                .authenticated()
                .and()
                //basic authentication
//                .httpBasic();
                //for based authentication
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/features", true)
                .and()
                .rememberMe(); // default to 2 weeks

    }


    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails rin = User.builder()
                .username("Rin")
                .password(passwordEncoder.encode("pass1"))
//                .roles(SE.name()) //ROLE_SOFTWARE_ENGINEER
                .authorities(SE.getGrantedAuthorities())
                .build();

        UserDetails linda = User.builder()
                .username("Linda")
                .password(passwordEncoder.encode("pass2"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails rio = User.builder()
                .username("Rio")
                .password(passwordEncoder.encode("pass3"))
//                .roles(SSE.name()) //ROLE_SENIOR_SOFTWARE_ENGINEER
                .authorities(SSE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(rin, linda, rio);
    }
}
