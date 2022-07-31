package com.practice.rin.security;

import com.practice.rin.auth.ApplicationUserService;
import com.practice.rin.jwt.JwtConfig;
import com.practice.rin.jwt.JwtTokenVerifier;
import com.practice.rin.jwt.JwtUsernamePasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.practice.rin.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder; // configured and registered as bean
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService,
                                     JwtConfig jwtConfig,
                                     SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                // so it won't be store in Database as it is stateless
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // by default we have access to authenticationManager() method as we extended WebSecurityConfigurerAdapter
                .addFilter(new JwtUsernamePasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernamePasswordAuthenticationFilter.class)
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
                .authenticated();

                //basic authentication
//                .httpBasic();
                //for based authentication
//                .formLogin()
//                    .loginPage("/login").permitAll()
//                        .defaultSuccessUrl("/features", true)
//                        .usernameParameter("username") // change in login.html if changed ex:"user"
//                        .passwordParameter("password")
//                .and()
//                .rememberMe() // expires after 2 weeks (default)
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // session id expires after 21 days (customized)
//                    .key("somethingverysecured")
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                // use below when csrf disabled(similar to above anyway). If csrf enabled, only use POST method(recommended)
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");

    }

    // this is how you wire things up
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    // this pretty much is an auth provider
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails rin = User.builder()
//                .username("Rin")
//                .password(passwordEncoder.encode("pass1"))
////                .roles(SE.name()) //ROLE_SOFTWARE_ENGINEER
//                .authorities(SE.getGrantedAuthorities())
//                .build();
//
//        UserDetails linda = User.builder()
//                .username("Linda")
//                .password(passwordEncoder.encode("pass2"))
////                .roles(ADMIN.name()) //ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails rio = User.builder()
//                .username("Rio")
//                .password(passwordEncoder.encode("pass3"))
////                .roles(SSE.name()) //ROLE_SENIOR_SOFTWARE_ENGINEER
//                .authorities(SSE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(rin, linda, rio);
//    }
}
