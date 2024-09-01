package com.sharda.springSecurity.security;

import com.sharda.springSecurity.auth.ApplicationUserService;
import com.sharda.springSecurity.jwt.JwtConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import com.sharda.springSecurity.jwt.JwtTokenVerifier;
import com.sharda.springSecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import javax.crypto.SecretKey;

import static com.sharda.springSecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey,
    JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }


//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(csrf -> csrf.disable())
////                Jwt Authentication
//                .sessionManagement(sessionManagement ->
//                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
//                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
//                .authorizeHttpRequests(authorizeRequests ->
//                        authorizeRequests
//                                .requestMatchers("/", "index", "/css/*", "/js/*").permitAll()
//                                .requestMatchers("/api/**").hasRole(STUDENT.name())
//                                  //commenting below line because I am using @preAuthorise instead of this
////                                .requestMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                                .requestMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                                .requestMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                                .requestMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
//                                .anyRequest().authenticated()
//                );
////         Basic Authentication
////                .httpBasic(withDefaults());
////        form based authentication
////                .formLogin(form -> form
////                        .loginPage("/login")
////                        .permitAll()
////                        .defaultSuccessUrl("/courses",true)
////                        .passwordParameter("password")
////                        .usernameParameter("username")
////                )
////                .rememberMe(rememberMe -> rememberMe
////                        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
////                        .key("somethingverysecured")
////                        .rememberMeParameter("remember-me")
////                )
////                .logout(logout -> logout
////                        .logoutUrl("/logout")
////                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
////                        .clearAuthentication(true)
////                        .invalidateHttpSession(true)
////                        .deleteCookies("JSESSIONID", "remember-me")
////                        .logoutSuccessUrl("/login"));
////
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                // JWT Authentication
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager, jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/", "index", "/css/*", "/js/*").permitAll()
                                .requestMatchers("/api/**").hasRole(STUDENT.name())
                                .anyRequest().authenticated()
                );
        return http.build();
    }



    //@Bean
        protected UserDetailsService userDetailsService() {
            UserDetails shardaUser = User.builder()
                    .username("sharda")
                    .password(passwordEncoder.encode("password"))
                    .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
                    .authorities(STUDENT.getGrantedAuthorities())
                    .build();

            UserDetails lindaUser = User.builder()
                    .username("sneha")
                    .password(passwordEncoder.encode("password123"))
                    .roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN
                    .authorities(ADMIN.getGrantedAuthorities())
                    .build();

            UserDetails tomUser = User.builder()
                    .username("tom")
                    .password(passwordEncoder.encode("password123"))
                    .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
                    .authorities(ADMINTRAINEE.getGrantedAuthorities())
                    .build();

            return new InMemoryUserDetailsManager(
                    shardaUser,
                    lindaUser,
                    tomUser
            );
        }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(daoAuthenticationProvider())
                .build();
    }


    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }


}
