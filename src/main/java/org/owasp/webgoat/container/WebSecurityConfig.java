/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import lombok.AllArgsConstructor;
import org.owasp.webgoat.container.users.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/** Security configuration for WebGoat. */
@Configuration
@AllArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig {

  private final UserService userDetailsService;

  /**
   * Registration is publicly accessible and switches the authenticated identity of the browser:
   * {@code /register.mvc} logs the current user out and logs the newly created user in. Without
   * CSRF protection a page on another site can auto-submit a registration form and silently log the
   * victim's browser into an account the attacker knows the credentials of (login CSRF).
   *
   * <p>Therefore CSRF protection is enabled for the registration endpoints. This is done in a
   * dedicated filter chain which only matches those endpoints, so the rest of WebGoat keeps
   * behaving exactly as before, including the deliberately vulnerable CSRF lessons and the login
   * CSRF lesson on {@code /login}.
   */
  @Bean
  @Order(1)
  public SecurityFilterChain registrationFilterChain(HttpSecurity http) throws Exception {
    return http.securityMatcher("/registration", "/register.mvc")
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
        // CSRF protection is on by default, it is stated explicitly here as the registration
        // endpoints must never be callable cross-site
        .csrf(Customizer.withDefaults())
        // Unlike the rest of WebGoat the default security headers are kept here, they stop the
        // page carrying the token from being cached or framed. HSTS is left out, WebGoat is
        // normally served over plain HTTP on localhost.
        .headers(headers -> headers.httpStrictTransportSecurity(hsts -> hsts.disable()))
        .build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(
            auth ->
                auth.requestMatchers(
                        "/favicon.ico",
                        "/css/**",
                        "/images/**",
                        "/js/**",
                        "/fonts/**",
                        "/plugins/**",
                        "/actuator/**")
                    .permitAll()
                    // The registration endpoints are served by registrationFilterChain, denying
                    // them here makes sure they can never be reached through this chain, which
                    // has CSRF protection disabled
                    .requestMatchers("/registration", "/register.mvc")
                    .denyAll()
                    .anyRequest()
                    .authenticated())
        .formLogin(
            login ->
                login
                    .loginPage("/login")
                    .defaultSuccessUrl("/welcome.mvc", true)
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .permitAll())
        .oauth2Login(
            oidc -> {
              oidc.defaultSuccessUrl("/login-oauth.mvc");
              oidc.loginPage("/login");
            })
        .logout(logout -> logout.deleteCookies("JSESSIONID").invalidateHttpSession(true))
        .csrf(csrf -> csrf.disable())
        .headers(headers -> headers.disable())
        .exceptionHandling(
            handling ->
                handling.authenticationEntryPoint(new AjaxAuthenticationEntryPoint("/login")))
        .build();
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
  }

  @Bean
  @Primary
  public UserDetailsService userDetailsServiceBean() {
    return userDetailsService;
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public NoOpPasswordEncoder passwordEncoder() {
    return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
  }
}
