/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Locale;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.WebGoat;
import org.owasp.webgoat.container.i18n.Language;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Registration creates a user and logs the browser in as that user, a request from another site
 * must therefore never be able to reach it (login CSRF).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class RegistrationControllerTest {

  @Autowired private WebApplicationContext wac;
  @Autowired private UserRepository userRepository;

  @MockitoBean private Language language;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setup() {
    when(language.getLocale()).thenReturn(Locale.ENGLISH);
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).apply(springSecurity()).build();
  }

  @Test
  @DisplayName("The registration form contains a CSRF token")
  void registrationFormContainsCsrfToken() throws Exception {
    mockMvc
        .perform(get("/registration"))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("name=\"_csrf\"")));
  }

  @Test
  @DisplayName("Registering from the registration page logs the new user in")
  void registrationLogsTheNewUserIn() throws Exception {
    registerFromRegistrationPage("new-user-1")
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/attack"))
        .andExpect(authenticated().withUsername("new-user-1"));

    assertThat(userRepository.existsByUsername("new-user-1")).isTrue();
  }

  @Test
  @DisplayName("A form submitted from another site cannot register and log in a user")
  void crossSiteRegistrationIsRejected() throws Exception {
    mockMvc
        .perform(registration("new-user-2").header("Origin", "http://attacker.local"))
        .andExpect(status().isForbidden())
        .andExpect(unauthenticated());

    assertThat(userRepository.existsByUsername("new-user-2")).isFalse();
  }

  @Test
  @DisplayName("A token which belongs to another session is rejected")
  void registrationWithTokenOfAnotherSessionIsRejected() throws Exception {
    var tokenOfAnotherSession = csrfToken(openRegistrationPage());
    var ownSession = (MockHttpSession) openRegistrationPage().getRequest().getSession(false);

    mockMvc
        .perform(
            registration("new-user-4").session(ownSession).param("_csrf", tokenOfAnotherSession))
        .andExpect(status().isForbidden())
        .andExpect(unauthenticated());

    assertThat(userRepository.existsByUsername("new-user-4")).isFalse();
  }

  @Test
  @DisplayName("A form submitted from another site does not change who the victim is logged in as")
  void crossSiteRegistrationDoesNotReplaceTheSessionOfTheVictim() throws Exception {
    var victim =
        registerFromRegistrationPage("victim-user")
            .andExpect(authenticated().withUsername("victim-user"))
            .andReturn();
    var victimSession = (MockHttpSession) victim.getRequest().getSession(false);
    assertThat(victimSession).isNotNull();

    mockMvc
        .perform(
            registration("new-user-3")
                .session(victimSession)
                .header("Origin", "http://attacker.local"))
        .andExpect(status().isForbidden())
        .andExpect(authenticated().withUsername("victim-user"));

    assertThat(userRepository.existsByUsername("new-user-3")).isFalse();
  }

  /** Registers a user the way a browser does: read the token from the form and post it back. */
  private ResultActions registerFromRegistrationPage(String username) throws Exception {
    var registrationPage = openRegistrationPage();
    var session = (MockHttpSession) registrationPage.getRequest().getSession(false);
    assertThat(session).isNotNull();

    return mockMvc.perform(
        registration(username).session(session).param("_csrf", csrfToken(registrationPage)));
  }

  private MvcResult openRegistrationPage() throws Exception {
    return mockMvc.perform(get("/registration")).andExpect(status().isOk()).andReturn();
  }

  private String csrfToken(MvcResult registrationPage) throws Exception {
    var token =
        Jsoup.parse(registrationPage.getResponse().getContentAsString())
            .selectFirst("input[name=_csrf]");
    assertThat(token).as("CSRF token on the registration page").isNotNull();
    return token.val();
  }

  private MockHttpServletRequestBuilder registration(String username) {
    return post("/register.mvc")
        .param("username", username)
        .param("password", "password")
        .param("matchingPassword", "password")
        .param("agree", "agree");
  }
}
