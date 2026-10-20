/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.user;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public WebWolfUser loadUserByUsername(final String username) throws UsernameNotFoundException {
    WebWolfUser webGoatUser = userRepository.findByUsername(username);
    if (webGoatUser == null) {
      throw new UsernameNotFoundException("User not found");
    }
    webGoatUser.createUser();
    return webGoatUser;
  }

  public void addUser(final String username, final String password) {
    userRepository.save(new WebWolfUser(username, passwordEncoder.encode(password)));
  }
}
