/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer verifyUserId = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();

  static {
    userSecQuestions.put("secQuestion0", "Dr. Watson");
    userSecQuestions.put("secQuestion1", "Baker Street");
  }

  private static final Map<Integer, Map> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(verifyUserId, userSecQuestions);
  }

  // end 'data store set up'

  // this is to aid feedback in the attack process and is not intended to be part of the
  // 'vulnerable' code
  private static boolean constantTimeEquals(String submittedAnswer, String expectedAnswer) {
    if (submittedAnswer == null || expectedAnswer == null) {
      return false;
    }

    return MessageDigest.isEqual(
        submittedAnswer.getBytes(StandardCharsets.UTF_8),
        expectedAnswer.getBytes(StandardCharsets.UTF_8));
  }

  public boolean didUserLikelylCheat(HashMap<String, String> submittedAnswers) {
    boolean likely = false;

    if (submittedAnswers.size() == secQuestionStore.get(verifyUserId).size()) {
      likely = true;
    }

    String expectedSecQuestion0 = (String) secQuestionStore.get(verifyUserId).get("secQuestion0");
    String expectedSecQuestion1 = (String) secQuestionStore.get(verifyUserId).get("secQuestion1");

    boolean secQuestion0Matches =
        submittedAnswers.containsKey("secQuestion0")
            && constantTimeEquals(submittedAnswers.get("secQuestion0"), expectedSecQuestion0);
    boolean secQuestion1Matches =
        submittedAnswers.containsKey("secQuestion1")
            && constantTimeEquals(submittedAnswers.get("secQuestion1"), expectedSecQuestion1);

    likely = secQuestion0Matches && secQuestion1Matches;

    return likely;
  }

  // end of cheating check ... the method below is the one of real interest. Can you find the flaw?

  public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    // short circuit if no questions are submitted
    boolean sizeMatches = submittedQuestions.entrySet().size() == secQuestionStore.get(verifyUserId).size();
    String expectedSecQuestion0 = (String) secQuestionStore.get(verifyUserId).get("secQuestion0");
    String expectedSecQuestion1 = (String) secQuestionStore.get(verifyUserId).get("secQuestion1");

    boolean secQuestion0Matches =
        submittedQuestions.containsKey("secQuestion0")
            && constantTimeEquals(submittedQuestions.get("secQuestion0"), expectedSecQuestion0);
    boolean secQuestion1Matches =
        submittedQuestions.containsKey("secQuestion1")
            && constantTimeEquals(submittedQuestions.get("secQuestion1"), expectedSecQuestion1);

    // else
    return sizeMatches && secQuestion0Matches && secQuestion1Matches;
  }
}
