package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.springframework.stereotype.Service;

@Service
public class RiskScoringEngine {

    public int calculate(
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {

        /*
         RULE 1:
         Blacklist danger = immediate high risk
         */
        if ("Danger".equalsIgnoreCase(
                blacklist.getStatus())) {
            return 95;
        }

        int dangerCount = 0;
        int warningCount = 0;

        if ("Danger".equalsIgnoreCase(lexical.getStatus())) dangerCount++;
        if ("Danger".equalsIgnoreCase(domain.getStatus())) dangerCount++;
        if ("Danger".equalsIgnoreCase(ssl.getStatus())) dangerCount++;

        if ("Warning".equalsIgnoreCase(lexical.getStatus())) warningCount++;
        if ("Warning".equalsIgnoreCase(domain.getStatus())) warningCount++;
        if ("Warning".equalsIgnoreCase(ssl.getStatus())) warningCount++;

        /*
         RULE 2:
         2+ Danger signals from any module = high risk
         */
        if (dangerCount >= 2) {
            return 85;
        }

        /*
         RULE 3:
         Lexical Danger + no blacklist hit + no domain flag.
         Raised from 35 → 65 so novel phishing is Suspicious (not Safe).
         Only suppress if domain is explicitly Clean AND ssl is also Clean
         (both corroborating evidence of legitimacy).
         */
        if (
                "Danger".equalsIgnoreCase(lexical.getStatus())
                        && "Clean".equalsIgnoreCase(blacklist.getStatus())
                        && "Clean".equalsIgnoreCase(domain.getStatus())
                        && "Clean".equalsIgnoreCase(ssl.getStatus())
        ) {
            return 65;
        }

        /*
         RULE 3b:
         Lexical Danger + SSL warning/danger + no blacklist = strong corroboration.
         Novel phishing with bad cert evidence should score High Risk.
         */
        if (
                "Danger".equalsIgnoreCase(lexical.getStatus())
                        && "Clean".equalsIgnoreCase(blacklist.getStatus())
                        && !"Clean".equalsIgnoreCase(ssl.getStatus())
        ) {
            return 78;
        }

        /*
         RULE 4:
         1 Danger + 1+ Warning from remaining modules = elevated risk
         */
        if (dangerCount == 1 && warningCount >= 1) {
            return 72;
        }

        /*
         RULE 5:
         Reduce ML false positives — only penalise very high lexical scores
         when both blacklist AND domain AND ssl are all Clean.
         */
        double lexicalScore = lexical.getScore();

        if (lexicalScore > 95
                && "Clean".equalsIgnoreCase(blacklist.getStatus())
                && "Clean".equalsIgnoreCase(domain.getStatus())
                && "Clean".equalsIgnoreCase(ssl.getStatus())) {
            lexicalScore *= 0.50;
        }

        /*
         Final weighted score
         */
        double finalScore =
                (lexicalScore          * 0.25) +
                        (blacklist.getScore() * 0.40) +
                        (domain.getScore()    * 0.20) +
                        (ssl.getScore()       * 0.15);

        return Math.min(
                (int) Math.round(finalScore),
                100
        );
    }

    public String getFinalStatus(int score) {

        if (score >= 70) {
            return "High Risk";
        }

        if (score >= 40) {
            return "Suspicious";
        }

        return "Safe";
    }
}