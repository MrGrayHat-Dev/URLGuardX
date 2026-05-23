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
         2+ Danger signals from any module.
         Score is calculated based on the signals and weightage of the flagged modules,
         normalized so that clean modules don't drag the score down to Safe.
         */
        if (dangerCount >= 2) {
            double flaggedScore = 0.0;
            double flaggedWeight = 0.0;

            if (!"Clean".equalsIgnoreCase(lexical.getStatus())) {
                flaggedScore += lexical.getScore() * 0.25;
                flaggedWeight += 0.25;
            }
            if (!"Clean".equalsIgnoreCase(blacklist.getStatus())) {
                flaggedScore += blacklist.getScore() * 0.40;
                flaggedWeight += 0.40;
            }
            if (!"Clean".equalsIgnoreCase(domain.getStatus())) {
                flaggedScore += domain.getScore() * 0.20;
                flaggedWeight += 0.20;
            }
            if (!"Clean".equalsIgnoreCase(ssl.getStatus())) {
                flaggedScore += ssl.getScore() * 0.15;
                flaggedWeight += 0.15;
            }

            if (flaggedWeight > 0) {
                return (int) Math.round(flaggedScore / flaggedWeight);
            }
        }

        /*
         RULE 3:
         Lexical Danger + no blacklist hit + no domain flag.
         Capped at 55 (<60) because ML can be inaccurate.
         */
        if (
                "Danger".equalsIgnoreCase(lexical.getStatus())
                        && "Clean".equalsIgnoreCase(blacklist.getStatus())
                        && "Clean".equalsIgnoreCase(domain.getStatus())
                        && "Clean".equalsIgnoreCase(ssl.getStatus())
        ) {
            return 55;
        }

        /*
         RULE 3b:
         Lexical Danger + SSL warning/danger.
         Score is calculated based on their specific signals and weightage.
         */
        if (
                "Danger".equalsIgnoreCase(lexical.getStatus())
                        && "Clean".equalsIgnoreCase(blacklist.getStatus())
                        && !"Clean".equalsIgnoreCase(ssl.getStatus())
        ) {
            double lexW = 0.25;
            double sslW = 0.15;
            double combinedScore = (lexical.getScore() * lexW + ssl.getScore() * sslW) / (lexW + sslW);
            return (int) Math.round(combinedScore);
        }

        /*
         RULE 4:
         1 Danger (not blacklist) + 3 Warnings = score > 70
         */
        if (dangerCount == 1 && warningCount >= 3) {
            return 75;
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