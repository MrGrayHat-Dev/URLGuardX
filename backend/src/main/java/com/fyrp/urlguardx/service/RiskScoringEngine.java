package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.springframework.stereotype.Service;

@Service
public class RiskScoringEngine {

    // ── Level weights used in the normalised weighted average ─────────────────
    private static final double W_LEXICAL   = 0.25;
    private static final double W_BLACKLIST = 0.40;
    private static final double W_DOMAIN    = 0.20;
    private static final double W_SSL       = 0.15;

    // ── Corroboration bonus: each extra DANGER signal beyond the first adds 6 pts
    private static final int DANGER_BONUS_PER_SIGNAL = 6;

    // ── Score floors per signal-level combination ─────────────────────────────
    //    Two independent DANGER signals must *always* be High Risk (≥70)
    private static final int FLOOR_2_DANGER          = 72;
    //    Three independent modules all flag something — minimum Suspicious
    private static final int FLOOR_3_ANY_FLAG        = 55;
    //    One DANGER + one or more WARNINGs — minimum strong Suspicious
    private static final int FLOOR_1D_1W             = 58;

    public int calculate(
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {

        // ── Pre-compute level counts ──────────────────────────────────────────
        int dangerCount  = 0;
        int warningCount = 0;

        if (isDanger(lexical))   dangerCount++;
        if (isDanger(domain))    dangerCount++;
        if (isDanger(ssl))       dangerCount++;
        if (isDanger(blacklist)) dangerCount++;

        if (isWarning(lexical))   warningCount++;
        if (isWarning(domain))    warningCount++;
        if (isWarning(ssl))       warningCount++;
        if (isWarning(blacklist)) warningCount++;

        /*
         RULE 1 — Blacklist DANGER = immediate critical threat.
         Blacklist is the highest-confidence module; a hit here is definitive.
         */
        if (isDanger(blacklist)) {
            return 95;
        }

        /*
         RULE 2 — Two or more independent DANGER signals.
         Problem with the old rule: it averaged raw scores, so two modules each
         returning a moderate raw score (e.g. 60) averaged to 60 → Suspicious.
         Fix: enforce a FLOOR of 72 (High Risk) and then boost via the normalised
         weighted average of the flagged modules — whichever is higher wins.
         A corroboration bonus (+6 per extra DANGER beyond the 2nd) rewards
         cases where 3 or more modules all flag DANGER simultaneously.
         */
        if (dangerCount >= 2) {
            double flaggedScore  = 0.0;
            double flaggedWeight = 0.0;

            if (!isClean(lexical)) {
                flaggedScore  += lexical.getScore()   * W_LEXICAL;
                flaggedWeight += W_LEXICAL;
            }
            if (!isClean(blacklist)) {
                flaggedScore  += blacklist.getScore() * W_BLACKLIST;
                flaggedWeight += W_BLACKLIST;
            }
            if (!isClean(domain)) {
                flaggedScore  += domain.getScore()    * W_DOMAIN;
                flaggedWeight += W_DOMAIN;
            }
            if (!isClean(ssl)) {
                flaggedScore  += ssl.getScore()       * W_SSL;
                flaggedWeight += W_SSL;
            }

            int weightedAvg = (flaggedWeight > 0)
                    ? (int) Math.round(flaggedScore / flaggedWeight)
                    : FLOOR_2_DANGER;

            // Corroboration bonus for 3+ DANGER signals
            int bonus = (dangerCount - 2) * DANGER_BONUS_PER_SIGNAL;

            // Apply floor: two DANGERs must never fall below High Risk
            int score = Math.max(FLOOR_2_DANGER, weightedAvg) + bonus;

            // Extra floor bump if there are also WARNING signals alongside the DANGERs
            if (warningCount >= 1) {
                score = Math.max(score, FLOOR_2_DANGER + 4);
            }

            return Math.min(score, 100);
        }

        /*
         RULE 3 — Lexical DANGER isolated: only the ML model fired.
         Capped at 55 to avoid over-penalising ML false-positives when every
         other module is clean.
         */
        if (
                isDanger(lexical)
                && isClean(blacklist)
                && isClean(domain)
                && isClean(ssl)
        ) {
            return 55;
        }

        /*
         RULE 3b — Lexical DANGER + SSL and/or Domain also flagged (no blacklist).
         Old rule only checked SSL. Now we include domain corroboration too.
         We use the normalised weighted average of all flagged modules, then
         enforce FLOOR_2_DANGER because lexical+SSL or lexical+domain is
         effectively two independent DANGER signals.
         */
        if (
                isDanger(lexical)
                && isClean(blacklist)
                && (!isClean(ssl) || !isClean(domain))
        ) {
            double lexW = W_LEXICAL;
            double sslW = isClean(ssl)    ? 0 : W_SSL;
            double domW = isClean(domain) ? 0 : W_DOMAIN;
            double totalW = lexW + sslW + domW;

            double combinedScore = (
                    lexical.getScore() * lexW
                    + ssl.getScore()    * sslW
                    + domain.getScore() * domW
            ) / totalW;

            // Enforce floor: lexical + another real signal → High Risk territory
            return Math.max(FLOOR_2_DANGER, (int) Math.round(combinedScore));
        }

        /*
         RULE 4 — Exactly one DANGER (not blacklist) combined with WARNINGs.
         Old rule:
           1D + 3W → 75  (fine)
           1D + 1-2W → 55  (too low — same score as isolated ML danger)
         New rule applies FLOOR_1D_1W (58) and scales up with warning count
         so that 1D+2W > 1D+1W, and 1D+3W stays at 75.
         */
        if (dangerCount == 1) {
            if (warningCount >= 3) {
                return 75;
            } else if (warningCount == 2) {
                return Math.max(FLOOR_1D_1W + 4, 62); // 62
            } else if (warningCount == 1) {
                return FLOOR_1D_1W;                   // 58
            }
        }

        /*
         RULE 4b — Three or more modules all flagged (Warning or above), no Danger.
         Multiple modules independently raising a WARNING is meaningful corroboration.
         */
        if (warningCount >= 3) {
            return FLOOR_3_ANY_FLAG;
        }

        /*
         RULE 4c — Two WARNINGs: moderate risk, needs human review.
         */
        if (warningCount == 2) {
            double flaggedScore  = 0.0;
            double flaggedWeight = 0.0;

            if (!isClean(lexical)) {
                flaggedScore  += lexical.getScore()   * W_LEXICAL;
                flaggedWeight += W_LEXICAL;
            }
            if (!isClean(domain)) {
                flaggedScore  += domain.getScore()    * W_DOMAIN;
                flaggedWeight += W_DOMAIN;
            }
            if (!isClean(ssl)) {
                flaggedScore  += ssl.getScore()       * W_SSL;
                flaggedWeight += W_SSL;
            }

            int avg = (flaggedWeight > 0)
                    ? (int) Math.round(flaggedScore / flaggedWeight)
                    : 45;
            return Math.max(42, avg); // floor at low-Suspicious
        }

        /*
         RULE 5 — Reduce ML false positives.
         Only penalise very high lexical scores when every other module is Clean.
         */
        double lexicalScore = lexical.getScore();

        if (lexicalScore > 95
                && isClean(blacklist)
                && isClean(domain)
                && isClean(ssl)) {
            lexicalScore *= 0.50;
        }

        /*
         RULE 6 — Final fallback: full weighted average across all four modules.
         Reached only when no module returned Danger and at most one returned Warning.
         */
        double finalScore =
                (lexicalScore          * W_LEXICAL)
                + (blacklist.getScore() * W_BLACKLIST)
                + (domain.getScore()    * W_DOMAIN)
                + (ssl.getScore()       * W_SSL);

        return Math.min((int) Math.round(finalScore), 100);
    }

    // ── Status tier helper methods ────────────────────────────────────────────

    public String getFinalStatus(int score) {
        if (score >= 70) return "High Risk";
        if (score >= 40) return "Suspicious";
        return "Safe";
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private boolean isDanger(ModuleResult m) {
        return m != null && "Danger".equalsIgnoreCase(m.getStatus());
    }

    private boolean isWarning(ModuleResult m) {
        return m != null && "Warning".equalsIgnoreCase(m.getStatus());
    }

    private boolean isClean(ModuleResult m) {
        return m == null || "Clean".equalsIgnoreCase(m.getStatus())
                         || "Skipped".equalsIgnoreCase(m.getStatus());
    }
}