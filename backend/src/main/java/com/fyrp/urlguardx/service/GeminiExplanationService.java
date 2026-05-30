package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@Service
public class GeminiExplanationService {

    private static final Logger log = LoggerFactory.getLogger(GeminiExplanationService.class);

    @Value("${gemini.api.key:}")
    private String geminiApiKey;

    @Value("${gemini.api.url:https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent}")
    private String geminiApiUrl;

    private final WebClient webClient;

    public GeminiExplanationService(WebClient webClient) {
        this.webClient = webClient;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Public entry point
    //  Called by AgenticControllerService.buildResponse() after every scan.
    //  Contract: always returns a non-null, non-blank String.
    // ─────────────────────────────────────────────────────────────────────────
    public String generateExplanation(
            String url,
            int riskScore,
            String status,
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {
        // Verdict prefix — always the very first token so the UI / caller
        // can strip or display it trivially.
        String verdict = buildVerdictPrefix(status, riskScore);

        // ── Try Gemini first ──────────────────────────────────────────────
        if (geminiApiKey != null && !geminiApiKey.isBlank() && !geminiApiKey.startsWith("YOUR_")) {
            try {
                String prompt = buildPrompt(url, riskScore, status, lexical, domain, ssl, blacklist);
                String apiUrl = geminiApiUrl + "?key=" + geminiApiKey;

                Map<String, Object> requestBody = Map.of(
                        "contents", List.of(
                                Map.of("parts", List.of(Map.of("text", prompt)))
                        ),
                        "generationConfig", Map.of(
                                "temperature",     0.2,
                                "maxOutputTokens", 350,
                                "topP",            0.8
                        )
                );

                @SuppressWarnings("unchecked")
                Map<String, Object> response = webClient.post()
                        .uri(uriBuilder -> uriBuilder
                                .path(geminiApiUrl.replace(
                                        "https://generativelanguage.googleapis.com", ""))
                                .queryParam("key", geminiApiKey)
                                .build())
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .bodyValue(requestBody)
                        .retrieve()
                        .bodyToMono(Map.class)
                        .timeout(Duration.ofSeconds(15))
                        .block();

                String geminiText = extractGeminiText(response);
                if (geminiText != null && !geminiText.isBlank()) {
                    // Prepend the verdict so it always appears first, even if
                    // Gemini omits or rephrases the overall verdict label.
                    return verdict + " " + geminiText.trim();
                }
            } catch (Exception e) {
                log.error("[GEMINI] API call failed: {}", e.getMessage());
            }
        } else {
            log.warn("[GEMINI] No API key configured — using rule-based fallback.");
        }

        // ── Fallback ──────────────────────────────────────────────────────
        return verdict + " " + buildFallbackExplanation(riskScore, lexical, domain, ssl, blacklist);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Verdict prefix  (mirrors RiskScoringEngine.getFinalStatus thresholds)
    //  Format:  "⚠ SUSPICIOUS (score 52/100):"
    // ─────────────────────────────────────────────────────────────────────────
    private String buildVerdictPrefix(String status, int riskScore) {
        return switch (status) {
            case "High Risk"   -> "🔴 HIGH RISK (score " + riskScore + "/100):";
            case "Suspicious"  -> "🟡 SUSPICIOUS (score " + riskScore + "/100):";
            default            -> "🟢 SAFE (score " + riskScore + "/100):";
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Prompt — mirrors ALL 6 scoring rules from RiskScoringEngine so Gemini
    //  can generate an explanation that is consistent with the actual score.
    // ─────────────────────────────────────────────────────────────────────────
    private String buildPrompt(
            String url,
            int riskScore,
            String status,
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {
        return """
You are a cybersecurity threat analyst for URLGuardX.

The scoring pipeline that produced this result follows these rules (highest priority first):

  RULE 1  — Blacklist DANGER → score = 95 (confirmed malicious, immediate critical threat)
  RULE 2  — Two or more independent DANGER signals → score ≥ 72 (High Risk), boosted by
            a +6-point corroboration bonus for every extra DANGER beyond the second.
  RULE 3  — Lexical DANGER alone (all others Clean) → score = 55 (Suspicious, ML-only flag,
            no corroboration; treat with moderate caution)
  RULE 3b — Lexical DANGER + SSL or Domain also flagged (no blacklist) → score ≥ 72 (High Risk)
  RULE 4  — Exactly one DANGER (non-blacklist) + WARNINGs → score 58–75
            (scales: 1W=58, 2W=62, 3W=75)
  RULE 4b — Three or more WARNINGs, no DANGER → score = 55 (Suspicious, corroborated concern)
  RULE 4c — Exactly two WARNINGs → weighted average, floor 42 (low Suspicious)
  RULE 5  — Lexical score >95 but everything else Clean → raw score halved (ML false-positive dampening)
  RULE 6  — Fallback weighted average (Lexical 25%%, Blacklist 40%%, Domain 20%%, SSL 15%%)

TASK: Write a 2–3 sentence explanation for WHY this URL received the score and status shown below.

STRICT RULES:
- Do NOT restate the verdict or score (it will be prepended automatically).
- Start directly with the reason, e.g. "The threat intelligence feed confirmed…"
- Reference ONLY the signals that actually fired (non-Clean, non-Skipped modules).
- If every module is Clean/Skipped, say everything checked out and the URL appears safe.
- Never say "all checks passed" unless every module is CLEAN or SKIPPED.
- Prioritise signals in this order: Blacklist > Domain > SSL > Lexical.
- Explain in simple, layman's terms. Do not include highly technical jargon like specific TLS protocol versions (e.g., TLSv1.3) or certificate issuer names.
- Be specific about the risk (e.g. "domain registered 3 days ago").
- No markdown, no bullet points, no headers. Plain sentences only.

URL: %s
Risk Score: %d/100
Final Status: %s

Module Results (status | raw score | details):
  Threat Intel / Blacklist : [%s | %.0f] %s
  Domain / WHOIS           : [%s | %.0f] %s
  SSL / TLS                : [%s | %.0f] %s
  Lexical / ML             : [%s | %.0f] %s

Now write the explanation (2–3 sentences, plain text, no headers):
""".formatted(
                url, riskScore, status,
                blacklist.getStatus(), blacklist.getScore(), nullSafe(blacklist.getDetails()),
                domain.getStatus(),   domain.getScore(),    nullSafe(domain.getDetails()),
                ssl.getStatus(),      ssl.getScore(),       nullSafe(ssl.getDetails()),
                lexical.getStatus(),  lexical.getScore(),   nullSafe(lexical.getDetails())
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Response extraction
    // ─────────────────────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private String extractGeminiText(Map<String, Object> response) {
        try {
            List<Map<String, Object>> candidates =
                    (List<Map<String, Object>>) response.get("candidates");

            if (candidates == null || candidates.isEmpty()) return null;

            Map<String, Object> content =
                    (Map<String, Object>) candidates.get(0).get("content");

            List<Map<String, Object>> parts =
                    (List<Map<String, Object>>) content.get("parts");

            if (parts == null || parts.isEmpty()) return null;

            return parts.get(0).get("text").toString();

        } catch (Exception e) {
            log.warn("[GEMINI] Failed to parse response: {}", e.getMessage());
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Rule-based fallback — mirrors every branch of RiskScoringEngine
    //  so the explanation matches the actual scoring logic when Gemini is down.
    //
    //  Priority order follows RiskScoringEngine rules top-to-bottom.
    // ─────────────────────────────────────────────────────────────────────────
    private String buildFallbackExplanation(
            int riskScore,
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {
        int dangerCount  = countDanger(lexical, domain, ssl, blacklist);
        int warningCount = countWarning(lexical, domain, ssl, blacklist);

        // ── RULE 1 — Blacklist DANGER ─────────────────────────────────────
        if (isDanger(blacklist)) {
            return "The threat intelligence feed (Google Safe Browsing / URLHaus) confirmed this URL "
                 + "as a known malicious destination: " + nullSafe(blacklist.getDetails()) + ". "
                 + "Do not visit this link under any circumstances.";
        }

        // ── RULE 2 — Two or more DANGER signals ──────────────────────────
        if (dangerCount >= 2) {
            StringBuilder sb = new StringBuilder();
            sb.append("Multiple independent modules flagged this URL as dangerous. ");
            if (isDanger(domain))   sb.append("Domain analysis: ").append(nullSafe(domain.getDetails())).append(". ");
            if (isDanger(ssl))      sb.append("SSL/TLS: ").append(nullSafe(ssl.getDetails())).append(". ");
            if (isDanger(lexical))  sb.append("The machine learning engine also detected strong phishing patterns. ");
            sb.append("Combined corroboration pushed the score to ").append(riskScore).append("/100.");
            return sb.toString().trim();
        }

        // ── RULE 3 — Lexical DANGER isolated ─────────────────────────────
        if (isDanger(lexical) && isClean(blacklist) && isClean(domain) && isClean(ssl)) {
            return "The machine learning model detected suspicious lexical patterns in the URL ("
                 + nullSafe(lexical.getDetails()) + "), but no blacklist hits, "
                 + "domain abuse indicators, or TLS issues were found. "
                 + "This may be a false positive — treat with moderate caution.";
        }

        // ── RULE 3b — Lexical DANGER + SSL or Domain flagged ─────────────
        if (isDanger(lexical) && isClean(blacklist) && (!isClean(ssl) || !isClean(domain))) {
            StringBuilder sb = new StringBuilder();
            sb.append("The machine learning model detected phishing-like URL patterns (")
              .append(nullSafe(lexical.getDetails())).append("), ");
            if (!isClean(domain)) sb.append("and domain analysis raised concerns: ").append(nullSafe(domain.getDetails())).append(". ");
            if (!isClean(ssl))    sb.append("SSL/TLS also flagged an issue: ").append(nullSafe(ssl.getDetails())).append(". ");
            sb.append("Two independent signals corroborate a high-risk verdict.");
            return sb.toString().trim();
        }

        // ── RULE 4 — One DANGER + WARNINGs ───────────────────────────────
        if (dangerCount == 1 && warningCount >= 1) {
            String dangerDetail = getDangerDetail(lexical, domain, ssl);
            String warningSummary = buildWarningSummary(lexical, domain, ssl);
            return "One module raised a critical alert: " + dangerDetail + ". "
                 + "Additional warning signals were detected: " + warningSummary + ". "
                 + "The combination of a definitive flag and corroborating warnings elevates the risk score to "
                 + riskScore + "/100.";
        }

        // ── RULE 4b — Three or more WARNINGs, no DANGER ──────────────────
        if (warningCount >= 3) {
            return "Three or more modules independently raised warnings: "
                 + buildWarningSummary(lexical, domain, ssl, blacklist) + ". "
                 + "While no single signal is definitive, the corroborated concern across "
                 + warningCount + " modules is sufficient to classify this URL as Suspicious.";
        }

        // ── RULE 4c — Exactly two WARNINGs ───────────────────────────────
        if (warningCount == 2) {
            return "Two modules raised warnings: " + buildWarningSummary(lexical, domain, ssl, blacklist) + ". "
                 + "No confirmed blacklist hit was found, but the combined signals warrant careful review "
                 + "before interacting with this URL.";
        }

        // ── Golden-domain path (domain.details contains the keyword) ─────
        if (domain.getDetails() != null &&
                domain.getDetails().toLowerCase().contains("golden domain")) {
            if (warningCount > 0) {
                return "This URL belongs to a well-known, trusted domain, so WHOIS analysis was skipped. "
                     + "However, a minor issue was detected: " + buildWarningSummary(lexical, domain, ssl, blacklist) + ".";
            }
            return "This URL belongs to a well-known, trusted domain. "
                 + "WHOIS analysis was skipped given the domain's established reputation, "
                 + "and all other checks (TLS, blacklist, and ML) returned clean results.";
        }

        // ── RULE 5/6 — Low/no signals, safe ──────────────────────────────
        return "All analysis modules returned clean or benign results. "
             + "No blacklist hits, domain abuse indicators, TLS issues, or strong phishing "
             + "patterns were detected. This URL appears safe to visit.";
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helper — collect the detail string from whichever module is in DANGER
    //  (excludes blacklist, which is handled at RULE 1)
    // ─────────────────────────────────────────────────────────────────────────
    private String getDangerDetail(ModuleResult lexical, ModuleResult domain, ModuleResult ssl) {
        if (isDanger(domain))  return "Domain analysis — " + nullSafe(domain.getDetails());
        if (isDanger(ssl))     return "SSL/TLS — " + nullSafe(ssl.getDetails());
        if (isDanger(lexical)) return "ML lexical model — " + nullSafe(lexical.getDetails());
        return "unknown signal";
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helper — build a comma-separated summary of all WARNING module details
    // ─────────────────────────────────────────────────────────────────────────
    private String buildWarningSummary(ModuleResult... modules) {
        StringBuilder sb = new StringBuilder();
        for (ModuleResult m : modules) {
            if (isWarning(m)) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(nullSafe(m.getDetails()));
            }
        }
        return sb.length() > 0 ? sb.toString() : "minor anomalies detected";
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Count helpers (mirrors RiskScoringEngine private helpers)
    // ─────────────────────────────────────────────────────────────────────────
    private int countDanger(ModuleResult... modules) {
        int c = 0;
        for (ModuleResult m : modules) if (isDanger(m)) c++;
        return c;
    }

    private int countWarning(ModuleResult... modules) {
        int c = 0;
        for (ModuleResult m : modules) if (isWarning(m)) c++;
        return c;
    }

    private boolean isDanger(ModuleResult m) {
        return m != null && "Danger".equalsIgnoreCase(m.getStatus());
    }

    private boolean isWarning(ModuleResult m) {
        return m != null && "Warning".equalsIgnoreCase(m.getStatus());
    }

    private boolean isClean(ModuleResult m) {
        return m == null
            || "Clean".equalsIgnoreCase(m.getStatus())
            || "Skipped".equalsIgnoreCase(m.getStatus());
    }

    private String nullSafe(String s) {
        if (s == null) return "no details available";
        // Strip highly technical TLS jargon for layman explanations
        return s.replaceAll("(?i)\\.?\\s*Issuer:.*", "")
                .replaceAll("(?i)\\.?\\s*Protocol:.*", "")
                .replaceAll("(?i)\\s*Issued by:.*?\\.", "")
                .replaceAll("(?i)\\s*\\(issued by.*?\\)", "")
                .replaceAll("(?i)\\s*Cert issued by:.*?\\.", "")
                .replaceAll("\\s+", " ")
                .trim();
    }
}
