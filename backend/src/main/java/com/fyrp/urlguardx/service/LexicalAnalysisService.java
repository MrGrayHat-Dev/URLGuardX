package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

@Service
public class LexicalAnalysisService {

    private static final Logger log =
            LoggerFactory.getLogger(LexicalAnalysisService.class);

    private final WebClient webClient;

    @org.springframework.beans.factory.annotation.Value("${ML_SERVICE_URL}")
    private String mlServiceUrl;

    public LexicalAnalysisService(WebClient.Builder builder) {
        this.webClient = builder.build();
    }

    // =========================================================
    // SHORTENERS
    // =========================================================

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly","tinyurl.com","t.co","goo.gl",
            "ow.ly","is.gd","buff.ly","adf.ly",
            "bl.ink","rebrand.ly","short.io",
            "tiny.cc","shorte.st"
    );

    // =========================================================
    // TRUSTED DOMAINS
    // =========================================================

    private static final Set<String> TRUSTED = Set.of(
            "google.com",
            "microsoft.com",
            "amazon.com",
            "github.com",
            "openai.com",
            "chatgpt.com",
            "facebook.com",
            "instagram.com"
    );

    // =========================================================
    // MAIN ANALYSIS
    // =========================================================

    @org.springframework.cache.annotation.Cacheable(
            value = "mlCache",
            key = "#url"
    )
    public ModuleResult analyze(String url) {

        try {

            // =================================================
            // NORMALIZATION
            // =================================================

            url = normalize(url);

            // =================================================
            // TRUSTED DOMAIN OVERRIDE
            // =================================================

            if (isTrusted(url) && !looksSuspicious(url)) {

                return ModuleResult.clean(
                        "Trusted domain with no suspicious lexical patterns",
                        5
                );
            }

            // =================================================
            // HEURISTIC BOOSTING
            // =================================================

            double heuristicRisk = heuristicRisk(url);

            // =================================================
            // SHORTENER PENALTY
            // =================================================

            if (isUrlShortener(url)) {

                heuristicRisk += 20;

                log.warn("[LEXICAL] URL shortener detected");
            }

            log.info(
                    "[LEXICAL-ML] Sending URL to ML service: {}",
                    url
            );

            // =================================================
            // ML INFERENCE
            // =================================================

            Map<String, Object> response = webClient.post()
                    .uri(mlServiceUrl + "/predict")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("url", url))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(60))
                    .block();

            if (response == null) {

                log.warn("[LEXICAL-ML] Null response");

                return fallback(url);
            }

            int prediction =
                    ((Number) response.get("prediction")).intValue();

            double confidence =
                    ((Number) response.get("confidence")).doubleValue();

            // =================================================
            // CALIBRATED SCORE
            // =================================================

            double mlScore = confidence * 100;

            double finalScore =
                    (mlScore * 0.80) +
                            (heuristicRisk * 0.20);

            log.info(
                    "[LEXICAL] pred={} conf={} heuristic={} final={}",
                    prediction,
                    mlScore,
                    heuristicRisk,
                    finalScore
            );

            // =================================================
            // DANGER
            // =================================================

            if (
                    prediction == 1 &&
                            finalScore >= 85
            ) {

                return ModuleResult.danger(
                        "Strong phishing indicators detected",
                        finalScore
                );
            }

            // =================================================
            // WARNING
            // =================================================

            if (
                    prediction == 1 ||
                            finalScore >= 60
            ) {

                return ModuleResult.warning(
                        "Suspicious lexical patterns detected",
                        finalScore
                );
            }

            // =================================================
            // CLEAN
            // =================================================

            return ModuleResult.clean(
                    "No significant phishing patterns detected",
                    Math.max(5, 100 - finalScore)
            );

        } catch (Exception e) {

            log.error(
                    "[LEXICAL-ML] ML service failed: {}",
                    e.getMessage()
            );

            return fallback(url);
        }
    }

    // =========================================================
    // NORMALIZATION
    // =========================================================

    private String normalize(String url) {

        url = url.trim().toLowerCase();

        if (!url.startsWith("http")) {
            url = "https://" + url;
        }

        return url;
    }

    // =========================================================
    // TRUST CHECK
    // =========================================================

    private boolean isTrusted(String url) {

        try {

            String host = new URL(url)
                    .getHost()
                    .toLowerCase();

            return TRUSTED.stream().anyMatch(
                    t -> host.equals(t)
                            || host.endsWith("." + t)
            );

        } catch (Exception e) {

            return false;
        }
    }

    // =========================================================
    // URL SHORTENER
    // =========================================================

    public boolean isUrlShortener(String url) {

        try {

            String host = new URL(url)
                    .getHost()
                    .toLowerCase();

            return SHORTENERS.stream().anyMatch(
                    s -> host.equals(s)
                            || host.endsWith("." + s)
            );

        } catch (Exception e) {

            return false;
        }
    }

    // =========================================================
    // SUSPICIOUS TOKENS
    // =========================================================

    private boolean looksSuspicious(String url) {

        String u = url.toLowerCase();

        return u.contains("@")
                || u.contains("login")
                || u.contains("verify")
                || u.contains("secure")
                || u.contains("update")
                || u.contains("signin")
                || u.contains("bank")
                || u.contains("wallet")
                || u.contains("confirm");
    }

    // =========================================================
    // HEURISTIC ENGINE
    // =========================================================

    private double heuristicRisk(String url) {

        double risk = 0;

        String u = url.toLowerCase();

        if (u.contains("@")) risk += 20;

        if (u.matches(".*\\d{1,3}(\\.\\d{1,3}){3}.*"))
            risk += 25;

        if (u.contains("login")) risk += 10;

        if (u.contains("verify")) risk += 10;

        if (u.contains("secure")) risk += 8;

        if (u.contains("update")) risk += 8;

        if (u.contains("bank")) risk += 12;

        if (u.contains("wallet")) risk += 12;

        if (u.length() > 120) risk += 10;

        long dashCount =
                u.chars().filter(ch -> ch == '-').count();

        if (dashCount >= 3)
            risk += 10;

        return Math.min(risk, 100);
    }

    // =========================================================
    // FALLBACK
    // =========================================================

    private ModuleResult fallback(String url) {

        log.warn("[LEXICAL] Using heuristic fallback");

        double risk = heuristicRisk(url);

        if (risk >= 70) {

            return ModuleResult.danger(
                    "Heuristic phishing indicators detected",
                    risk
            );
        }

        if (risk >= 40) {

            return ModuleResult.warning(
                    "Suspicious lexical structure detected",
                    risk
            );
        }

        return ModuleResult.clean(
                "ML unavailable, no major lexical threats detected",
                10
        );
    }
}