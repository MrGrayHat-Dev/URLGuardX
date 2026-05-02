package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import com.fyrp.urlguardx.dto.ScanResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AgenticControllerService {

    private static final Logger log =
            LoggerFactory.getLogger(AgenticControllerService.class);

    private final LexicalAnalysisService lexicalService;
    private final BlacklistCheckerService blacklistService;
    private final SslValidatorService sslService;
    private final DomainAnalyzerService domainService;
    private final RiskScoringEngine riskEngine;
    private final GeminiExplanationService geminiService;
    private final ResultStorageService storageService;

    public AgenticControllerService(
            LexicalAnalysisService lexicalService,
            BlacklistCheckerService blacklistService,
            SslValidatorService sslService,
            DomainAnalyzerService domainService,
            RiskScoringEngine riskEngine,
            GeminiExplanationService geminiService,
            ResultStorageService storageService
    ) {
        this.lexicalService = lexicalService;
        this.blacklistService = blacklistService;
        this.sslService = sslService;
        this.domainService = domainService;
        this.riskEngine = riskEngine;
        this.geminiService = geminiService;
        this.storageService = storageService;
    }

    public ScanResponse orchestrate(String rawUrl) {

        String url = normalizeUrl(rawUrl);

        log.info("[AGENT] Starting scan for {}", url);

        ModuleResult lexical;
        ModuleResult blacklist;
        ModuleResult domain = ModuleResult.skipped("Not executed");
        ModuleResult ssl = ModuleResult.skipped("Not executed");

        // ✅ LEXICAL (safe)
        try {
            lexical = lexicalService.analyze(url);
        } catch (Exception e) {
            log.error("Lexical failed", e);
            lexical = ModuleResult.warning("Lexical failed", 10.0);
        }

        // ✅ BLACKLIST (safe)
        try {
            blacklist = blacklistService.check(url);
        } catch (Exception e) {
            log.error("Blacklist failed", e);
            blacklist = ModuleResult.warning("Blacklist unavailable", 20.0);
        }

        // ✅ FAIL FAST
        if ("Danger".equalsIgnoreCase(blacklist.getStatus())) {
            return buildResponse(url, lexical, domain, ssl, blacklist);
        }

        boolean goldenDomain = false;

        try {
            goldenDomain = domainService.isGoldenDomain(url);
        } catch (Exception e) {
            log.error("Golden domain check failed", e);
        }

        // ✅ DOMAIN + SSL SAFE BLOCK
        try {
            if (goldenDomain) {
                domain = ModuleResult.clean("Golden domain detected", 2.0);
                ssl = sslService.validate(url);
            } else if (url.startsWith("http://")) {
                ssl = ModuleResult.danger("No HTTPS", 70.0);
                domain = domainService.analyze(url);
            } else {
                domain = domainService.analyze(url);
                ssl = sslService.validate(url);
            }
        } catch (Exception e) {
            log.error("Domain/SSL failed", e);
            domain = ModuleResult.warning("Domain check failed", 25.0);
            ssl = ModuleResult.warning("SSL check failed", 25.0);
        }

        return buildResponse(url, lexical, domain, ssl, blacklist);
    }

    private ScanResponse buildResponse(
            String url,
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {

        int score = riskEngine.calculate(
                lexical,
                domain,
                ssl,
                blacklist
        );

        String status = riskEngine.getFinalStatus(score);

        String explanation;

        try {
            explanation = geminiService.generateExplanation(
                    url, score, status, lexical, domain, ssl, blacklist
            );
        } catch (Exception e) {
            log.error("Gemini failed", e);
            explanation = "AI explanation unavailable (fallback)";
        }
        ScanResponse response = new ScanResponse();
        response.setRiskScore(score);
        response.setStatus(status);
        response.setExplanation(explanation);
        response.setModules(
                new ScanResponse.ModulesWrapper(
                        lexical,
                        domain,
                        ssl,
                        blacklist
                )
        );

        storageService.save(url, response);

        return response;
    }

    private String normalizeUrl(String url) {
        url = url.trim();

        if (!url.startsWith("http://")
                && !url.startsWith("https://")) {
            return "https://" + url;
        }

        return url;
    }
}