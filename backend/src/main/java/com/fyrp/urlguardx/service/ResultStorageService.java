package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import com.fyrp.urlguardx.dto.ScanResponse;
import com.fyrp.urlguardx.entity.ScanResultEntity;
import com.fyrp.urlguardx.repository.ScanResultRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ResultStorageService {

    private static final Logger log = LoggerFactory.getLogger(ResultStorageService.class);

    private final ScanResultRepository repository;

    public ResultStorageService(ScanResultRepository repository) {
        this.repository = repository;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Persist a completed scan result
    // ─────────────────────────────────────────────────────────────────────
    public void save(String url, ScanResponse response) {
        try {
            ScanResultEntity entity = new ScanResultEntity();
            entity.setUrl(url);
            entity.setRiskScore(response.getRiskScore());
            entity.setStatus(response.getStatus());
            entity.setExplanation(response.getExplanation());

            ModuleResult lexical   = response.getModules().getLexical();
            ModuleResult domain    = response.getModules().getDomain();
            ModuleResult ssl       = response.getModules().getSsl();
            ModuleResult blacklist = response.getModules().getBlacklist();

            entity.setLexicalStatus(lexical.getStatus());
            entity.setLexicalDetails(lexical.getDetails());
            entity.setDomainStatus(domain.getStatus());
            entity.setDomainDetails(domain.getDetails());
            entity.setSslStatus(ssl.getStatus());
            entity.setSslDetails(ssl.getDetails());
            entity.setBlacklistStatus(blacklist.getStatus());
            entity.setBlacklistDetails(blacklist.getDetails());

            repository.save(entity);
            log.info("[STORAGE] Scan saved — URL: {} | Score: {} | Status: {}",
                     url, response.getRiskScore(), response.getStatus());

        } catch (Exception e) {
            log.error("[STORAGE] Failed to persist scan result: {}", e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Rebuild a ScanResponse from a cached entity (for repeat URLs)
    // ─────────────────────────────────────────────────────────────────────
    public ScanResponse loadCached(String url) {
        return repository.findTopByUrlOrderByScannedAtDesc(url)
                .map(this::toResponse)
                .orElse(null);
    }

    private ScanResponse toResponse(ScanResultEntity e) {
        ScanResponse r = new ScanResponse();
        r.setRiskScore(e.getRiskScore());
        r.setStatus(e.getStatus());
        r.setExplanation(e.getExplanation());

        ModuleResult lex  = new ModuleResult(e.getLexicalStatus(),   e.getLexicalDetails(),   0);
        ModuleResult dom  = new ModuleResult(e.getDomainStatus(),    e.getDomainDetails(),    0);
        ModuleResult ssl  = new ModuleResult(e.getSslStatus(),       e.getSslDetails(),       0);
        ModuleResult bl   = new ModuleResult(e.getBlacklistStatus(), e.getBlacklistDetails(), 0);

        r.setModules(new ScanResponse.ModulesWrapper(lex, dom, ssl, bl));
        return r;
    }
}
