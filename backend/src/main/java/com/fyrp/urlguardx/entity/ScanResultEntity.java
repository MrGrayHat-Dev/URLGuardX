package com.fyrp.urlguardx.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Persistent record of every scan — stored in the H2 Result Storage DB.
 * Switch to PostgreSQL by changing the datasource properties.
 */
@Entity
@Table(name = "scan_results")
public class ScanResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 2048, nullable = false)
    private String url;

    private int    riskScore;
    private String status;

    @Column(length = 4096)
    private String explanation;

    // Module results stored as compact strings
    private String lexicalStatus;
    @Column(length = 1024)
    private String lexicalDetails;

    private String domainStatus;
    @Column(length = 1024)
    private String domainDetails;

    private String sslStatus;
    @Column(length = 1024)
    private String sslDetails;

    private String blacklistStatus;
    @Column(length = 1024)
    private String blacklistDetails;

    private LocalDateTime scannedAt;

    @PrePersist
    protected void onCreate() {
        scannedAt = LocalDateTime.now();
    }

    // ---- Getters & Setters ----
    public Long          getId()               { return id; }
    public String        getUrl()              { return url; }
    public void          setUrl(String u)      { url = u; }
    public int           getRiskScore()        { return riskScore; }
    public void          setRiskScore(int s)   { riskScore = s; }
    public String        getStatus()           { return status; }
    public void          setStatus(String s)   { status = s; }
    public String        getExplanation()      { return explanation; }
    public void          setExplanation(String e) { explanation = e; }
    public String        getLexicalStatus()    { return lexicalStatus; }
    public void          setLexicalStatus(String s)   { lexicalStatus = s; }
    public String        getLexicalDetails()   { return lexicalDetails; }
    public void          setLexicalDetails(String d)  { lexicalDetails = d; }
    public String        getDomainStatus()     { return domainStatus; }
    public void          setDomainStatus(String s)    { domainStatus = s; }
    public String        getDomainDetails()    { return domainDetails; }
    public void          setDomainDetails(String d)   { domainDetails = d; }
    public String        getSslStatus()        { return sslStatus; }
    public void          setSslStatus(String s)       { sslStatus = s; }
    public String        getSslDetails()       { return sslDetails; }
    public void          setSslDetails(String d)      { sslDetails = d; }
    public String        getBlacklistStatus()  { return blacklistStatus; }
    public void          setBlacklistStatus(String s) { blacklistStatus = s; }
    public String        getBlacklistDetails() { return blacklistDetails; }
    public void          setBlacklistDetails(String d){ blacklistDetails = d; }
    public LocalDateTime getScannedAt()        { return scannedAt; }
}
