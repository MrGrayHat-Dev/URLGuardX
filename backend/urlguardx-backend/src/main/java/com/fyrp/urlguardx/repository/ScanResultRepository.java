package com.fyrp.urlguardx.repository;

import com.fyrp.urlguardx.entity.ScanResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResultEntity, Long> {

    /** Look up the most recent cached result for a URL (avoids re-scanning). */
    Optional<ScanResultEntity> findTopByUrlOrderByScannedAtDesc(String url);

    /** Retrieve the 20 most recent scan records for an audit history view. */
    List<ScanResultEntity> findTop20ByOrderByScannedAtDesc();
}
