package com.fyrp.urlguardx.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager("threatCache", "mlCache");

        manager.setCaffeine(
                Caffeine.newBuilder()
                        .expireAfterWrite(15, TimeUnit.SECONDS)  // 🔥 TTL reduced to 15 seconds for testing
                        .maximumSize(1000)
        );

        return manager;
    }
}