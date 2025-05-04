package com.secureloginimplementation.demo;

 import io.github.bucket4j.*;
 import io.github.bucket4j.distributed.proxy.ProxyManager;
 import io.github.bucket4j.grid.jcache.Bucket4jJCache;
 import io.github.bucket4j.grid.jcache.JCacheProxyManager;
 import org.springframework.beans.factory.annotation.Value;
 import org.springframework.cache.CacheManager; 
 import org.springframework.stereotype.Service;
 import io.github.bucket4j.distributed.proxy.ClientSideConfig;

 import javax.cache.Cache; 
 import java.time.Duration;
 import java.util.function.Supplier;

 @Service
 public class RateLimitingService {

     private final ProxyManager<String> proxyManager;
     private final Bandwidth limit;

     public RateLimitingService(CacheManager cacheManager, 
                               @Value("${app.rate-limit.capacity}") long capacity,
                               @Value("${app.rate-limit.refill-rate}") long refillRate,
                               @Value("${app.rate-limit.refill-period}") long refillPeriod,
                               @Value("${app.rate-limit.refill-unit}") String refillUnit) {

         Cache<String, byte[]> jCache = (Cache<String, byte[]>) cacheManager.getCache("rateLimitCache").getNativeCache();
         this.proxyManager = Bucket4jJCache.entryProcessorBasedBuilder(jCache)
            .build();

         Duration duration = switch (refillUnit.toUpperCase()) {
             case "SECONDS" -> Duration.ofSeconds(refillPeriod);
             case "HOURS" -> Duration.ofHours(refillPeriod);
             default -> Duration.ofMinutes(refillPeriod); 
         };

         this.limit = Bandwidth.classic(capacity, Refill.greedy(refillRate, duration));
         System.out.println("Rate Limit Configured: " + capacity + " requests / " + refillPeriod + " " + refillUnit);
     }

     public Bucket resolveBucket(String key) {
         Supplier<BucketConfiguration> configSupplier = () -> BucketConfiguration.builder()
                 .addLimit(this.limit)
                 .build();
         return proxyManager.builder().build(key, configSupplier);
     }
 }
