package com.secureloginimplementation.demo;

 import io.github.bucket4j.Bucket;
 import io.github.bucket4j.ConsumptionProbe;
 import jakarta.servlet.http.HttpServletRequest; 
 import jakarta.servlet.http.HttpServletResponse;
 import org.springframework.http.HttpStatus;
 import org.springframework.stereotype.Component;
 import org.springframework.web.servlet.HandlerInterceptor;

 @Component
 public class RateLimitInterceptor implements HandlerInterceptor {

     private final RateLimitingService rateLimitingService;

     public RateLimitInterceptor(RateLimitingService rateLimitingService) {
         this.rateLimitingService = rateLimitingService;
     }

     @Override
     public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
         String ipAddress = request.getRemoteAddr();
         Bucket bucket = rateLimitingService.resolveBucket(ipAddress);
         ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

         if (probe.isConsumed()) {
             response.addHeader("X-Rate-Limit-Remaining", String.valueOf(probe.getRemainingTokens()));
             System.out.println("Request allowed for IP: " + ipAddress + ", Remaining tokens: " + probe.getRemainingTokens());
             return true;
         } else {
        
             long waitForRefillNanos = probe.getNanosToWaitForRefill();
             long waitForRefillSeconds = java.util.concurrent.TimeUnit.NANOSECONDS.toSeconds(waitForRefillNanos);

             response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value()); 
             response.addHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(waitForRefillSeconds));
             response.getWriter().write("Too many requests");
             System.out.println("Rate limit exceeded for IP: " + ipAddress + ". Wait for " + waitForRefillSeconds + " seconds.");
             return false; 
         }
     }
 }
