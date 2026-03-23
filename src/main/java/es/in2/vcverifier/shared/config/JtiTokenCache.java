package es.in2.vcverifier.shared.config;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.NoSuchElementException;

@Component
@RequiredArgsConstructor
public class JtiTokenCache {

    private final CacheStore<String> jtiCacheStore;

    public void addJti(String jti) {
        jtiCacheStore.add(jti, "present");
    }

    public boolean isJtiPresent(String jti) {
        try {
            jtiCacheStore.get(jti);
            return true;
        } catch (NoSuchElementException e) {
            return false;
        }
    }

}
