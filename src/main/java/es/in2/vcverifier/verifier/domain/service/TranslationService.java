package es.in2.vcverifier.verifier.domain.service;

public interface TranslationService {
    String getLocale();
    String translate(String code, Object... args);
}

