package es.in2.vcverifier.shared.config;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditContextFilterConfigTest {

    /**
     * The starter registers its own filter with {@code @ConditionalOnMissingBean(name = "auditContextFilter")}.
     * This one replaces it only while it has that name: under another one the request would get two filters.
     */
    @Test
    void filterBean_isNamedLikeTheOneOfTheStarterSoItReplacesItInsteadOfAddingASecondOne() {
        List<Method> beans = Arrays.stream(AuditContextFilterConfig.class.getDeclaredMethods())
                .filter(method -> method.isAnnotationPresent(Bean.class))
                .toList();

        assertEquals(1, beans.size());
        assertEquals("auditContextFilter", beans.getFirst().getName());
        assertEquals(0, beans.getFirst().getAnnotation(Bean.class).name().length);
    }
}
