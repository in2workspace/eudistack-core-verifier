package es.in2.vcverifier.sso.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * US-06 (Single Logout, AD-2): pool acotado dedicado para el dispatch asíncrono de
 * Back-Channel Logout. Aísla la latencia/fallo de los callees del hilo de la request
 * del iniciador (AC-03) — separado del executor genérico de la aplicación.
 */
@Configuration
public class BackChannelLogoutExecutorConfig {

    @Bean(name = "backChannelLogoutExecutor")
    public Executor backChannelLogoutExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(4);
        executor.setMaxPoolSize(16);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("backchannel-logout-");
        executor.initialize();
        return executor;
    }
}
