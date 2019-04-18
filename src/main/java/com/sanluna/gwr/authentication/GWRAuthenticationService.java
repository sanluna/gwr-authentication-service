package com.sanluna.gwr.authentication;

import com.sanluna.gwr.authentication.security.GWRAuthenticationProvider;
import com.sanluna.gwr.authentication.service.GWRUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import sanluna.gwr.security.principal.GWRTokenConverter;

@SpringBootApplication
public class GWRAuthenticationService {

    @Value("${GWR.security.prv}")
    private String prvKey;
    @Value("${GWR.security.pub}")
    private String pubKey;

    public static void main(String[] args) {
        SpringApplication.run(GWRAuthenticationService.class, args);
    }

    @Bean
    @Primary
    public BCryptPasswordEncoder userPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Primary
    public GWRUserDetailsService userDetailsService() {
        return new GWRUserDetailsService();
    }

    @Bean
    @Primary
    public GWRAuthenticationProvider getAuthenticationProvider() {
        return new GWRAuthenticationProvider();
    }

    @Bean
    @Primary
    public JwtAccessTokenConverter accessTokenConverter() {
        GWRTokenConverter converter = new GWRTokenConverter();
        converter.setSigningKey(prvKey);
        converter.setVerifierKey(pubKey);
        return converter;
    }

}
