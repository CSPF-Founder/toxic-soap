package com.toxicsoap;

import com.toxicsoap.config.AuthProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AuthProperties.class)
public class ToxicSoapApplication {

    public static void main(String[] args) {
        SpringApplication.run(ToxicSoapApplication.class, args);
    }
}
