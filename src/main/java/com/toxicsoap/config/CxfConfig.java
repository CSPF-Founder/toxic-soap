package com.toxicsoap.config;

import com.toxicsoap.interceptor.AuthInterceptor;
import com.toxicsoap.service.BankingPortalService;
import jakarta.xml.ws.Endpoint;
import org.apache.cxf.Bus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CxfConfig {

    @Autowired
    private Bus bus;

    @Autowired
    private BankingPortalService bankingPortalService;

    @Autowired
    private AuthInterceptor authInterceptor;

    @Bean
    public Endpoint bankingEndpoint() {
        EndpointImpl endpoint = new EndpointImpl(bus, bankingPortalService);
        endpoint.publish("/banking");
        // Auth interceptor extracts credentials for all requests
        // Authorization is enforced per-operation in the service implementation
        endpoint.getInInterceptors().add(authInterceptor);
        return endpoint;
    }
}
