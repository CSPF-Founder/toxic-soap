package com.toxicsoap.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(1)
public class WsdlDownloadFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String queryString = httpRequest.getQueryString();

        // Only force download when ?wsdl&download is used
        // Regular ?wsdl will display in browser as usual
        if (queryString != null && queryString.toLowerCase().contains("wsdl")
                && queryString.toLowerCase().contains("download")) {
            httpResponse.setHeader("Content-Disposition", "attachment; filename=\"toxic-soap.wsdl\"");
        }

        chain.doFilter(request, response);
    }
}
