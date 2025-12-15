package com.toxicsoap.interceptor;

import com.toxicsoap.config.AuthProperties;
import com.toxicsoap.model.AuthContext;
import com.toxicsoap.service.JwtService;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.transport.http.AbstractHTTPDestination;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class AuthInterceptor extends AbstractSoapInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(AuthInterceptor.class);
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String API_KEY_HEADER = "X-API-Key";

    private final AuthProperties authProperties;
    private final JwtService jwtService;

    private final Map<String, UserCredentials> usersByUsername = new HashMap<>();
    private final Map<String, ApiKeyCredentials> apiKeyMap = new HashMap<>();

    public AuthInterceptor(AuthProperties authProperties, JwtService jwtService) {
        super(Phase.PRE_INVOKE);
        this.authProperties = authProperties;
        this.jwtService = jwtService;
    }

    @PostConstruct
    public void init() {
        // Load users from configuration
        for (AuthProperties.UserConfig user : authProperties.getUsers()) {
            usersByUsername.put(user.getUsername(),
                new UserCredentials(user.getPassword(), user.getRole()));
            logger.debug("Loaded user: {} with role: {}", user.getUsername(), user.getRole());
        }

        // Load API keys from configuration
        for (AuthProperties.ApiKeyConfig apiKey : authProperties.getApiKeys()) {
            apiKeyMap.put(apiKey.getKey(),
                new ApiKeyCredentials(apiKey.getUsername(), apiKey.getRole()));
            logger.debug("Loaded API key for user: {}", apiKey.getUsername());
        }
    }

    @Override
    public void handleMessage(SoapMessage message) throws Fault {
        AuthContext.clear();
        AuthContext ctx = AuthContext.get();

        // Order of authentication attempts:
        // 1. WS-Security (SOAP header - most specific to SOAP)
        // 2. Bearer Token (JWT - modern, preferred for programmatic access)
        // 3. API Key (simple, good for service-to-service)
        // 4. Basic Auth (legacy, fallback)

        if (tryWsSecurityAuth(message, ctx)) {
            logger.debug("WS-Security authentication successful for user: {}", ctx.getUsername());
            return;
        }

        if (tryBearerAuth(message, ctx)) {
            logger.debug("Bearer token authentication successful for user: {}", ctx.getUsername());
            return;
        }

        if (tryApiKeyAuth(message, ctx)) {
            logger.debug("API key authentication successful for user: {}", ctx.getUsername());
            return;
        }

        if (tryBasicAuth(message, ctx)) {
            logger.debug("Basic HTTP authentication successful for user: {}", ctx.getUsername());
            return;
        }

        logger.debug("No authentication provided");
    }

    private boolean tryWsSecurityAuth(SoapMessage message, AuthContext ctx) {
        try {
            Header securityHeader = message.getHeader(new QName(WSSE_NS, "Security"));
            if (securityHeader == null) {
                return false;
            }

            Element securityElement = (Element) securityHeader.getObject();
            NodeList usernameTokens = securityElement.getElementsByTagNameNS(WSSE_NS, "UsernameToken");

            if (usernameTokens.getLength() == 0) {
                return false;
            }

            Element usernameToken = (Element) usernameTokens.item(0);
            String username = getElementValue(usernameToken, WSSE_NS, "Username");
            String password = getElementValue(usernameToken, WSSE_NS, "Password");

            return authenticateWithPassword(username, password, ctx);
        } catch (Exception e) {
            logger.debug("WS-Security auth failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean tryBearerAuth(SoapMessage message, AuthContext ctx) {
        try {
            HttpServletRequest request = (HttpServletRequest) message.get(AbstractHTTPDestination.HTTP_REQUEST);
            if (request == null) {
                return false;
            }

            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
                return false;
            }

            String token = authHeader.substring(BEARER_PREFIX.length()).trim();
            if (token.isEmpty()) {
                return false;
            }

            Optional<JwtService.JwtClaims> claims = jwtService.parseToken(token);
            if (claims.isEmpty()) {
                logger.debug("Invalid or expired JWT token");
                return false;
            }

            JwtService.JwtClaims jwtClaims = claims.get();

            // Verify user exists in our system
            if (!usersByUsername.containsKey(jwtClaims.username())) {
                logger.debug("JWT user not found in system: {}", jwtClaims.username());
                return false;
            }

            ctx.setUsername(jwtClaims.username());
            ctx.setRole(jwtClaims.role());
            ctx.setAuthenticated(true);
            return true;

        } catch (Exception e) {
            logger.debug("Bearer auth failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean tryApiKeyAuth(SoapMessage message, AuthContext ctx) {
        try {
            HttpServletRequest request = (HttpServletRequest) message.get(AbstractHTTPDestination.HTTP_REQUEST);
            if (request == null) {
                return false;
            }

            String apiKey = request.getHeader(API_KEY_HEADER);
            if (apiKey == null || apiKey.trim().isEmpty()) {
                return false;
            }

            ApiKeyCredentials creds = apiKeyMap.get(apiKey.trim());
            if (creds == null) {
                logger.debug("Unknown API key");
                return false;
            }

            ctx.setUsername(creds.username);
            ctx.setRole(creds.role);
            ctx.setAuthenticated(true);
            return true;

        } catch (Exception e) {
            logger.debug("API key auth failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean tryBasicAuth(SoapMessage message, AuthContext ctx) {
        try {
            HttpServletRequest request = (HttpServletRequest) message.get(AbstractHTTPDestination.HTTP_REQUEST);
            if (request == null) {
                return false;
            }

            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith(BASIC_PREFIX)) {
                return false;
            }

            String base64Credentials = authHeader.substring(BASIC_PREFIX.length()).trim();
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(decodedBytes, StandardCharsets.UTF_8);
            String[] parts = credentials.split(":", 2);

            if (parts.length != 2) {
                return false;
            }

            return authenticateWithPassword(parts[0], parts[1], ctx);
        } catch (Exception e) {
            logger.debug("Basic auth failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean authenticateWithPassword(String username, String password, AuthContext ctx) {
        if (username == null || password == null) {
            return false;
        }

        UserCredentials creds = usersByUsername.get(username);
        if (creds != null && creds.password.equals(password)) {
            ctx.setUsername(username);
            ctx.setRole(creds.role);
            ctx.setAuthenticated(true);
            return true;
        }
        return false;
    }

    private String getElementValue(Element parent, String namespace, String localName) {
        NodeList elements = parent.getElementsByTagNameNS(namespace, localName);
        if (elements.getLength() > 0) {
            return elements.item(0).getTextContent();
        }
        return null;
    }

    private record UserCredentials(String password, String role) {}

    private record ApiKeyCredentials(String username, String role) {}
}
