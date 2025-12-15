package com.toxicsoap.interceptor;

import com.toxicsoap.model.AuthContext;
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

import jakarta.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthInterceptor extends AbstractSoapInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(AuthInterceptor.class);
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

    private static final Map<String, UserCredentials> USERS = new HashMap<>();

    static {
        USERS.put("user", new UserCredentials("user123", "USER"));
        USERS.put("admin", new UserCredentials("admin123", "ADMIN"));
        USERS.put("guest", new UserCredentials("guest", "GUEST"));
    }

    public AuthInterceptor() {
        super(Phase.PRE_INVOKE);
    }

    @Override
    public void handleMessage(SoapMessage message) throws Fault {
        AuthContext.clear();
        AuthContext ctx = AuthContext.get();

        if (tryWsSecurityAuth(message, ctx)) {
            logger.debug("WS-Security authentication successful for user: {}", ctx.getUsername());
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

            return authenticate(username, password, ctx);
        } catch (Exception e) {
            logger.debug("WS-Security auth failed: {}", e.getMessage());
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
            if (authHeader == null || !authHeader.startsWith("Basic ")) {
                return false;
            }

            String base64Credentials = authHeader.substring("Basic ".length()).trim();
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(decodedBytes, StandardCharsets.UTF_8);
            String[] parts = credentials.split(":", 2);

            if (parts.length != 2) {
                return false;
            }

            return authenticate(parts[0], parts[1], ctx);
        } catch (Exception e) {
            logger.debug("Basic auth failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean authenticate(String username, String password, AuthContext ctx) {
        if (username == null || password == null) {
            return false;
        }

        UserCredentials creds = USERS.get(username);
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

    private static class UserCredentials {
        final String password;
        final String role;

        UserCredentials(String password, String role) {
            this.password = password;
            this.role = role;
        }
    }
}
