package com.toxicsoap.service;

import com.toxicsoap.model.AuthContext;
import com.toxicsoap.model.Order;
import com.toxicsoap.model.Product;
import com.toxicsoap.model.User;
import jakarta.jws.WebService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * BankingPortalServiceImpl - Unified SOAP service with all operations.
 *
 * DELIBERATELY VULNERABLE - For security scanner testing only.
 *
 * Vulnerabilities by operation:
 * - PUBLIC: SQL Injection, XXE, XML Bomb, SSRF, Information Disclosure
 * - USER AUTH: SQL Injection, IDOR, XPath Injection, Sensitive Data Exposure
 * - ADMIN AUTH: Command Injection, LDAP Injection, Insecure Deserialization, Path Traversal
 */
@Service
@WebService(
    serviceName = "BankingPortalService",
    portName = "BankingPortalServicePort",
    targetNamespace = "http://toxicsoap.com/banking",
    endpointInterface = "com.toxicsoap.service.BankingPortalService"
)
public class BankingPortalServiceImpl implements BankingPortalService {

    private static final Logger logger = LoggerFactory.getLogger(BankingPortalServiceImpl.class);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // Sample XML data for XPath injection demo
    private static final String USER_DATA_XML = """
        <users>
            <user id="1">
                <username>user</username>
                <email>user@example.com</email>
                <secret>user-secret-key-12345</secret>
                <role>USER</role>
            </user>
            <user id="2">
                <username>admin</username>
                <email>admin@example.com</email>
                <secret>admin-master-key-99999</secret>
                <role>ADMIN</role>
            </user>
            <user id="3">
                <username>guest</username>
                <email>guest@example.com</email>
                <secret>guest-temporary-key</secret>
                <role>GUEST</role>
            </user>
        </users>
        """;

    // ==================== AUTH HELPERS ====================

    private void requireAuth() {
        AuthContext ctx = AuthContext.get();
        if (!ctx.isAuthenticated()) {
            throw new RuntimeException("Authentication required. Please provide valid credentials.");
        }
    }

    private void requireAdmin() {
        AuthContext ctx = AuthContext.get();
        if (!ctx.isAuthenticated()) {
            throw new RuntimeException("Authentication required. Please provide valid credentials.");
        }
        if (!ctx.hasRole("ADMIN")) {
            throw new RuntimeException("Admin privileges required. Current role: " + ctx.getRole());
        }
    }

    /**
     * Extracts the root cause SQLException from Spring's exception wrapper.
     * This exposes the real database error message for security scanners.
     */
    private String extractSqlError(Exception e) {
        Throwable rootCause = e;
        while (rootCause.getCause() != null) {
            rootCause = rootCause.getCause();
        }

        if (rootCause instanceof java.sql.SQLException sqlEx) {
            return "java.sql.SQLException: " + sqlEx.getMessage() +
                   " [SQLState: " + sqlEx.getSQLState() +
                   ", ErrorCode: " + sqlEx.getErrorCode() + "]";
        }
        return e.getMessage();
    }

    // ==================== PUBLIC OPERATIONS (No Auth) ====================

    /**
     * VULNERABILITY: SQL Injection
     * The productId is directly concatenated into the SQL query without sanitization.
     */
    @Override
    public Product getProductById(String productId) {
        logger.info("Getting product by ID: {}", productId);

        // VULNERABLE: SQL Injection - productId directly concatenated
        String sql = "SELECT * FROM products WHERE id = " + productId;
        logger.debug("Executing SQL: {}", sql);

        try {
            return jdbcTemplate.queryForObject(sql, (rs, rowNum) -> {
                Product p = new Product();
                p.setId(rs.getInt("id"));
                p.setName(rs.getString("name"));
                p.setDescription(rs.getString("description"));
                p.setPrice(rs.getDouble("price"));
                p.setCategory(rs.getString("category"));
                p.setImageUrl(rs.getString("image_url"));
                return p;
            });
        } catch (Exception e) {
            // VULNERABILITY: Information Disclosure - full stack trace exposed
            logger.error("Error executing query", e);
            throw new RuntimeException("Database error: " + extractSqlError(e) + "\nSQL: " + sql, e);
        }
    }

    /**
     * VULNERABILITY: XXE (XML External Entity) Injection
     * XML parsing without disabling external entities allows attackers to read local files
     * or perform SSRF attacks.
     */
    @Override
    public List<Product> searchProducts(String xmlQuery) {
        logger.info("Searching products with XML query");
        List<Product> results = new ArrayList<>();

        try {
            // VULNERABLE: XXE - External entities are enabled
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // These secure settings are intentionally NOT set:
            // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlQuery)));

            Element root = doc.getDocumentElement();
            String category = getElementText(root, "category");
            String name = getElementText(root, "name");

            StringBuilder sql = new StringBuilder("SELECT * FROM products WHERE 1=1");
            if (category != null && !category.isEmpty()) {
                sql.append(" AND category = '").append(category).append("'");
            }
            if (name != null && !name.isEmpty()) {
                sql.append(" AND name LIKE '%").append(name).append("%'");
            }

            logger.debug("Executing SQL: {}", sql);

            results = jdbcTemplate.query(sql.toString(), (rs, rowNum) -> {
                Product p = new Product();
                p.setId(rs.getInt("id"));
                p.setName(rs.getString("name"));
                p.setDescription(rs.getString("description"));
                p.setPrice(rs.getDouble("price"));
                p.setCategory(rs.getString("category"));
                p.setImageUrl(rs.getString("image_url"));
                return p;
            });

        } catch (Exception e) {
            // VULNERABILITY: Information Disclosure - full exception details
            logger.error("Error parsing XML query", e);
            throw new RuntimeException("XML parsing error: " + e.getMessage(), e);
        }

        return results;
    }

    /**
     * VULNERABILITY: XML Bomb (Billion Laughs Attack)
     * No limits on entity expansion allows DoS attacks.
     */
    @Override
    public String parseProductXml(String productXml) {
        logger.info("Parsing product XML");

        try {
            // VULNERABLE: XML Bomb - No entity expansion limits
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Intentionally NOT setting secure processing or limits

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(productXml)));

            Element root = doc.getDocumentElement();
            StringBuilder result = new StringBuilder();
            result.append("Parsed product: ");
            result.append("Name=").append(getElementText(root, "name"));
            result.append(", Price=").append(getElementText(root, "price"));
            result.append(", Description=").append(getElementText(root, "description"));

            return result.toString();

        } catch (Exception e) {
            logger.error("Error parsing product XML", e);
            throw new RuntimeException("XML parsing error: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: SSRF (Server-Side Request Forgery)
     * The URL is fetched without validation, allowing attackers to probe internal networks.
     */
    @Override
    public String fetchProductImage(String imageUrl) {
        logger.info("Fetching product image from URL: {}", imageUrl);

        try {
            // VULNERABLE: SSRF - No URL validation
            URL url = new URL(imageUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line).append("\n");
                }
            }

            // Return response info (useful for SSRF exploitation)
            return "Response Code: " + conn.getResponseCode() +
                   "\nContent-Type: " + conn.getContentType() +
                   "\nContent-Length: " + conn.getContentLength() +
                   "\nResponse (first 1000 chars):\n" +
                   response.substring(0, Math.min(response.length(), 1000));

        } catch (Exception e) {
            // VULNERABILITY: Information Disclosure - connection errors reveal internal network info
            logger.error("Error fetching URL", e);
            throw new RuntimeException("Failed to fetch URL " + imageUrl + ": " + e.getMessage(), e);
        }
    }

    @Override
    public List<Product> listAllProducts() {
        logger.info("Listing all products");
        return jdbcTemplate.query("SELECT * FROM products", (rs, rowNum) -> {
            Product p = new Product();
            p.setId(rs.getInt("id"));
            p.setName(rs.getString("name"));
            p.setDescription(rs.getString("description"));
            p.setPrice(rs.getDouble("price"));
            p.setCategory(rs.getString("category"));
            p.setImageUrl(rs.getString("image_url"));
            return p;
        });
    }

    // ==================== USER OPERATIONS (Auth Required) ====================

    /**
     * VULNERABILITY: SQL Injection
     * User-controlled search query is concatenated into SQL.
     */
    @Override
    public List<Order> getUserOrders(String searchQuery) {
        requireAuth();
        AuthContext ctx = AuthContext.get();
        logger.info("User {} searching orders with query: {}", ctx.getUsername(), searchQuery);

        // VULNERABLE: SQL Injection - searchQuery directly concatenated
        String sql = "SELECT * FROM orders WHERE status LIKE '%" + searchQuery + "%'";
        logger.debug("Executing SQL: {}", sql);

        try {
            return jdbcTemplate.query(sql, (rs, rowNum) -> {
                Order o = new Order();
                o.setId(rs.getInt("id"));
                o.setUserId(rs.getInt("user_id"));
                o.setProductId(rs.getInt("product_id"));
                o.setQuantity(rs.getInt("quantity"));
                o.setTotalPrice(rs.getDouble("total_price"));
                o.setStatus(rs.getString("status"));
                o.setOrderDate(new Date(rs.getTimestamp("order_date").getTime()));
                o.setShippingAddress(rs.getString("shipping_address"));
                return o;
            });
        } catch (Exception e) {
            logger.error("Error searching orders", e);
            throw new RuntimeException("Database error: " + extractSqlError(e) + "\nSQL: " + sql, e);
        }
    }

    /**
     * VULNERABILITY: Broken Access Control (IDOR)
     * User can access any user's profile by specifying their ID.
     */
    @Override
    public User getUserProfile(int userId) {
        requireAuth();
        AuthContext ctx = AuthContext.get();
        logger.info("User {} requesting profile for user ID: {}", ctx.getUsername(), userId);

        // VULNERABLE: IDOR - No check if user is accessing their own profile
        // Should verify ctx.getUsername() matches the requested userId

        try {
            return jdbcTemplate.queryForObject(
                "SELECT * FROM users WHERE id = ?",
                new Object[]{userId},
                (rs, rowNum) -> {
                    User u = new User();
                    u.setId(rs.getInt("id"));
                    u.setUsername(rs.getString("username"));
                    u.setEmail(rs.getString("email"));
                    u.setRole(rs.getString("role"));
                    // Not returning sensitive fields here
                    return u;
                }
            );
        } catch (Exception e) {
            logger.error("Error fetching user profile", e);
            throw new RuntimeException("Error fetching profile: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: XPath Injection
     * User input is directly interpolated into XPath query.
     */
    @Override
    public String searchUserData(String xpathQuery) {
        requireAuth();
        AuthContext ctx = AuthContext.get();
        logger.info("User {} executing XPath query: {}", ctx.getUsername(), xpathQuery);

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(USER_DATA_XML)));

            XPath xpath = XPathFactory.newInstance().newXPath();

            // VULNERABLE: XPath Injection - user input directly in query
            // Example attack: ' or '1'='1
            String query = "/users/user[username='" + xpathQuery + "']/email";
            logger.debug("Executing XPath: {}", query);

            String result = xpath.evaluate(query, doc);
            return "Query result: " + result;

        } catch (Exception e) {
            logger.error("Error executing XPath query", e);
            throw new RuntimeException("XPath error: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: Sensitive Data Exposure
     * Returns full user profile including password, API tokens, credit card, SSN.
     */
    @Override
    public User getFullProfile() {
        requireAuth();
        AuthContext ctx = AuthContext.get();
        logger.info("User {} requesting full profile", ctx.getUsername());

        try {
            return jdbcTemplate.queryForObject(
                "SELECT * FROM users WHERE username = ?",
                new Object[]{ctx.getUsername()},
                (rs, rowNum) -> {
                    User u = new User();
                    u.setId(rs.getInt("id"));
                    u.setUsername(rs.getString("username"));
                    // VULNERABLE: Exposing sensitive data
                    u.setPassword(rs.getString("password"));
                    u.setEmail(rs.getString("email"));
                    u.setRole(rs.getString("role"));
                    u.setApiToken(rs.getString("api_token"));
                    u.setCreditCard(rs.getString("credit_card"));
                    u.setSsn(rs.getString("ssn"));
                    return u;
                }
            );
        } catch (Exception e) {
            logger.error("Error fetching full profile", e);
            throw new RuntimeException("Error: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: SQL Injection via XML parsing
     */
    @Override
    public boolean updateProfile(String userData) {
        requireAuth();
        AuthContext ctx = AuthContext.get();
        logger.info("User {} updating profile", ctx.getUsername());

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(userData)));

            String email = doc.getElementsByTagName("email").item(0).getTextContent();

            // VULNERABLE: SQL Injection through XML-parsed data
            String sql = "UPDATE users SET email = '" + email + "' WHERE username = '" + ctx.getUsername() + "'";
            logger.debug("Executing SQL: {}", sql);

            jdbcTemplate.execute(sql);
            return true;

        } catch (Exception e) {
            logger.error("Error updating profile", e);
            throw new RuntimeException("Update failed: " + extractSqlError(e), e);
        }
    }

    // ==================== ADMIN OPERATIONS (Admin Role Required) ====================

    /**
     * VULNERABILITY: Command Injection
     * User input is passed directly to Runtime.exec() allowing arbitrary command execution.
     */
    @Override
    public String generateReport(String reportFormat) {
        requireAdmin();
        AuthContext ctx = AuthContext.get();
        logger.info("Admin {} generating report in format: {}", ctx.getUsername(), reportFormat);

        try {
            // VULNERABLE: Command Injection - format is passed directly to shell
            // Example attack: pdf; cat /etc/passwd
            String command = "echo Report generated in format: " + reportFormat;
            logger.debug("Executing command: {}", command);

            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // Also capture stderr for more information disclosure
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append("ERROR: ").append(line).append("\n");
                }
            }

            process.waitFor();
            return output.toString();

        } catch (Exception e) {
            logger.error("Error generating report", e);
            throw new RuntimeException("Report generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: LDAP Injection
     * User input is directly interpolated into LDAP filter without sanitization.
     */
    @Override
    public String lookupEmployee(String ldapFilter) {
        requireAdmin();
        AuthContext ctx = AuthContext.get();
        logger.info("Admin {} looking up employee with filter: {}", ctx.getUsername(), ldapFilter);

        // VULNERABLE: LDAP Injection
        // Example attack: *)(uid=*))(|(uid=*
        String filter = "(cn=" + ldapFilter + ")";
        logger.debug("LDAP filter: {}", filter);

        // Note: This will fail without an actual LDAP server, but demonstrates the vulnerability
        // In a real scenario, this would connect to an LDAP directory

        try {
            // Simulate LDAP lookup (without actual LDAP server)
            // In production, this would use:
            // Hashtable<String, String> env = new Hashtable<>();
            // env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            // env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            // DirContext ctx = new InitialDirContext(env);

            return "LDAP query executed with filter: " + filter +
                   "\n(Note: No LDAP server configured. In production, this would return directory results.)" +
                   "\nVulnerable to LDAP injection attacks.";

        } catch (Exception e) {
            logger.error("LDAP lookup error", e);
            throw new RuntimeException("LDAP error: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: Insecure Deserialization
     * Deserializes untrusted data which can lead to remote code execution.
     */
    @Override
    public String importData(byte[] serializedData) {
        requireAdmin();
        AuthContext ctx = AuthContext.get();
        logger.info("Admin {} importing serialized data ({} bytes)", ctx.getUsername(),
                    serializedData != null ? serializedData.length : 0);

        if (serializedData == null || serializedData.length == 0) {
            return "No data provided";
        }

        try {
            // VULNERABLE: Insecure Deserialization
            // Deserializing untrusted data can lead to RCE via gadget chains
            // (e.g., commons-collections gadgets)
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
            Object obj = ois.readObject();
            ois.close();

            return "Data imported successfully. Object type: " + obj.getClass().getName() +
                   "\nObject: " + obj.toString();

        } catch (Exception e) {
            logger.error("Error importing data", e);
            throw new RuntimeException("Import failed: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: Direct Command Execution
     * Allows arbitrary system command execution (more direct than generateReport).
     */
    @Override
    public String executeSystemCommand(String command) {
        requireAdmin();
        AuthContext ctx = AuthContext.get();
        logger.info("Admin {} executing system command: {}", ctx.getUsername(), command);

        try {
            // VULNERABLE: Direct command execution
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            process.waitFor();
            return "Command output:\n" + output.toString();

        } catch (Exception e) {
            logger.error("Error executing command", e);
            throw new RuntimeException("Command execution failed: " + e.getMessage(), e);
        }
    }

    /**
     * VULNERABILITY: Path Traversal
     * Allows reading arbitrary files from the filesystem.
     */
    @Override
    public String readConfigFile(String filePath) {
        requireAdmin();
        AuthContext ctx = AuthContext.get();
        logger.info("Admin {} reading config file: {}", ctx.getUsername(), filePath);

        try {
            // VULNERABLE: Path Traversal
            // Example attack: ../../../etc/passwd
            String content = Files.readString(Paths.get(filePath));
            return "File content:\n" + content;

        } catch (Exception e) {
            logger.error("Error reading file", e);
            throw new RuntimeException("File read error for path '" + filePath + "': " + e.getMessage(), e);
        }
    }

    // ==================== HELPER METHODS ====================

    private String getElementText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return null;
    }
}
