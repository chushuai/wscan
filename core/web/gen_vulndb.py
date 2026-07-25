#!/usr/bin/env python3
"""
Generate the embedded vuln description DB under core/web/vulndb/.

Two kinds of entries:
  1. json-sourced: pulled from core/scannable_vuln.json byAppId. The target id
     (xml stem) may differ from the json key; JSON_REMAP maps target -> source key.
  2. hand-written: defined in HANDWRITTEN below. These cover wscan-specific or
     per-CVE checks that have no good match in the AWVS-derived json.

Only ids listed in core/web/vulndb_allowlist.txt are emitted (the set of vuln
types reachable from a plugin Binding.ID via the vulnIDAliases map in
vulndb.go). Run from repo root:  python3 core/web/gen_vulndb.py
"""
import json
import os
import sys
from xml.sax.saxutils import escape

SRC = "core/scannable_vuln.json"
DST = "core/web/vulndb"
ALLOWLIST = "core/web/vulndb_allowlist.txt"

# target id (xml stem) -> source json key. Used when the id we want is not a
# json key itself but a different entry describes exactly that vuln class.
JSON_REMAP = {
    "xxe": "xml_external_entity_injection_and_xml_injection2.xml",
    "http_parameter_pollution": "hpp.xml",
    "waf_detected": "waf_detected.xml",
    "git_repository_found": "git_repository_found.xml",
    "host_header_attack": "host_header_attack.xml",
    "no_https": "no_https.xml",
    "csp_not_implemented": "csp_not_implemented.xml",
}

# Hand-written entries. severity: 0 info,1 low,2 medium,3 high,4 critical.
# Each value is a dict of fields; references is a list of (title,url) tuples.
HANDWRITTEN = {
    "open_redirect": {
        "name": "Open Redirect",
        "description": "The application accepts a user-controlled URL or parameter value and uses it as the target of an HTTP redirect (via a 3xx Location header or a client-side redirect) without sufficient validation. An attacker can craft a link that appears to come from the trusted site but redirects the victim to an arbitrary external domain.",
        "impact": "Open redirects are abused in phishing campaigns: the victim sees a familiar hostname and is transparently forwarded to an attacker-controlled site. They can also bypass anti-CSRF or SSO flows that rely on a trusted return URL, and in some cases lead to SSRF when the redirect target is fetched server-side.",
        "recommendation": "Do not redirect to absolute URLs taken directly from user input. Use a server-side allowlist of permitted redirect destinations, or map untrusted values to known keys. If only relative redirects are needed, validate that the resolved path stays within the origin and reject absolute URLs and protocol-relative URLs (//host).",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "tags": ["open_redirect", "CWE-601"],
        "references": [
            ("OWASP Open Redirect", "https://owasp.org/www-community/attacks/Redirect_After_Login"),
            ("CWE-601", "https://cwe.mitre.org/data/definitions/601.html"),
        ],
    },
    "ssl_certificate_expired": {
        "name": "SSL/TLS Certificate Expired or Invalid",
        "description": "The server's TLS certificate is expired, not yet valid, or otherwise invalid (self-signed without trust, hostname mismatch, revoked). Browsers will warn or block users; automated clients may refuse the connection.",
        "impact": "An expired or invalid certificate breaks encryption trust: users are trained to click through warnings, which enables man-in-the-middle attacks. Valid clients fail to connect, and the service may be flagged as insecure by scanners.",
        "recommendation": "Renew certificates before expiry, monitor expiration dates, and automate renewal (e.g. ACME/Let's Encrypt). Ensure the certificate matches the served hostname and is issued by a trusted CA.",
        "severity": 2,
        "cvss3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "tags": ["ssl_tls", "CWE-295"],
        "references": [
            ("CWE-295: Improper Certificate Validation", "https://cwe.mitre.org/data/definitions/295.html"),
        ],
    },
    "vcs_svn_leak": {
        "name": "SVN Repository Metadata Exposed",
        "description": "The target serves the Subversion metadata directory (.svn/) of a working copy, typically left in the web root by a deployment that copied the whole repository instead of exporting it. The .svn/entries file reveals the file list of the project.",
        "impact": "An attacker can reconstruct the full source tree of the application, including files never intended to be public (configuration, credentials, internal logic), leading to further compromise.",
        "recommendation": "Deploy from an svn export, never a checkout. Remove .svn/ directories from the web root and deny access to dotfiles in the web server config. Move the repository out of the document root entirely.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "tags": ["information_disclosure", "source_code_disclosure", "CWE-538"],
        "references": [
            ("OWASP: Test for Old Backup and Unreferenced Files", "https://owasp.org/www-community/web-vulnerabilities/source-code-disclosure"),
        ],
    },
    "flask_debug_mode": {
        "name": "Flask Debug Mode Enabled",
        "description": "The Flask application is running with debug mode (app.run(debug=True) or FLASK_DEBUG=1) enabled in production. The Werkzeug debugger exposes an interactive Python console at the traceback page.",
        "impact": "The Werkzeug debugger console allows arbitrary Python execution on the server by anyone who can trigger an exception (or via a PIN that is often brute-forceable). This is full remote code execution.",
        "recommendation": "Never run Flask with debug=True in production. Set FLASK_DEBUG=0 and use a production WSGI server (gunicorn/uwsgi). The debugger must never be reachable from untrusted clients.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["debug_mode", "rce", "CWE-489"],
        "references": [
            ("Flask Deployment", "https://flask.palletsprojects.com/en/latest/deploying/"),
            ("Werkzeug Debugger PIN", "https://werkzeug.palletsprojects.com/en/latest/debug/"),
        ],
    },
    "rails_debug_mode": {
        "name": "Ruby on Rails Debug Mode Enabled",
        "description": "The Rails application is running with the development environment or config.consider_all_requests_local = true in production. Unhandled exceptions return a detailed stack trace and environment dump to the client.",
        "impact": "Stack traces expose internal file paths, framework version, gems, and sometimes secrets from environment variables, aiding an attacker in crafting targeted exploits.",
        "recommendation": "Run Rails in the production environment (RAILS_ENV=production) and ensure config.consider_all_requests_local is false in production config. Serve a generic error page instead.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["debug_mode", "information_disclosure", "CWE-489"],
        "references": [
            ("Rails Configuring Applications", "https://guides.rubyonrails.org/configuring.html"),
        ],
    },
    "application_error_traceback": {
        "name": "Application Error / Stack Trace Disclosed",
        "description": "The application returns a detailed error message or stack trace to the client when an unexpected condition occurs. The trace reveals implementation details: file paths, library versions, SQL fragments, and sometimes credentials or session data.",
        "impact": "Information leakage from stack traces helps an attacker fingerprint the stack and craft targeted attacks. Repeated triggering can also enable denial of service.",
        "recommendation": "Disable detailed error output in production. Return a generic error page and log full traces server-side only. Set framework debug flags to false and use a production error handler.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["information_disclosure", "CWE-209"],
        "references": [
            ("CWE-209: Information Exposure Through Error Message", "https://cwe.mitre.org/data/definitions/209.html"),
        ],
    },
    "fingerprint": {
        "name": "Technology Fingerprint Identified",
        "description": "The server or application exposes identifying signals (HTTP headers such as Server, X-Powered-By, X-AspNet-Version; default error pages; favicon hashes; generator meta tags) that disclose the web server, framework, programming language, and in some cases the precise version.",
        "impact": "Version disclosure lets an attacker map the install to known CVEs and focus exploitation. On its own it is informational but it materially raises the risk of every other finding.",
        "recommendation": "Suppress fingerprinting headers and default landing pages. Set server_tokens off (nginx), ServerSignature Off / ServerTokens Prod (Apache), and remove X-Powered-By / X-AspNet-Version headers. Keep patched so that even a known fingerprint has no exploitable CVE.",
        "severity": 0,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "tags": ["fingerprint", "information_disclosure", "CWE-200"],
        "references": [
            ("CWE-200: Information Exposure", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },
    "tomcat_put_cve_2017_12615": {
        "name": "Apache Tomcat PUT Method RCE (CVE-2017-12615)",
        "description": "When running on Windows with the readonly initialisation parameter set to false, the default servlet in Apache Tomcat 7.0.0 through 7.0.81 processes a PUT request as a write. An attacker can upload a JSP file via a crafted PUT request and then request it to execute arbitrary code.",
        "impact": "Remote code execution with the privileges of the Tomcat process. Full server compromise.",
        "recommendation": "Upgrade Tomcat to a fixed version. Never set the DefaultServlet readonly parameter to false in production. Restrict HTTP methods to those actually required.",
        "severity": 4,
        "cvss3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["rce", "tomcat", "CVE-2017-12615", "CWE-434"],
        "references": [
            ("CVE-2017-12615", "https://nvd.nist.gov/vuln/detail/CVE-2017-12615"),
        ],
    },
    "tomcat_ghostcat_cve_2020_1938": {
        "name": "Apache Tomcat Ghostcat (CVE-2020-1938)",
        "description": "The AJP connector in Apache Tomcat 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54, and 7.0.0 to 7.0.99 did not validate the AJP request attributes. An attacker who can reach the AJP port (8009) can read or include any file the Tomcat process can read, and in some configurations execute included JSP files.",
        "impact": "Arbitrary file read and, where JSP inclusion is reachable, remote code execution.",
        "recommendation": "Upgrade Tomcat to a fixed version. Do not expose the AJP port to untrusted networks. Set the secret attribute on the AJP connector and require it.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "tags": ["tomcat", "file_read", "CVE-2020-1938", "CWE-20"],
        "references": [
            ("CVE-2020-1938", "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"),
        ],
    },
    "tomcat_example_apps": {
        "name": "Apache Tomcat Example Applications Exposed",
        "description": "The Tomcat distribution ships with example web applications (docs, examples, manager/help) under the webapps directory. These are deployed and reachable, leaking server info and in some cases offering functional endpoints.",
        "impact": "Examples leak version and configuration details and should never be present on a production server. They expand the attack surface.",
        "recommendation": "Remove the example webapps (docs, examples, ROOT default page) from the Tomcat webapps directory in production deployments.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["tomcat", "information_disclosure", "CWE-489"],
        "references": [],
    },
    "tomcat_manager_exposure": {
        "name": "Apache Tomcat Manager Application Exposed",
        "description": "The Tomcat Manager (and Host Manager) web application is reachable on the public interface. It allows deploying and undeploying web applications and is protected only by HTTP basic auth.",
        "impact": "If credentials are weak or default, an attacker can deploy a malicious WAR and achieve remote code execution. Even without valid credentials, the endpoint confirms Tomcat and invites brute force.",
        "recommendation": "Remove the manager and host-manager webapps, or bind them to a localhost/management interface only. Use strong unique credentials and IP restrictions.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["tomcat", "rce", "CWE-732"],
        "references": [
            ("Tomcat Manager App", "https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html"),
        ],
    },
    "jboss_jmx_console_exposed": {
        "name": "JBoss JMX Console Exposed",
        "description": "The JBoss JMX Console web application is reachable without authentication. The JMX console exposes management operations on MBeans, including deployment of new applications.",
        "impact": "An unauthenticated attacker can deploy a malicious WAR via the JMX console and gain remote code execution.",
        "recommendation": "Remove the JMX console from the public interface, enforce authentication, and restrict access to a management network. Upgrade to a supported JBoss/WildFly version.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["jboss", "rce", "CWE-306"],
        "references": [],
    },
    "jboss_mbeans_exposed": {
        "name": "JBoss MBeans Exposed",
        "description": "JBoss MBeans are reachable through an exposed JMX invoker or web console without authentication, allowing introspection and invocation of management operations.",
        "impact": "Exposes management operations to unauthenticated callers, enabling information disclosure and in many configurations remote code execution via WAR deployment.",
        "recommendation": "Secure or remove the JMX invoker and web console. Require authentication and restrict to a management network. Upgrade to a supported version.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["jboss", "rce", "CWE-306"],
        "references": [],
    },
    "jboss_status_servlet": {
        "name": "JBoss Status Servlet Exposed",
        "description": "The JBoss Status Servlet (status-servlet) is reachable, leaking deployment and connector information including active sessions and thread counts.",
        "impact": "Information disclosure that aids an attacker in understanding the deployment topology and targeting further attacks.",
        "recommendation": "Remove or restrict the status servlet. Require authentication and restrict to a management interface.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["jboss", "information_disclosure", "CWE-200"],
        "references": [],
    },
    "weblogic_console_exposed": {
        "name": "Oracle WebLogic Console Exposed",
        "description": "The Oracle WebLogic administration console (/console) is reachable on a public interface. It allows administration of the domain and is protected only by console credentials.",
        "impact": "Exposing the admin console invites credential brute force and exploitation of console CVEs. A successful login gives full control of the domain.",
        "recommendation": "Do not expose the WebLogic console on public interfaces. Restrict to a management network, enforce strong credentials, and keep patched.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["weblogic", "CWE-306"],
        "references": [],
    },
    "weblogic_wls_wsat_rce": {
        "name": "Oracle WebLogic WLS-WSAT RCE",
        "description": "The WebLogic WLS-WSAT component (and related wls9-async / _async endpoints) is vulnerable to deserialization of untrusted data, allowing unauthenticated remote code execution. Affects WebLogic 10.3.6.0, 12.1.3.0, 12.2.1.0-12.2.1.2.",
        "impact": "Unauthenticated remote code execution with the privileges of the WebLogic server.",
        "recommendation": "Apply the Oracle CPU patches. Remove or restrict the wls-wsat and wls9-async web applications. Restrict access to the WebLogic admin paths.",
        "severity": 4,
        "cvss3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["weblogic", "rce", "deserialization", "CWE-502"],
        "references": [
            ("Oracle CPU Apr 2017", "https://www.oracle.com/security-alerts/cpuapr2017.html"),
        ],
    },
    "spring_actuator_endpoints_exposed": {
        "name": "Spring Boot Actuator Endpoints Exposed",
        "description": "Spring Boot Actuator endpoints (such as /actuator, /env, /heapdump, /jolokia, /trace) are enabled and reachable without authentication. Several expose sensitive runtime data or allow interaction with the application.",
        "impact": "Endpoints like /env and /heapdump leak secrets (database credentials, session tokens, environment variables); /jolokia and /shutdown can lead to remote code execution or denial of service.",
        "recommendation": "Disable or restrict actuator endpoints in production. Expose only /health over the management port on a protected network, require authentication, and never expose /env, /heapdump, /jolokia, or /shutdown publicly.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
        "tags": ["spring", "information_disclosure", "rce", "CWE-200"],
        "references": [
            ("Spring Boot Actuator", "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"),
        ],
    },
    "spring_actuator_env_secrets": {
        "name": "Spring Boot Actuator /env Secrets Exposure",
        "description": "The Spring Boot Actuator /env (or /actuator/env) endpoint is reachable and returns the application's environment, including properties such as database URLs and credentials. Although Spring sanitizes some properties by default, many are not sanitized (e.g. *-url, *-host, custom keys) and the heapdump/jolokia endpoints reveal the rest.",
        "impact": "Disclosure of database credentials, API keys, and internal configuration, leading to further compromise.",
        "recommendation": "Disable the /env endpoint or require authentication. Mark sensitive properties for sanitization, and restrict the management port to a protected network.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "tags": ["spring", "information_disclosure", "CWE-200"],
        "references": [
            ("Spring Boot Actuator Endpoints", "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"),
        ],
    },
    "spring_jolokia_exposed": {
        "name": "Spring Boot Jolokia Endpoint Exposed",
        "description": "The Jolokia endpoint (exposed via Actuator or directly) is reachable without authentication. Jolokia is a JMX-HTTP bridge that allows invoking MBean operations, including those that load classes or execute commands (e.g. ch.qos.logback.classic.jmx.JMXConfigurator reloadByURL, which can fetch and parse an attacker-controlled XML).",
        "impact": "Remote code execution via JMX MBean operations or denial of service.",
        "recommendation": "Disable the jolokia actuator endpoint. Restrict the management port to a protected network and require authentication. Upgrade Spring Boot.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["spring", "rce", "CWE-502"],
        "references": [
            ("Jolokia", "https://jolokia.org/"),
        ],
    },
    "spring_known_cves": {
        "name": "Spring Framework Known CVE",
        "description": "The detected Spring Framework or Spring Boot version is affected by a known vulnerability (such as Spring4Shell / CVE-2022-22965 class-binding or SpEL injection) based on fingerprinting.",
        "impact": "Depends on the specific CVE; ranges from remote code execution to data binding bypass.",
        "recommendation": "Upgrade Spring Framework / Spring Boot to a fixed version and apply relevant mitigations. Track the Spring security advisories.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["spring", "rce", "CVE", "CWE-94"],
        "references": [
            ("Spring Security Advisories", "https://spring.io/security"),
        ],
    },
    "elasticsearch_exposed": {
        "name": "Elasticsearch Instance Exposed",
        "description": "An Elasticsearch node is reachable on its HTTP port (9200/9300) without authentication. The REST API exposes index contents, cluster state, and, on older versions, allows script execution through the search and update APIs.",
        "impact": "Unauthenticated read of all indexed data, and on versions prior to the script security changes, remote code execution via script injection. The cluster can also be damaged or wiped.",
        "recommendation": "Bind Elasticsearch to a private interface, enable security (XPack / RBAC, TLS), and never expose port 9200 to the internet. Place it behind a firewall or VPN.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["exposed_service", "elasticsearch", "CWE-306"],
        "references": [
            ("Elasticsearch Security", "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html"),
        ],
    },
    "phpmyadmin_exposed": {
        "name": "phpMyAdmin Exposed",
        "description": "A phpMyAdmin installation is reachable on the public interface. It is the web management UI for MySQL/MariaDB and is protected only by its own login.",
        "impact": "Exposing phpMyAdmin invites brute force and exploitation of phpMyAdmin CVEs; a successful login gives full database access. Many installs also leak version and server details.",
        "recommendation": "Do not expose phpMyAdmin publicly. Restrict to a protected network or VPN, require strong credentials, and keep it patched.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "tags": ["exposed_service", "phpmyadmin", "CWE-306"],
        "references": [],
    },
    "solr_exposed": {
        "name": "Apache Solr Exposed",
        "description": "An Apache Solr instance is reachable without authentication. Solr exposes its admin REST API, which on many versions allows reading arbitrary files, modifying cores, and in some versions running Velocity templates that lead to RCE.",
        "impact": "Information disclosure and, on vulnerable versions, remote code execution via Velocity response writers or the configupload/Cloud features.",
        "recommendation": "Do not expose Solr to untrusted networks. Enable Solr's authentication and authorization, keep patched, and run behind a firewall.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["exposed_service", "solr", "rce", "CWE-306"],
        "references": [
            ("Solr Security", "https://solr.apache.org/guide/solr/latest/configuration-guide/security.html"),
        ],
    },
    "api_key_exposure": {
        "name": "API Key / Secret Token Exposure",
        "description": "An API key, secret token, or credential appears in a response body, URL parameter, or client-reachable resource. Keys may be cloud provider keys, third-party API keys, or internal access tokens.",
        "impact": "A leaked key grants the holder whatever permissions the key carries — often read or write access to cloud storage, databases, payment providers, or the application's own APIs. Cloud keys are routinely automated for cryptomining or data exfiltration within minutes.",
        "recommendation": "Remove the key from any client-visible surface. Rotate the exposed key immediately, restrict it by IP or scope, and store secrets server-side in a secrets manager rather than in client code or responses.",
        "severity": 3,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "tags": ["sensitive_data", "CWE-200", "CWE-312"],
        "references": [
            ("CWE-200: Information Exposure", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },
    "sensitive_info_china_id_card": {
        "name": "Chinese Resident ID Card Number Disclosed",
        "description": "A response body contains what matches the format of a Chinese resident identity card number (18 digits, valid region/date/checksum).",
        "impact": "Disclosure of resident ID numbers is a privacy breach subject to China's Personal Information Protection Law (PIPL) and may enable identity fraud.",
        "recommendation": "Remove the ID numbers from the response. Avoid storing or transmitting resident IDs in plaintext; mask or tokenize them and restrict access.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "tags": ["sensitive_data", "PII", "CWE-200"],
        "references": [
            ("PIPL", "http://www.npc.gov.cn/englishnpc/c23934/202112/1abd8829788946ecab270e469b13c39c.shtml"),
        ],
    },
    "sensitive_info_china_bank_card": {
        "name": "Chinese Bank Card Number Disclosed",
        "description": "A response body contains what matches the format of a Chinese bank card number (16-19 digits with a valid Luhn checksum).",
        "impact": "Disclosure of bank card numbers is a financial-data privacy breach and may enable fraud.",
        "recommendation": "Remove the card numbers from the response. Tokenize or mask PAN data and comply with PCI-DSS handling requirements.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "tags": ["sensitive_data", "PCI", "CWE-200"],
        "references": [],
    },
    "sensitive_info_china_phone": {
        "name": "Chinese Mobile Phone Number Disclosed",
        "description": "A response body contains what matches the format of a Chinese mobile phone number (11 digits starting with the 1x pattern of a carrier).",
        "impact": "Disclosure of mobile numbers is a privacy breach under PIPL and enables spam, SIM-swap, and social-engineering attacks.",
        "recommendation": "Remove phone numbers from the response. Mask or tokenize PII and restrict access to it.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["sensitive_data", "PII", "CWE-200"],
        "references": [],
    },
    "sensitive_info_china_address": {
        "name": "Chinese Address / Location Disclosed",
        "description": "A response body contains detailed address or location information (Chinese province/city/district and street-level address patterns).",
        "impact": "Disclosure of detailed addresses is a privacy breach under PIPL and may enable physical attacks or doxxing.",
        "recommendation": "Remove detailed address fields from responses shown to untrusted users. Store only what is needed and mask sensitive portions.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["sensitive_data", "PII", "CWE-200"],
        "references": [],
    },
    "autocomplete_enabled": {
        "name": "Form Autocomplete Enabled on Sensitive Field",
        "description": "A form containing a password, credit card, or other sensitive input has the autocomplete attribute enabled (or unset, the default), allowing the browser to cache and suggest the value on this and other sites.",
        "impact": "Sensitive values may be stored by the browser and leaked to other users of the device or to malware with browser data access.",
        "recommendation": "Set autocomplete=\"off\" (or a more specific off token like new-password / cc-number) on sensitive input fields.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "tags": ["configuration", "CWE-522"],
        "references": [
            ("CWE-522: Insufficiently Protected Credentials", "https://cwe.mitre.org/data/definitions/522.html"),
        ],
    },
    "crossdomain_policy": {
        "name": "Overly Permissive crossdomain.xml Policy",
        "description": "A crossdomain.xml policy file is served that grants Flash/ Silverlight plug-ins from arbitrary domains (allow-access-from domain=\"*\") the ability to read data from this origin, bypassing the same-origin policy.",
        "impact": "Although Flash is largely deprecated, an overly broad crossdomain.xml remains a legacy information-disclosure vector and signals poor security hygiene.",
        "recommendation": "Remove crossdomain.xml if Flash/Silverlight clients are not required. Otherwise restrict allow-access-from to specific trusted domains.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "tags": ["configuration", "CWE-942"],
        "references": [
            ("CWE-942: Permissive Cross-domain Policy", "https://cwe.mitre.org/data/definitions/942.html"),
        ],
    },
    "content_type_missing": {
        "name": "Missing Content-Type Header",
        "description": "An HTTP response is missing a Content-Type header, leaving the browser to sniff the content type. This can cause responses to be interpreted as HTML even when not intended.",
        "impact": "Combined with content sniffing this widens the window for XSS and content-confusion attacks.",
        "recommendation": "Always send an explicit, correct Content-Type header, and send X-Content-Type-Options: nosniff.",
        "severity": 0,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "tags": ["configuration", "CWE-434"],
        "references": [],
    },
    "jsonp_hijacking": {
        "name": "JSONP Endpoint / JSON Hijacking",
        "description": "A JSONP callback endpoint (or a JSON endpoint without an explicit JSON content type that older browsers would treat as script) returns sensitive data. A malicious page can include it via a <script> tag and read the data through the callback.",
        "impact": "Cross-site read of sensitive JSON/JSONP data, bypassing the same-origin policy for any user who is logged in to the vulnerable site.",
        "recommendation": "Avoid JSONP; return plain JSON with Content-Type: application/json and CSRF protection. If JSONP is unavoidable, validate the callback name and require an anti-CSRF token. Set X-Content-Type-Options: nosniff.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "tags": ["jsonp", "CWE-79", "CWE-352"],
        "references": [
            ("JSON Hijacking", "https://haacked.com/archive/2009/06/25/json-hijacking.aspx/"),
        ],
    },
    "thinkphp_rce": {
        "name": "ThinkPHP Remote Code Execution",
        "description": "The ThinkPHP framework version in use is vulnerable to remote code execution through the well-known RCE chains: the invokeFunction / Method arbitrary class invocation chain (5.x), the method filter chain, and the preg_replace e-modifier chain. The framework routes user-controlled input into ReflectionClass / call_user_func paths without sanitization.",
        "impact": "Unauthenticated remote code execution with web-server privileges. These ThinkPHP RCE chains are heavily weaponized in the wild.",
        "recommendation": "Upgrade ThinkPHP to the latest patched version. Apply the official RCE patches, restrict access to the framework entrypoints, and run a WAF rule set that blocks the known payloads.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["thinkphp", "rce", "CWE-94"],
        "references": [
            ("ThinkPHP RCE analysis", "https://blog.thinkphp.cn/869075"),
        ],
    },
    "thinkphp_v6_file_write": {
        "name": "ThinkPHP v6 Arbitrary File Write",
        "description": "ThinkPHP 6 allows an unauthenticated attacker to write arbitrary files (including PHP code) via abuse of the session handler / file-based session storage with a controlled session filename, leading to remote code execution.",
        "impact": "Unauthenticated remote code execution through writing a PHP file into a web-accessible path.",
        "recommendation": "Upgrade ThinkPHP 6 to a fixed version. Do not store sessions in a web-accessible path, and configure the session handler securely.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["thinkphp", "rce", "CWE-434"],
        "references": [],
    },
    "cookiekey_weak_key": {
        "name": "Cookie / Session Secret Weak Key",
        "description": "A signed cookie or session token (Django, Flask, Express, JWT, Rack, Laravel, Beaker, Bottle, Pyramid, Tornado, web2py, Yii2) is signed or encrypted using a weak, default, or well-known secret key. The plugin brute-forced the signing key against a dictionary of common keys and matched.",
        "impact": "Once the signing key is known, an attacker can forge session cookies, escalate privileges, or — for frameworks that serialize objects in the cookie (e.g. Flask Pickle, Beaker, Django signed-cookie sessions) — achieve remote code execution by submitting a crafted, signed payload.",
        "recommendation": "Generate a long, random, unique secret key per deployment and store it in a secrets manager / environment. Never ship default keys (e.g. 'secret', 'changeme', the framework example). Rotate the key if it may have leaked. Prefer server-side session storage over signed cookies where possible.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["weak_crypto", "session", "CWE-321", "CWE-798"],
        "references": [
            ("CWE-321: Use of Hard-coded Cryptographic Key", "https://cwe.mitre.org/data/definitions/321.html"),
            ("CWE-798: Use of Hard-coded Credentials", "https://cwe.mitre.org/data/definitions/798.html"),
        ],
    },
    "csp_misconfiguration": {
        "name": "Content Security Policy Misconfigured",
        "description": "A Content-Security-Policy header is present but malformed, contradictory, or missing required directives (e.g. both report-only and enforced, a meta policy with disallowed directives, or a policy that fails to restrict script sources). Browsers fall back to permissive behavior.",
        "impact": "A broken CSP gives no protection and may create a false sense of security. XSS and injection defenses that depend on CSP are not enforced.",
        "recommendation": "Validate the CSP with a parser, ship a single enforced policy with explicit script-src/style-src directives, and use report-uri to collect violations before switching report-only off.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "tags": ["csp", "configuration", "CWE-1021"],
        "references": [
            ("Content Security Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"),
        ],
    },
    "csp_unsafe_inline_script": {
        "name": "CSP Allows Unsafe Inline Script",
        "description": "The Content-Security-Policy script-src directive permits 'unsafe-inline', allowing inline <script> elements and event handlers. This neutralizes CSP's primary XSS mitigation.",
        "impact": "An attacker who can inject HTML can inject inline scripts that execute, defeating the XSS protection CSP is meant to provide.",
        "recommendation": "Remove 'unsafe-inline' from script-src. Use nonces or hashes for legitimate inline scripts, and move inline scripts to external files.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "tags": ["csp", "xss", "CWE-79"],
        "references": [
            ("CWE-79", "https://cwe.mitre.org/data/definitions/79.html"),
        ],
    },
    "csp_unsafe_inline_style": {
        "name": "CSP Allows Unsafe Inline Style",
        "description": "The Content-Security-Policy style-src directive permits 'unsafe-inline', allowing inline style attributes and <style> elements. This weakens CSP and can enable some CSS-based data exfiltration.",
        "impact": "Lower than unsafe-inline script, but still weakens CSP and can enable CSS-based data exfiltration attacks.",
        "recommendation": "Remove 'unsafe-inline' from style-src where feasible; use nonces or hashes for inline styles.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "tags": ["csp", "CWE-79"],
        "references": [],
    },
    "csp_unsafe_eval": {
        "name": "CSP Allows unsafe-eval",
        "description": "The Content-Security-Policy script-src directive permits 'unsafe-eval', allowing eval(), Function(), and setTimeout(string). Many template and compilation libraries require it, but it widens the XSS attack surface.",
        "impact": "If an attacker can inject script, unsafe-eval makes it easier to execute dynamic payloads and bypass some CSP-based controls.",
        "recommendation": "Remove 'unsafe-eval' from script-src. Refactor code that depends on eval / new Function to avoid dynamic code generation.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "tags": ["csp", "CWE-95"],
        "references": [],
    },
    "csp_unsafe_hashes": {
        "name": "CSP Uses unsafe-hashes",
        "description": "The Content-Security-Policy uses 'unsafe-hashes' to allow specific inline event handlers by hash. While more constrained than unsafe-inline, it still permits inline handlers and weakens CSP.",
        "impact": "Inline event handlers are permitted, which keeps a path open for HTML-injection-based XSS even if script injection is blocked.",
        "recommendation": "Move event handlers into external scripts and remove 'unsafe-hashes'.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "tags": ["csp", "CWE-79"],
        "references": [],
    },
    "csp_wildcard": {
        "name": "CSP Contains Wildcard Source",
        "description": "The Content-Security-Policy uses a wildcard source (e.g. script-src * or *.com), allowing scripts or styles from any origin or any subdomain of a public suffix.",
        "impact": "An attacker who controls any matching origin (or any subdomain of the wildcarded domain) can inject executable content, defeating CSP.",
        "recommendation": "Replace wildcards with an explicit allowlist of trusted origins. Avoid * and broad *.com patterns.",
        "severity": 2,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "tags": ["csp", "CWE-79"],
        "references": [],
    },
    "csp_legacy_header": {
        "name": "Legacy CSP Header (X-Content-Security-Policy / X-WebKit-CSP)",
        "description": "Only the legacy X-Content-Security-Policy or X-WebKit-CSP header is present, without the standard Content-Security-Policy header. Modern browsers ignore the legacy headers.",
        "impact": "Modern browsers do not enforce the policy, so the CSP provides no protection for current users.",
        "recommendation": "Set the standard Content-Security-Policy header. The legacy headers may be kept for very old browsers but must not be the only policy.",
        "severity": 1,
        "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "tags": ["csp", "configuration", "CWE-1021"],
        "references": [
            ("CSP on MDN", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"),
        ],
    },
}

# ---- XStream per-CVE hand-written entries ----
XSTREAM = {
    "xstream_cve_2020_26217": ("XStream Deserialization RCE (CVE-2020-26217)", "CVE-2020-26217",
        "XStream before 1.4.14 can deserialize arbitrary crafted input, allowing remote code execution via a manipulated serialized stream. The default setup allowed the instantiation of arbitrary types through crafted XML."),
    "xstream_cve_2020_26258": ("XStream SSRF / RCE (CVE-2020-26258)", "CVE-2020-26258",
        "XStream before 1.4.14 allows Server-Side Request Forgery via a crafted serialized input, and in some configurations can be chained to remote code execution."),
    "xstream_cve_2020_26259": ("XStream DoS (CVE-2020-26259)", "CVE-2020-26259",
        "XStream before 1.4.14 allows a denial-of-service attack via a crafted serialized input that causes high CPU or memory consumption during parsing."),
    "xstream_cve_2021_21345": ("XStream RCE (CVE-2021-21345)", "CVE-2021-21345",
        "XStream before 1.4.16 allows remote code execution via crafted serialized input. The default security framework was not enabled."),
    "xstream_cve_2021_21351": ("XStream RCE (CVE-2021-21351)", "CVE-2021-21351",
        "XStream before 1.4.16 allows remote code execution via a crafted serialized input due to insufficient validation of the instantiated types."),
    "xstream_cve_2021_39144": ("XStream RCE (CVE-2021-39144)", "CVE-2021-39144",
        "XStream before 1.4.18 allows remote code execution via a crafted serialized input. Multiple previously-allowed type chains remained exploitable before the security framework defaults were tightened."),
    "xstream_cve_2021_39152": ("XStream SSRF (CVE-2021-39152)", "CVE-2021-39152",
        "XStream before 1.4.18 allows Server-Side Request Forgery via a crafted serialized input when the security framework is not enabled."),
    "xstream_cve_2013_7285": ("XStream RCE (CVE-2013-7285)", "CVE-2013-7285",
        "XStream 1.4.x before 1.4.7 allows remote code execution via a crafted serialized Java object (the EventHandler chain), as exploited in the wild."),
}
for stem, (name, cve, desc) in XSTREAM.items():
    HANDWRITTEN[stem] = {
        "name": name,
        "description": desc,
        "impact": "Remote code execution or server-side request forgery with the privileges of the process deserializing the XStream payload. XStream deserialization flaws are routinely weaponized for full server compromise.",
        "recommendation": "Upgrade XStream to a fixed version (>= 1.4.18) and enable the security framework with a strict allowlist of permitted types (XStream.setupDefaultSecurity / addPermission). Never deserialize untrusted input; validate before deserialization.",
        "severity": 4,
        "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": ["xstream", "deserialization", "rce", cve, "CWE-502"],
        "references": [
            (cve, "https://nvd.nist.gov/vuln/detail/" + cve),
            ("XStream Security", "https://x-stream.github.io/security.html"),
        ],
    }


def main():
    with open(SRC, "r", encoding="utf-8") as f:
        data = json.load(f)
    apps = data.get("byAppId", {})
    if not apps:
        print("no byAppId entries found", file=sys.stderr)
        sys.exit(1)

    allow = load_allowlist()

    os.makedirs(DST, exist_ok=True)
    for name in os.listdir(DST):
        if name.endswith(".xml"):
            os.remove(os.path.join(DST, name))

    count = 0
    # 1) json-sourced entries (direct key match or via JSON_REMAP)
    for key, v in apps.items():
        stem_id = stem(key)
        # determine target id: if remap targets this stem, use the remap target;
        # otherwise the entry is emitted only if its own stem is allowlisted.
        # Simpler: iterate allowlist and emit from json where the source exists.
        pass
    emitted = set()
    for target in sorted(allow):
        src_key = None
        if target in JSON_REMAP:
            src_key = JSON_REMAP[target]
        elif (target + ".xml") in apps:
            src_key = target + ".xml"
        elif target in HANDWRITTEN:
            write_handwritten(target, HANDWRITTEN[target])
            emitted.add(target)
            count += 1
            continue
        if src_key and src_key in apps:
            v = apps[src_key]
            write_json_entry(target, v)
            emitted.add(target)
            count += 1
            continue
        # not found anywhere
        print("WARN: no source for allowlisted id %r" % target, file=sys.stderr)

    # report any allowlisted ids that produced nothing
    missing = set(allow) - emitted
    if missing:
        print("MISSING (no source):", sorted(missing), file=sys.stderr)

    print("wrote %d vuln xml files to %s" % (count, DST))


def write_json_entry(target, v):
    path = os.path.join(DST, target + ".xml")
    with open(path, "w", encoding="utf-8") as out:
        out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        out.write('<vuln id="%s">\n' % escape(target))
        write_str(out, "name", v.get("name", ""))
        write_str(out, "description", v.get("description", ""))
        write_str(out, "impact", v.get("impact", ""))
        write_str(out, "recommendation", v.get("recommendation", ""))
        write_int(out, "severity", v.get("severity"))
        write_num(out, "score", v.get("score"))
        write_str(out, "cvss2", v.get("cvss2", ""))
        write_str(out, "cvss3", v.get("cvss3", ""))
        write_str(out, "cvss4", v.get("cvss4", ""))
        write_str(out, "details_template", v.get("details_template", ""))
        write_tags(out, v.get("tags") or [])
        write_refs(out, v.get("references") or [])
        out.write("</vuln>\n")


def write_handwritten(target, v):
    path = os.path.join(DST, target + ".xml")
    with open(path, "w", encoding="utf-8") as out:
        out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        out.write('<vuln id="%s">\n' % escape(target))
        write_str(out, "name", v.get("name", ""))
        write_str(out, "description", v.get("description", ""))
        write_str(out, "impact", v.get("impact", ""))
        write_str(out, "recommendation", v.get("recommendation", ""))
        write_int(out, "severity", v.get("severity"))
        if "score" in v:
            write_num(out, "score", v["score"])
        write_str(out, "cvss2", v.get("cvss2", ""))
        write_str(out, "cvss3", v.get("cvss3", ""))
        write_str(out, "cvss4", v.get("cvss4", ""))
        write_str(out, "details_template", v.get("details_template", ""))
        write_tags(out, v.get("tags") or [])
        # references come as list of (title, url)
        refs = v.get("references") or []
        out.write("  <references>\n")
        for r in refs:
            if isinstance(r, tuple):
                title, url = r
                out.write("    <reference>\n")
                out.write("      <title>%s</title>\n" % escape(title))
                out.write("      <url>%s</url>\n" % escape(url))
                out.write("    </reference>\n")
            elif isinstance(r, str):
                out.write('    <reference>\n      <url>%s</url>\n    </reference>\n' % escape(r))
        out.write("  </references>\n")
        out.write("</vuln>\n")


def write_tags(out, tags):
    out.write("  <tags>\n")
    for tg in tags:
        out.write("    <tag>%s</tag>\n" % escape(str(tg)))
    out.write("  </tags>\n")


def write_refs(out, refs):
    out.write("  <references>\n")
    for r in refs:
        if isinstance(r, dict):
            title = r.get("title", "")
            url = r.get("url", "")
            out.write("    <reference>\n")
            out.write("      <title>%s</title>\n" % escape(title))
            out.write("      <url>%s</url>\n" % escape(url))
            out.write("    </reference>\n")
        elif isinstance(r, str):
            out.write('    <reference>\n      <url>%s</url>\n    </reference>\n' % escape(r))
    out.write("  </references>\n")


def stem(fname):
    return fname[:-4] if fname.endswith(".xml") else fname


def write_str(out, tag, val):
    if val is None:
        val = ""
    out.write("  <%s>%s</%s>\n" % (tag, escape(str(val)), tag))


def write_int(out, tag, val):
    if val is None:
        return
    out.write("  <%s>%d</%s>\n" % (tag, int(val), tag))


def write_num(out, tag, val):
    if val is None:
        return
    out.write("  <%s>%s</%s>\n" % (tag, escape(str(val)), tag))


def load_allowlist():
    allow = set()
    try:
        with open(ALLOWLIST, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    allow.add(line)
    except FileNotFoundError:
        return None
    return allow


if __name__ == "__main__":
    main()
