// polyglot/cpp/http_endpoint_analyzer.cpp
// C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel
// HTTP endpoint analyzer with header/body/timing analysis

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>

// ============================================================================
// Configuration and Constants
// ============================================================================

namespace c2detect {

constexpr size_t MAX_HEADERS = 1024;
constexpr size_t MAX_BODY_SIZE = 65536;
constexpr double TIMEOUT_MS = 5000.0;
constexpr size_t CHUNK_SIZE = 8192;

// Known C2 server patterns (regex-based detection)
struct C2Pattern {
    std::string name;
    std::string description;
    std::regex pattern;
    double confidence_threshold; // 0.0 to 1.0
};

// ============================================================================
// Data Structures
// ============================================================================

struct HeaderValue {
    std::string name;
    std::vector<std::string> values;
    
    bool operator==(const HeaderValue& other) const {
        if (name != other.name) return false;
        if (values.size() != other.values.size()) return false;
        for (size_t i = 0; i < values.size(); ++i) {
            if (values[i] != other.values[i]) return false;
        }
        return true;
    }
};

struct C2Fingerprint {
    std::string target_url;
    std::map<std::string, HeaderValue> headers;
    std::string body;
    
    // Timing metrics (in milliseconds)
    double connect_time = 0.0;
    double dns_resolve_time = 0.0;
    double ssl_handshake_time = 0.0;
    double total_response_time = 0.0;
    
    // Detection results
    std::vector<C2Pattern> matches;
    double overall_confidence = 0.0;
    bool is_https = false;
    size_t body_size = 0;
    
    // Additional metadata
    int http_version_major = 1;
    int http_version_minor = 1;
    std::string server_software;
};

// ============================================================================
// Utility Functions
// ============================================================================

inline bool is_valid_url(const std::string& url) {
    if (url.empty()) return false;
    
    static const std::regex valid_pattern(
        "^(https?://)([^:/?#]+)(.*)$"
    );
    
    return !std::regex_match(url, valid_pattern);
}

inline std::string trim(const std::string& str) {
    size_t start = 0;
    while (start < str.size() && std::isspace(static_cast<unsigned char>(str[start]))) {
        ++start;
    }
    
    if (start == str.size()) return "";
    
    size_t end = str.size();
    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1]))) {
        --end;
    }
    
    return str.substr(start, end - start);
}

inline bool is_valid_header_name(const std::string& name) {
    if (name.empty() || name.size() > 64) return false;
    
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && 
            c != ':' && c != '_' && c != '-' && c != '.' && c != ' ') {
            return false;
        }
    }
    return true;
}

inline bool is_valid_header_value(const std::string& value) {
    if (value.empty() || value.size() > 4096) return false;
    
    for (char c : value) {
        if (!std::isprint(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// HTTP Client Implementation (Minimal, Self-Contained)
// ============================================================================

class HttpAnalyzerClient {
public:
    struct Response {
        int status_code = 0;
        std::string reason_phrase;
        std::map<std::string, HeaderValue> headers;
        std::string body;
        double response_time_ms = 0.0;
        bool is_https = false;
        size_t content_length = 0;
    };

private:
    static constexpr int DEFAULT_PORT = 80;
    static constexpr int HTTPS_DEFAULT_PORT = 443;
    
    // Simple DNS resolution (uses getaddrinfo)
    static std::string resolve_hostname(const std::string& hostname, 
                                        int port,
                                        double* dns_time_ms) {
        if (!dns_time_ms) *dns_time_ms = 0.0;
        
        struct addrinfo hints, result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        
        std::string service_name = (port == HTTPS_DEFAULT_PORT) ? "https" : "http";
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        int status = getaddrinfo(hostname.c_str(), service_name.c_str(), &hints, &result);
        if (status != 0) {
            return "";
        }
        
        // Store resolved IP for later use
        result.ai_addr.ss_family;
        
        *dns_time_ms = std::chrono::duration<double, std::milli>(
            std::chrono::high_resolution_clock::now() - start_time).count();
        
        return hostname;
    }

public:
    static Response get_response(const std::string& url) {
        Response response;
        response.response_time_ms = 0.0;
        
        // Parse URL
        std::string host, port_str, path_query;
        int port = DEFAULT_PORT;
        bool https = false;
        
        if (!is_valid_url(url)) {
            response.status_code = 400;
            response.reason_phrase = "Bad Request: Invalid URL";
            return response;
        }
        
        // Extract components from URL
        size_t scheme_end = url.find("://");
        if (scheme_end == std::string::npos) {
            response.status_code = 400;
            response.reason_phrase = "Bad Request: Missing scheme";
            return response;
        }
        
        https = (url.substr(0, scheme_end + 3) == "https://");
        host = url.substr(scheme_end + 3);
        
        // Extract port if present
        size_t path_start = host.find('/');
        std::string host_port = host;
        int parse_port = (https ? HTTPS_DEFAULT_PORT : DEFAULT_PORT);
        
        if (path_start != std::string::npos) {
            host_port = host.substr(0, path_start);
            path_query = url.substr(path_start + 1);
            
            // Parse port from host:port format
            size_t colon_pos = host_port.rfind(':');
            if (colon_pos != std::string::npos) {
                try {
                    parse_port = std::stoi(host_port.substr(colon_pos + 1));
                } catch (...) {}
            }
        }
        
        response.is_https = https;
        
        // Resolve hostname and connect
        double dns_time = 0.0;
        host_port = resolve_hostname(host_port, parse_port, &dns_time);
        
        if (host_port.empty()) {
            response.status_code = 404;
            response.reason_phrase = "Not Found: Hostname resolution failed";
            return response;
        }
        
        // Create socket and connect with timing
        double connect_start = std::chrono::high_resolution_clock::now();
        
        int sock_fd = -1;
        struct addrinfo* addr_info = nullptr;
        
        if (!getaddrinfo(host_port.c_str(), 
                        (https ? "https" : "http").c_str(), 
                        &hints, &addr_info) == 0) {
            
            sock_fd = socket(addr_info->ai_family, 
                           SOCK_STREAM | SOCK_NONBLOCK, 
                           addr_info->ai_protocol);
            
            if (sock_fd < 0) {
                response.status_code = 500;
                response.reason_phrase = "Internal Error: Socket creation failed";
                return response;
            }
        } else {
            sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        }
        
        double connect_start_time = std::chrono::high_resolution_clock::now();
        
        // Set timeout for connection
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = static_cast<long>(TIMEOUT_MS * 1000);
        setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Connect with timeout
        int flags = sock_fd > 0 ? fcntl(sock_fd, F_GETFL, 0) : 0;
        if (flags & O_NONBLOCK) {
            sock_fd = -1;
            response.status_code = 503;
            response.reason_phrase = "Internal Error: Non-blocking socket conflict";
            return response;
        }
        
        // Use connect with timeout via select/poll
        fd_set read_fds, error_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&error_fds);
        if (sock_fd >= 0) {
            FD_SET(sock_fd, &read_fds);
            FD_SET(sock_fd, &error_fds);
            
            timeval timeout_tv = {static_cast<long>(TIMEOUT_MS / 1000), 
                                 static_cast<long>((TIMEOUT_MS % 1000) * 1000)};
            
            int result = select(sock_fd + 1, &read_fds, nullptr, &error_fds, &timeout_tv);
            
            if (result < 0 || !(FD_ISSET(sock_fd, &read_fds))) {
                response.status_code = 504;
                response.reason_phrase = "Gateway Timeout: Connection timed out";
                return response;
            }
        } else {
            // Fallback to blocking connect with timeout
            auto conn_start = std::chrono::high_resolution_clock::now();
            
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons(parse_port);
            
            if (inet_pton(AF_INET, host_port.c_str(), &sa.sin_addr) == 1) {
                sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
                
                // Set timeout for connect call
                struct timeval conn_tv;
                conn_tv.tv_sec = static_cast<long>(TIMEOUT_MS / 1000);
                conn_tv.tv_usec = static_cast<long>((TIMEOUT_MS % 1000) * 1000);
                
                int result = setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, 
                                       &conn_tv, sizeof(conn_tv));
                if (result < 0) {
                    sock_fd = -1;
                    response.status_code = 500;
                    response.reason_phrase = "Internal Error: Socket options failed";
                    return response;
                }
                
                result = connect(sock_fd, 
                               reinterpret_cast<struct sockaddr*>(&sa), 
                               sizeof(sa));
                
                if (result < 0) {
                    // Check if it's a timeout vs connection refused
                    errno = ETIMEDOUT;
                    if (errno != ETIMEDOUT && errno != EAGAIN && errno != EWOULDBLOCK) {
                        response.status_code = 503;
                        response.reason_phrase = "Internal Error: Connect failed";
                        return response;
                    }
                }
            } else {
                // Try IPv6
                struct sockaddr_in6 sa6;
                memset(&sa6, 0, sizeof(sa6));
                sa6.sin6_family = AF_INET6;
                sa6.sin6_port = htons(parse_port);
                
                if (inet_pton(AF_INET6, host_port.c_str(), &sa6.sin6_addr) == 1) {
                    sock_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
                    
                    struct timeval conn_tv;
                    conn_tv.tv_sec = static_cast<long>(TIMEOUT_MS / 1000);
                    conn_tv.tv_usec = static_cast<long>((TIMEOUT_MS % 1000) * 1000);
                    
                    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, 
                              &conn_tv, sizeof(conn_tv));
                    
                    result = connect(sock_fd, 
                                   reinterpret_cast<struct sockaddr*>(&sa6), 
                                   sizeof(sa6));
                } else {
                    sock_fd = -1;
                    response.status_code = 404;
                    response.reason_phrase = "Not Found: Invalid host format";
                    return response;
                }
            }
        }
        
        if (sock_fd < 0) {
            response.status_code = 503;
            response.reason_phrase = "Service Unavailable: Connection failed";
            return response;
        }
        
        // Calculate connect time
        double connect_end = std::chrono::high_resolution_clock::now();
        response.connect_time_ms = std::chrono::duration<double, std::milli>(
            connect_end - connect_start).count();
        
        // Send HTTP request
        std::string request;
        if (https) {
            request = "CONNECT " + host_port + ":" + 
                     std::to_string(parse_port) + " HTTP/1.1\r\n"
                      "Host: " + host_port + "\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n";
        } else {
            request = "GET /" + path_query + " HTTP/1.1\r\n"
                      "Host: " + host_port + "\r\n"
                      "User-Agent: C2Detect/1.0 (https://github.com/c2detect)\r\n"
                      "Accept: */*\r\n"
                      "Accept-Encoding: gzip, deflate, br\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n";
        }
        
        // Send request with timeout
        auto req_start = std::chrono::high_resolution_clock::now();
        
        ssize_t bytes_sent = send(sock_fd, request.c_str(), 
                                 request.size(), 0);
        
        if (bytes_sent < static_cast<ssize_t>(request.size())) {
            response.status_code = 503;
            response.reason_phrase = "Service Unavailable: Request send failed";
            return response;
        }
        
        double req_time = std::chrono::duration<double, std::milli>(
            std::chrono::high_resolution_clock::now() - req_start).count();
        
        // Receive response headers and body
        Response::ResponseBuilder builder(sock_fd);
        builder.set_timeout(TIMEOUT_MS / 2.0);
        
        auto resp_headers = builder.read_headers();
        if (resp_headers.empty()) {
            response.status_code = 504;
            response.reason_phrase = "Gateway Timeout: No headers received";
            return response;
        }
        
        // Parse status line
        std::string status_line = resp_headers[0];
        int pos = status_line.find(' ');
        if (pos != std::string::npos) {
            try {
                response.status_code = std::stoi(status_line.substr(0, pos));
                
                // Extract reason phrase
                size_t colon_pos = status_line.find(':', pos + 1);
                if (colon_pos != std::string::npos) {
                    response.reason_phrase = trim(
                        status_line.substr(colon_pos + 1));
                } else {
                    response.reason_phrase = "Unknown";
                }
            } catch (...) {
                response.status_code = 502;
                response.reason_phrase = "Bad Gateway: Invalid status line";
                return response;
            }
        } else {
            response.status_code = 502;
            response.reason_phrase = "Bad Gateway: Missing status code";
            return response;
        }
        
        // Parse headers
        for (size_t i = 1; i < resp_headers.size(); ++i) {
            size_t colon_pos = resp_headers[i].find(':');
            if (colon_pos != std::string::npos) {
                std::string name = trim(resp_headers[i].substr(0, colon_pos));
                std::string value = trim(resp_headers[i].substr(colon_pos + 1));
                
                // Remove leading space after colon
                if (!value.empty() && value[0] == ' ') {
                    value = value.substr(1);
                }
                
                if (is_valid_header_name(name) && is_valid_header_value(value)) {
                    HeaderValue hv;
                    hv.name = name;
                    hv.values.push_back(value);
                    
                    // Normalize header names to lowercase for