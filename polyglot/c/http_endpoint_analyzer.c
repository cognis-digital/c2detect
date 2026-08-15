#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_HEADERS 100
#define MAX_LINE_LEN 4096
#define MAX_RESPONSE_SIZE 65536

/* C2 Framework signatures */
typedef struct {
    const char *name;
    int priority;
} c2_signature_t;

static c2_signature_t g_signatures[] = {
    /* Cobalt Strike / Beacon */
    {"cobaltstrike", 10},
    {"beacon", 10},
    {"beacon-protocol", 9},
    
    /* Sliver */
    {"sliver", 8},
    {"sliver-client", 8},
    {"sliver-c2", 7},
    
    /* Mythic */
    {"mythic", 8},
    {"mythic-c2", 7},
    {"mythic-agent", 6},
    
    /* Havoc */
    {"havoc", 8},
    {"havoc-client", 7},
    {"havoc-protocol", 6},
    
    /* Brute Ratel */
    {"bruteratel", 7},
    {"ratel-c2", 6},
    {"ratel-agent", 5},
    
    {NULL, 0}
};

/* Response header info */
typedef struct {
    char line[MAX_LINE_LEN];
    bool is_header;
    bool is_body_start;
} http_line_t;

typedef struct {
    http_line_t lines[MAX_HEADERS + 1];
    int count;
    char body[MAX_RESPONSE_SIZE];
    size_t body_len;
    int status_code;
    char status_text[256];
} http_response_t;

/* Parse HTTP response into structured format */
static bool parse_http_response(const char *raw, http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));
    
    const char *p = raw;
    int line_num = 0;
    
    /* Skip empty lines at start */
    while (*p == '\n' || *p == '\r') p++;
    
    /* Parse status line */
    if (sscanf(p, "%d %255s", &resp->status_code, resp->status_text) < 1) {
        return false;
    }
    
    /* Find header/body boundary */
    const char *body_start = strstr(raw, "\r\n\r\n");
    if (!body_start) body_start = strstr(raw, "\n\n");
    
    if (body_start) {
        resp->body_len = strlen(body_start + 4);
        memcpy(resp->body, body_start + 4, resp->body_len);
        
        /* Parse headers */
        const char *hptr = raw;
        while (*hptr && line_num < MAX_HEADERS) {
            if (sscanf(hptr, "%256[^:\r\n]", resp->lines[line_num].line) > 0) {
                resp->lines[line_num].is_header = true;
                line_num++;
            } else if (*hptr == '\n' || *hptr == '\r') {
                hptr++;
            } else {
                break;
            }
            
            /* Check for body start */
            if (strchr(hptr, '\r')) {
                const char *cr = strchr(hptr, '\r');
                if (*cr) {
                    size_t remaining = strlen(cr + 1);
                    resp->body_len = remaining;
                    memcpy(resp->body, cr + 1, remaining);
                    break;
                }
            }
            
            hptr += strcspn(hptr, "\r\n");
        }
    } else {
        /* No body found */
        resp->body_len = 0;
    }
    
    resp->count = line_num;
    return true;
}

/* Check if header matches a pattern (case-insensitive) */
static bool match_header_pattern(const char *header, const char *pattern) {
    size_t plen = strlen(pattern);
    for (size_t i = 0; i < plen && header[i]; i++) {
        if (tolower((unsigned char)header[i]) != tolower((unsigned char)pattern[i])) {
            return false;
        }
    }
    return true;
}

/* Extract header value */
static const char *get_header_value(const http_line_t *line, const char *name) {
    if (!line->is_header || !line->line[0]) return NULL;
    
    size_t nlen = strlen(name);
    for (size_t i = 0; i < nlen && line->line[i]; i++) {
        if (tolower((unsigned char)line->line[i]) != tolower((unsigned char)name[i])) {
            return NULL;
        }
    }
    
    /* Check for colon separator */
    const char *colon = strchr(line->line + nlen, ':');
    if (!colon) return NULL;
    
    /* Skip whitespace after colon */
    size_t start = (size_t)(colon - line->line) + 1;
    while (start < strlen(line->line) && isspace((unsigned char)line->line[start])) {
        start++;
    }
    
    if (start >= strlen(line->line)) return NULL;
    
    /* Find end of value */
    size_t end = strcspn(line->line + start, "\r\n");
    return line->line + start;
}

/* Detect C2 framework from headers */
static int detect_c2_from_headers(const http_response_t *resp) {
    int found_priority = 0;
    
    for (int i = 0; resp->lines[i].is_header && i < MAX_HEADERS; i++) {
        const char *hval = get_header_value(&resp->lines[i], "X-Cobalt-Beacon");
        if (hval) found_priority = 10;
        
        hval = get_header_value(&resp->lines[i], "X-Sliver-Client");
        if (hval) found_priority = 8;
        
        hval = get_header_value(&resp->lines[i], "X-Mythic-C2");
        if (hval) found_priority = 8;
        
        hval = get_header_value(&resp->lines[i], "X-Havoc-Protocol");
        if (hval) found_priority = 8;
    }
    
    /* Check Content-Type for hints */
    const char *ct = get_header_value(&resp->lines[0], "Content-Type");
    if (ct) {
        if (strstr(ct, "beacon") || strstr(ct, "cobalt")) found_priority = 10;
        else if (strstr(ct, "sliver")) found_priority = 8;
        else if (strstr(ct, "mythic")) found_priority = 7;
    }
    
    /* Check User-Agent */
    const char *ua = get_header_value(&resp->lines[0], "User-Agent");
    if (ua) {
        if (strstr(ua, "beacon") || strstr(ua, "cobalt")) found_priority = 10;
        else if (strstr(ua, "sliver")) found_priority = 8;
        else if (strstr(ua, "mythic")) found_priority = 7;
    }
    
    return found_priority;
}

/* Detect C2 from response body */
static int detect_c2_from_body(const http_response_t *resp) {
    int found_priority = 0;
    
    if (resp->body_len == 0) return 0;
    
    const char *body = resp->body;
    size_t len = resp->body_len;
    
    /* Look for beacon protocol strings */
    static const char *beacon_patterns[] = {
        "beacon-protocol",
        "cobaltstrike",
        "sliver-client",
        "mythic-c2",
        "havoc-agent",
        "ratel-c2",
        NULL
    };
    
    for (int i = 0; beacon_patterns[i]; i++) {
        const char *pat = beacon_patterns[i];
        size_t plen = strlen(pat);
        
        if (len >= plen) {
            /* Case-insensitive search */
            for (size_t j = 0; j <= len - plen; j++) {
                bool match = true;
                for (size_t k = 0; k < plen && match; k++) {
                    if (tolower((unsigned char)body[j + k]) != tolower((unsigned char)pat[k])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    found_priority = 10 - i; /* Higher priority for earlier matches */
                    break;
                }
            }
        }
    }
    
    return found_priority;
}

/* Main detection function */
int c2_detect(const char *response, size_t len, int *priority) {
    http_response_t resp;
    
    if (!parse_http_response(response, &resp)) {
        *priority = 0;
        return -1;
    }
    
    /* Check headers first */
    int header_priority = detect_c2_from_headers(&resp);
    
    /* If not found in headers, check body */
    if (header_priority == 0) {
        header_priority = detect_c2_from_body(&resp);
    }
    
    *priority = header_priority;
    return 0;
}

/* Print detection results */
void print_detection(int priority) {
    const char *result;
    
    switch (priority) {
        case 10: result = "HIGH CONFIDENCE - Cobalt Strike / Beacon"; break;
        case 9: result = "HIGH CONFIDENCE - Cobalt Strike variant"; break;
        case 8: result = "HIGH CONFIDENCE - Sliver / Mythic / Havoc"; break;
        case 7: result = "MEDIUM CONFIDENCE - Possible C2 framework"; break;
        case 6: result = "LOW CONFIDENCE - Weak signal detected"; break;
        case 5: result = "LOW CONFIDENCE - Minor indicator found"; break;
        default: result = priority > 0 ? "SUSPECTED - Unknown C2 variant" : "NO MATCH - Clean or unknown response"; break;
    }
    
    printf("%s\n", result);
}

/* Test harness with sample responses */
static const char *TEST_RESPONSES[] = {
    /* Cobalt Strike beacon response */
    "HTTP/1.1 200 OK\r\n"
    "X-Cobalt-Beacon: v4.25\r\n"
    "Content-Type: application/octet-stream\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    "\r\n"
    "beacon-protocol-v4",
    
    /* Sliver client response */
    "HTTP/1.1 200 OK\r\n"
    "X-Sliver-Client: v3.1.0\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    "{\"status\":\"ok\"}",
    
    /* Mythic agent response */
    "HTTP/1.1 200 OK\r\n"
    "X-Mythic-C2: v2.8\r\n"
    "Content-Type: application/octet-stream\r\n"
    "\r\n"
    "mythic-c2-payload",
    
    /* Havoc protocol response */
    "HTTP/1.1 200 OK\r\n"
    "X-Havoc-Protocol: v1.5\r\n"
    "Content-Type: application/x-havoc\r\n"
    "\r\n"
    "havoc-agent-data",
    
    /* Brute Ratel response */
    "HTTP/1.1 200 OK\r\n"
    "X-Ratel-C2: v2.1\r\n"
    "Content-Type: application/octet-stream\r\n"
    "\r\n"
    "ratel-c2-payload",
    
    /* Clean response */
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Server: Apache/2.4.51\r\n"
    "\r\n"
    "<html><body>Hello</body></html>",
    
    /* Empty response */
    "",
};

int main(void) {
    printf("=== C2 Endpoint Analyzer Demo ===\n\n");
    
    int results[7];
    
    for (int i = 0; TEST_RESPONSES[i] != NULL && i < 7; i++) {
        const char *test = TEST_RESPONSES[i];
        
        if (*test == '\0') {
            printf("Test %d: Empty response\n", i + 1);
            c2_detect(test, 0, &results[i]);
        } else {
            printf("Test %d:\n", i + 1);
            size_t len = strlen(test);
            c2_detect(test, len, &results[i]);
        }
        
        print_detection(results[i]);
        printf("\n");
    }
    
    return 0;
}