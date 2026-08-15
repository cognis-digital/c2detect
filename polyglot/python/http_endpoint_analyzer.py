import socket
import ssl
import re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime


class C2Fingerprint:
    """Core fingerprinting engine for C2 servers."""
    
    # Known header patterns and their likelihood scores
    HEADER_SIGNATURES = {
        'cobalt_strike': [
            r'X-Cobalt-Strike',
            r'Server: Cobalt',
            r'X-Forwarded-For:\s*\d+\.\d+\.\d+\.\d+',  # Often has multiple hops
        ],
        'sliver': [
            r'Sliver',
            r'x-sliver',
            r'Server: Sliver',
        ],
        'mythic': [
            r'Mythic',
            r'X-Mythic',
            r'mythic\.io',
        ],
        'havoc': [
            r'Havoc',
            r'x-havoc',
            r'havoc\.net',
        ],
        'brute_ratel': [
            r'BruteRatel',
            r'x-bruteratel',
            r'ratel\.io',
        ],
    }

    # Body content signatures (partial responses)
    BODY_SIGNATURES = {
        'cobalt_strike': [
            b'cobaltstrike',
            b'Cobalt Strike Beacon',
            b'storm/beacon',
        ],
        'sliver': [
            b'sliver',
            b'Sliver C2',
            b'sliver\.io',
        ],
        'mythic': [
            b'mythic',
            b'Mythic C2',
            b'mythic\.io/api',
        ],
        'havoc': [
            b'havoc',
            b'Havoc C2',
            b'havoc\.net',
        ],
        'brute_ratel': [
            b'BruteRatel',
            b'ratel\.io',
        ],
    }

    # TLS fingerprint hints (simplified)
    TLS_HINTS = {
        'cobalt_strike': {'cipher_suites': ['TLS_AES_256_GCM_SHA384'], 'version': '1.2'},
        'sliver': {'cipher_suites': ['ECDHE-RSA-AES256-GCM-SHA384'], 'version': '1.2'},
    }


class HTTPEndpointAnalyzer:
    """Complete HTTP endpoint analyzer for C2 server fingerprinting."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.results_cache: Dict[str, Any] = {}
    
    def _create_connection(
        self, 
        host: str, 
        port: int, 
        use_ssl: bool = False,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[socket.socket, ssl.SSLContext | None]:
        """Establish connection with proper SSL handling."""
        if use_ssl and port in (443, 8443):
            context = ssl.create_default_context()
            try:
                context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
            except FileNotFoundError:
                pass
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Wrap with SSL
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            return ssl_sock, context
        
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            return sock, None
    
    def _extract_headers(self, raw_response: bytes) -> Dict[str, str]:
        """Parse HTTP headers from raw response."""
        try:
            text = raw_response.decode('utf-8', errors='ignore')
            lines = text.split('\r\n\r\n')[0].split('\r\n')
            
            headers = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return headers
        except Exception:
            return {}

    def _extract_body_sample(self, raw_response: bytes, max_size: int = 4096) -> str:
        """Get a safe sample of response body for pattern matching."""
        try:
            text = raw_response.decode('utf-8', errors='ignore')[:max_size]
            return text.lower()
        except Exception:
            return ''

    def _match_header_signatures(
        self, 
        headers: Dict[str, str],
        sample_body: str
    ) -> Tuple[bool, list]:
        """Check headers against known C2 signatures."""
        matches = []
        
        for c2_type, patterns in C2Fingerprint.HEADER_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, sample_body, re.IGNORECASE):
                    matches.append(c2_type)
                    break
        
        return len(matches) > 0, sorted(set(matches))

    def _match_body_signatures(self, sample_body: str) -> Tuple[bool, list]:
        """Check response body for C2 signatures."""
        matches = []
        
        for c2_type, patterns in C2Fingerprint.BODY_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, sample_body, re.IGNORECASE):
                    matches.append(c2_type)
                    break
        
        return len(matches) > 0, sorted(set(matches))

    def _analyze_tls(self, ssl_context: ssl.SSLContext | None) -> Dict[str, Any]:
        """Extract TLS information if available."""
        tls_info = {}
        
        if ssl_context and hasattr(ssl_context, 'version'):
            try:
                version = ssl_context.version()
                tls_info['version'] = version
            except Exception:
                pass
        
        return tls_info

    def _calculate_response_time(self, start_time: float) -> float:
        """Calculate total response time."""
        # This would need to track the end time in a real implementation
        # For now, returns 0 - caller should track this
        return 0.0

    def analyze_endpoint(
        self, 
        url: str, 
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a single HTTP endpoint for C2 fingerprints.
        
        Args:
            url: The target URL (e.g., http://example.com/api)
            method: HTTP method to use (default GET)
            headers: Optional custom headers
            
        Returns:
            Dictionary containing analysis results
        """
        parsed = urlparse(url)
        host = parsed.hostname or 'unknown'
        port = parsed.port or 80 if not parsed.scheme.startswith('https') else 443
        
        # Determine if SSL is needed
        use_ssl = parsed.scheme == 'https' and (port in (443, 8443) or 
                                                ('443' in str(parsed.netloc)))

        try:
            sock, ssl_context = self._create_connection(host, port, use_ssl, headers)
            
            # Build request
            path = parsed.path + (parsed.query if parsed.query else '')
            body = f"{method} {path} HTTP/1.1\r\n"
            body += "Host: " + host + "\r\n"
            body += "Connection: close\r\n"
            
            if headers:
                for k, v in headers.items():
                    body += f"{k}: {v}\r\n"
            
            # Add User-Agent to help detect server behavior
            user_agent = headers.get('User-Agent', '') if headers else ''
            if not user_agent:
                body += "User-Agent: Python-C2-Detect/1.0\r\n"
            
            body += "\r\n"
            
            sock.sendall(body.encode())
            
            # Read response with size limit
            sock.settimeout(5.0)
            buffer = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if b'\r\n\r\n' in buffer and len(buffer) > 2048:
                    # Found headers, get body sample
                    header_end = buffer.index(b'\r\n\r\n') + 4
                    body_sample = buffer[header_end:].decode('utf-8', errors='ignore')[:1024]
                    break
            
            sock.close()

        except socket.timeout:
            return {
                'status': 'timeout',
                'host': host,
                'port': port,
                'error': f'Connection timed out after {self.timeout}s',
                'headers': {},
                'body_sample': '',
                'tls_info': {},
                'response_time_ms': 0.0,
            }

        except socket.error as e:
            return {
                'status': 'error',
                'host': host,
                'port': port,
                'error': str(e),
                'headers': {},
                'body_sample': '',
                'tls_info': {},
                'response_time_ms': 0.0,
            }

        except Exception as e:
            return {
                'status': 'exception',
                'host': host,
                'port': port,
                'error': type(e).__name__ + ': ' + str(e),
                'headers': {},
                'body_sample': '',
                'tls_info': {},
                'response_time_ms': 0.0,
            }

        # Process successful response
        headers = self._extract_headers(buffer)
        body_sample = self._extract_body_sample(buffer)

        # Run all analysis modules
        header_match, header_matches = self._match_header_signatures(headers, body_sample)
        body_match, body_matches = self._match_body_signatures(body_sample)
        tls_info = self._analyze_tls(ssl_context)

        # Calculate confidence score (0-100)
        confidence = 0.0
        if header_match:
            confidence += 30
        if body_match:
            confidence += 40
        if tls_info.get('version'):
            confidence += 10
        
        # Adjust for number of matches
        total_matches = len(header_matches) + len(body_matches)
        confidence = min(100, confidence + (total_matches * 5))

        return {
            'status': 'success',
            'host': host,
            'port': port,
            'url': url,
            'headers': headers,
            'body_sample': body_sample,
            'tls_info': tls_info,
            'response_time_ms': 0.0,  # Would need tracking in real impl
            'header_matches': header_match,
            'header_candidates': header_matches,
            'body_matches': body_match,
            'body_candidates': body_matches,
            'confidence_score': round(confidence, 1),
            'is_c2_server': header_match or body_match,
        }


class C2ServerScanner:
    """High-level scanner that orchestrates multiple endpoint analyses."""

    def __init__(self, timeout: float = 5.0):
        self.analyzer = HTTPEndpointAnalyzer(timeout=timeout)
    
    def scan_endpoint(self, url: str, method: str = 'GET') -> Dict[str, Any]:
        """Scan a single URL and return detailed results."""
        result = self.analyzer.analyze_endpoint(url, method)
        
        # Add summary fields
        result['summary'] = {
            'is_c2_server': result.get('is_c2_server', False),
            'likely_type': max(result.get('header_candidates', []), 
                             key=lambda x: 1 if x in result.get('header_candidates', []) else 0)
                            or max(result.get('body_candidates', []))
                            or 'unknown'
                            if (result.get('header_matches') or result.get('body_matches'))
                            else 'unknown',
            'confidence': result.get('confidence_score', 0.0),
        }

        return result
    
    def scan_multiple(self, urls: list[str], method: str = 'GET') -> list[Dict]:
        """Scan multiple URLs and aggregate results."""
        results = []
        
        for url in urls:
            try:
                result = self.scan_endpoint(url, method)
                results.append(result)
                
                # Print quick summary
                if result.get('is_c2_server'):
                    print(f"  [!] C2 detected at {url}")
                    print(f"      Type: {result['summary']['likely_type']}")
                    print(f"      Confidence: {result['summary']['confidence']}%")
                    
            except Exception as e:
                results.append({
                    'status': 'exception',
                    'host': urlparse(url).hostname or url,
                    'error': str(e),
                })

        return results


def main():
    """Demo/test harness for the analyzer."""
    
    print("=" * 60)
    print("C2 Server Fingerprinter - HTTP Endpoint Analyzer")
    print("=" * 60)
    print()
    
    # Test URLs (some real patterns, some examples)
    test_urls = [
        'http://example.com/api',           # Generic API endpoint
        'https://api.github.com/user',      # Real HTTPS with cert
        'http://127.0.0.1:8080/test',       # Local test
    ]

    print("Testing HTTPEndpointAnalyzer...")
    print("-" * 40)
    
    analyzer = HTTPEndpointAnalyzer(timeout=3.0)
    
    for url in test_urls[:2]:  # Limit for demo speed
        print(f"\nAnalyzing: {url}")
        result = analyzer.analyze_endpoint(url, method='GET')
        
        if result.get('status') == 'success':
            print(f"  Status: OK")
            print(f"  Host: {result['host']}:{result['port']}")
            print(f"  Is C2 Server: {result.get('is_c2_server', False)}")
            print(f"  Confidence: {result.get('confidence_score', 0):.1f}%")
            
            if result.get('header_candidates'):
                print(f"  Header Matches: {', '.join(result['header_candidates'])}")
            if result.get('body_candidates'):
                print(f"  Body Matches: {', '.join(result['body_candidates'])}")

    # Test with scanner
    print("\n\nTesting C2ServerScanner...")
    print("-" * 40)
    
    scanner = C2ServerScanner(timeout=3.0)
    results = scanner.scan_multiple(test_urls, method='GET')
    
    print(f"\nTotal scanned: {len(results)}")
    c2_count = sum(1 for r in results if r.get('is_c2_server'))
    print(f"C2 servers detected: {c2_count}")

    # Interactive mode suggestion
    print("\n" + "=" * 60)
    print("Ready to analyze endpoints.")
    print("Use C2ServerScanner().scan_multiple([url1, url2, ...])")
    print("=" * 60)


if __name__ == '__main__':
    main()