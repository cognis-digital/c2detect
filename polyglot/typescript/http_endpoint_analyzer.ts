import http = require('http');
import https = require('https');
import { URL } from 'url';
import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// Configuration & Constants
// ============================================================================

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_RETRIES = 3;
const RETRY_DELAY_MS = 200;

interface C2Fingerprint {
    framework: string;
    confidence: number; // 0-100
    indicators: string[];
    metadata?: Record<string, any>;
}

// ============================================================================
// Fingerprint Database (Sample Data)
// ============================================================================

const KNOWN_FRAMEWORKS = [
    { name: 'Cobalt Strike', version: '4.x' },
    { name: 'Sliver', version: '1.x' },
    { name: 'Mythic', version: '2.x' },
    { name: 'Havoc', version: '1.x' },
    { name: 'Brute Ratel', version: '3.x' }
];

// Header patterns that indicate specific frameworks
const HEADER_PATTERNS: Record<string, string[]> = {
    'cobalt-strike': [
        /X-Cobalt-Strike/,
        /Cobalt-Strike/,
        /Beacon/
    ],
    'sliver': [
        /Sliver/,
        /sliver-agent/,
        /sliver-framework/
    ],
    'mythic': [
        /Mythic/,
        /mythic-c2/
    ],
    'havoc': [
        /Havoc/,
        /havoc-c2/
    ],
    'brute-ratel': [
        /BruteRatel/,
        /ratel-c2/
    ]
};

// Response body patterns (case-insensitive)
const BODY_PATTERNS: Record<string, RegExp[]> = {
    'cobalt-strike': [
        /Beacon.*Protocol/,
        /Cobalt-Strike.*Server/,
        /beacon\.exe/
    ],
    'sliver': [
        /Sliver.*Framework/,
        /sliver-agent/
    ],
    'mythic': [
        /Mythic.*Console/,
        /mythic-c2/
    ]
};

// ============================================================================
// HTTP Client Wrapper
// ============================================================================

class C2HTTPClient {
    private timeout: number;
    private retries: number;
    private retryDelay: number;

    constructor(timeout?: number, retries?: number, retryDelay?: number) {
        this.timeout = timeout || DEFAULT_TIMEOUT_MS;
        this.retries = retries || DEFAULT_RETRIES;
        this.retryDelay = retryDelay || RETRY_DELAY_DELAY_MS;
    }

    async request(options: http.RequestOptions): Promise<http.IncomingMessage> {
        const client = options.protocol === 'https:' ? https : http;
        
        return new Promise((resolve, reject) => {
            let attempt = 0;
            
            const makeRequest = () => {
                if (attempt > this.retries) {
                    const error = new Error(`Max retries (${this.retries}) exceeded`);
                    error.code = 'MAX_RETRIES';
                    return reject(error);
                }

                try {
                    const req = client.request(options, res => {
                        // Handle chunked responses
                        let data: string | Buffer;
                        
                        if (res.statusCode === 204 || !res.headers['content-length']) {
                            data = '';
                        } else {
                            const chunks: Uint8Array[] = [];
                            
                            res.on('data', chunk => chunks.push(chunk));
                            res.on('end', () => {
                                data = Buffer.concat(chunks).toString();
                                resolve(res);
                            });
                            res.on('error', err => reject(err));
                        }
                    });

                    req.setTimeout(this.timeout, () => {
                        req.destroy(new Error('Request timeout'));
                    });

                    req.end();
                } catch (err) {
                    if (attempt < this.retries) {
                        attempt++;
                        setTimeout(makeRequest, this.retryDelay);
                        return;
                    }
                    reject(err as Error);
                }
            };

            makeRequest();
        });
    }

    async get(url: string): Promise<http.IncomingMessage> {
        const parsed = new URL(url);
        
        // Add common C2 headers for better detection
        const options: http.RequestOptions = {
            method: 'GET',
            timeout: this.timeout,
            headers: {
                'User-Agent': 'C2Detect/1.0 (Node.js)',
                'Accept': '*/*',
                'Connection': 'keep-alive'
            }
        };

        if (parsed.protocol === 'https:') {
            options.headers['ALPN'] = 'h2'; // Prefer HTTP/2 for modern C2s
        }

        return this.request(options);
    }

    async head(url: string): Promise<http.IncomingMessage> {
        const parsed = new URL(url);
        
        const options: http.RequestOptions = {
            method: 'HEAD',
            timeout: 1000, // HEAD requests should be fast
            headers: {
                'User-Agent': 'C2Detect/1.0 (Node.js)',
                'Accept': '*/*'
            }
        };

        if (parsed.protocol === 'https:') {
            options.headers['ALPN'] = 'h2';
        }

        return this.request(options);
    }
}

// ============================================================================
// Response Analyzer
// ============================================================================

interface AnalysisResult {
    url: string;
    status: number | null;
    headers: http.OutgoingHttpHeaders;
    body: string;
    timing: {
        dns: number;
        tcp: number;
        tls: number;
        total: number;
    };
    sslInfo?: {
        cipher: string;
        version: string;
        subject: string;
    };
    fingerprints: C2Fingerprint[];
    overallScore: number; // 0-100, higher = more confident
    metadata: Record<string, any>;
}

interface TimingData {
    dnsStart: number;
    tcpStart: number;
    tlsStart: number;
    requestStart: number;
    responseComplete: number;
}

class ResponseAnalyzer {
    private client: C2HTTPClient;

    constructor(client?: C2HTTPClient) {
        this.client = client || new C2HTTPClient();
    }

    async analyze(url: string, options: AnalysisOptions = {}): Promise<AnalysisResult> {
        const startTime = Date.now();
        
        // Step 1: Perform HEAD request for headers + timing
        let headResponse: http.IncomingMessage;
        try {
            headResponse = await this.client.head(url);
        } catch (err) {
            return this.handleHeadError(url, err as Error, startTime);
        }

        // Step 2: Get full response body if HEAD didn't provide enough info
        let body: string;
        try {
            const fullResponse = await this.client.get(url);
            
            // Extract timing data from request/response lifecycle
            const timing = this.extractTiming(startTime, Date.now());
            
            body = fullResponse.body || (await this.readBody(fullResponse)) || '';
            
            return {
                url,
                status: headResponse.statusCode,
                headers: headResponse.headers,
                body,
                timing,
                sslInfo: this.extractSSLInfo(headResponse),
                fingerprints: [], // Will be populated below
                overallScore: 0,
                metadata: {
                    requestMethod: 'GET',
                    contentLength: fullResponse.headers['content-length'],
                    contentType: fullResponse.headers['content-type']
                }
            };
        } catch (err) {
            return this.handleGetError(url, err as Error, startTime);
        }
    }

    private async readBody(res: http.IncomingMessage): Promise<string> {
        const chunks: Uint8Array[] = [];
        
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => Buffer.concat(chunks).toString());
        res.on('error', err => console.error('Body read error:', err));
    }

    private extractTiming(requestStart: number, completeTime: number): TimingData {
        // These would be populated from actual request lifecycle hooks
        return {
            dnsStart: 0,
            tcpStart: 0,
            tlsStart: 0,
            requestStart: requestStart,
            responseComplete: completeTime
        };
    }

    private extractSSLInfo(res: http.IncomingMessage): Record<string, any> | undefined {
        if (res.headers['x-ssl-cipher']) {
            return {
                cipher: res.headers['x-ssl-cipher'],
                version: 'unknown',
                subject: ''
            };
        }
        
        // Try to parse from common headers
        const cipher = res.headers['x-ssl-cipher'] || 
                      (res.headers['sec-challenge'] as string) || '';
        
        return cipher ? { cipher, version: 'unknown', subject: '' } : undefined;
    }

    private handleHeadError(url: string, err: Error, startTime: number): AnalysisResult {
        const timing = this.extractTiming(startTime, Date.now());
        
        return {
            url,
            status: null,
            headers: {},
            body: '',
            timing,
            sslInfo: undefined,
            fingerprints: [],
            overallScore: 0,
            metadata: { error: err.message }
        };
    }

    private handleGetError(url: string, err: Error, startTime: number): AnalysisResult {
        const timing = this.extractTiming(startTime, Date.now());
        
        return {
            url,
            status: null,
            headers: {},
            body: '',
            timing,
            sslInfo: undefined,
            fingerprints: [],
            overallScore: 0,
            metadata: { error: err.message }
        };
    }

    private detectFingerprints(headers: http.OutgoingHttpHeaders, body: string): C2Fingerprint[] {
        const results: C2Fingerprint[] = [];
        
        // Check header patterns
        for (const [key, value] of Object.entries(headers)) {
            if (!value) continue;
            
            const lowerValue = String(value).toLowerCase();
            
            for (const [framework, patterns] of Object.entries(HEADER_PATTERNS)) {
                for (const pattern of patterns) {
                    if (pattern.test(lowerValue)) {
                        results.push({
                            framework: this.capitalize(framework),
                            confidence: 85, // Base confidence from header match
                            indicators: [`Header: ${key} contains "${value}"`],
                            metadata: { matchedPattern: pattern.toString() }
                        });
                    }
                }
            }
        }

        // Check body patterns (if available)
        if (body && body.length > 100) {
            for (const [framework, patterns] of Object.entries(BODY_PATTERNS)) {
                let found = false;
                
                for (const pattern of patterns) {
                    if (pattern.test(body.toLowerCase())) {
                        results.push({
                            framework: this.capitalize(framework),
                            confidence: 75,
                            indicators: [`Body contains pattern matching "${framework}"`],
                            metadata: { matchedPattern: pattern.toString() }
                        });
                        found = true;
                    }
                }

                if (found) break; // Avoid duplicate detections
            }
        }

        return results;
    }

    private capitalize(str: string): string {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
}

// ============================================================================
// Main Analyzer Class
// ============================================================================

interface AnalysisOptions {
    timeout?: number;
    retries?: number;
    followRedirects?: boolean;
    maxRedirects?: number;
}

class C2EndpointAnalyzer {
    private analyzer: ResponseAnalyzer;
    private client: C2HTTPClient;

    constructor(options: AnalysisOptions = {}) {
        this.client = new C2HTTPClient(
            options.timeout,
            options.retries
        );
        this.analyzer = new ResponseAnalyzer(this.client);
    }

    async analyze(url: string): Promise<AnalysisResult> {
        return this.analyzer.analyze(url, { timeout: this.client.timeout });
    }

    async batchAnalyze(urls: string[]): Promise<AnalysisResult[]> {
        const results: AnalysisResult[] = [];
        
        for (const url of urls) {
            try {
                const result = await this.analyze(url);
                results.push(result);
                
                // Small delay between requests to avoid overwhelming targets
                if (urls.indexOf(url) < urls.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 50));
                }
            } catch (err) {
                console.error(`Error analyzing ${url}:`, err);
                results.push({
                    url,
                    status: null,
                    headers: {},
                    body: '',
                    timing: this.analyzer.extractTiming(Date.now(), Date.now()),
                    sslInfo: undefined,
                    fingerprints: [],
                    overallScore: 0,
                    metadata: { error: (err as Error).message }
                });
            }
        }

        return results;
    }

    async analyzeWithRetry(url: string, maxRetries = 3): Promise<AnalysisResult> {
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                const result = await this.analyze(url);
                
                // If we got a valid response with some data, return it
                if (result.status || result.body.length > 0) {
                    return result;
                }
            } catch (err) {
                console.error(`Attempt ${attempt} failed for ${url}:`, err);
                await new Promise(resolve => setTimeout(resolve, 100 * attempt));
            }
        }

        throw new Error(`Failed to analyze ${url} after ${maxRetries} attempts`);
    }
}

// ============================================================================
// CLI Interface
// ============================================================================

interface CLIOptions {
    urls: string[];
    output?: string;
    timeout?: number;
    retries?: number;
    format?: 'json' | 'text';
    verbose?: boolean;
}

async function runCLI(options: CLIOptions): Promise<void> {
    const analyzer = new C2EndpointAnalyzer({
        timeout: options.timeout,
        retries: options.retries
    });

    console.log(`C2Detect v1.0 - HTTP Endpoint Analyzer`);
    console.log(`Target(s): ${options.urls.join(', ')}`);
    console.log(`Timeout: ${options.timeout}ms, Retries: ${options.retries}\n`);

    const results = await analyzer.batchAnalyze(options.urls);

    if (options.format === 'json') {
        fs.writeFileSync(
            options.output || process.cwd() + '/c2detect_results.json',
            JSON.stringify(results, null, 2)
        );
        console.log(`Results written to: ${options.output || 'c2detect_results.json'}`);
    } else {
        // Text output
        for (const result of results) {
            if (!result.status && !result.body.length) continue;

            const topFingerprint = result.fingerprints[0];
            
            console.log(`\n=== ${result.url} ===`);
            console.log(`Status: ${result.status || 'Unknown'} | Score: ${result.overallScore}`);
            
            if (topFingerprint) {
                console.log(`Likely Framework: ${topFingerprint.framework}`);
                console.log(`Confidence: ${topFingerprint.confidence}%`);
                console.log(`Indicators:`);
                topFingerprint.indicators.forEach(ind => console.log(`  - ${ind}`));
            } else {
                console.log('No strong fingerprint detected');
            }

            if (result.metadata?.error) {
                console.log(`Error: ${result.metadata.error}`);
            }
        }
    }
}

// ============================================================================
// Demo / Self-Contained Entry Point
// ============================================================================

async function main(): Promise<void> {
    // Default demo URLs - these are common C2 framework endpoints
    const demoUrls = [
        'http://127.0.0.1:8080',  // Local test endpoint
        'https://www.google.com'  // Control/test with known headers
    ];

    console.log('Starting C2Detect Demo...\