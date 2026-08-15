use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum C2DetectError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Timeout waiting for response")]
    Timeout,
    
    #[error("Empty or invalid response from server")]
    EmptyResponse,
}

pub type Result<T> = std::result::Result<T, C2DetectError>;

/// Response metadata extracted during analysis
#[derive(Debug, Clone)]
pub struct AnalysisMetadata {
    pub url: String,
    pub method: reqwest::Method,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub content_length: Option<u64>,
    pub response_time_ms: f32,
}

/// Fingerprint result for a single C2 framework
#[derive(Debug, Clone)]
pub struct FrameworkMatch {
    pub name: &'static str,
    pub confidence: u8, // 0-100
    pub evidence: Vec<String>,
    pub detected_paths: Vec<String>,
}

/// Complete analysis result
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub metadata: AnalysisMetadata,
    pub matches: Vec<FrameworkMatch>,
    pub primary_match: Option<&'static str>,
    pub raw_body: String,
}

impl AnalysisResult {
    pub fn is_confident(&self) -> bool {
        self.primary_match.is_some() && 
            self.matches.iter().any(|m| m.confidence >= 70)
    }
    
    pub fn get_primary_url(&self) -> &str {
        if let Some(name) = self.primary_match {
            match name {
                "Cobalt Strike" => "/beacon/",
                "Sliver" => "/sliver/",
                "Mythic" => "/api/v1/",
                "Havoc" => "/havoc/",
                "Brute Ratel" => "/bruteratel/",
                _ => "/",
            }
        } else {
            "/"
        }
    }
}

/// Raw HTTP response wrapper for analysis
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub headers: HashMap<String, String>,
    pub body: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
}

impl From<reqwest::Response> for RawResponse {
    fn from(response: reqwest::Response) -> Self {
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        RawResponse {
            headers,
            body: String::from_utf8_lossy(&response.bytes().unwrap_or_default()).into_owned(),
            status_code: response.status().as_u16(),
            content_length: response.content_length(),
        }
    }
}

/// Configuration for the analyzer
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub timeout_ms: u64,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub user_agent: Option<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            follow_redirects: true,
            max_redirects: 5,
            user_agent: Some(String::from("C2Detect/1.0"),