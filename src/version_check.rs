// Security Center - GitHub Version Check
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Automatic update checking via GitHub Releases API.

use reqwest::Url;
use serde::Deserialize;
use tracing::{debug, warn};

const GITHUB_OWNER: &str = "christosdaggas";
const GITHUB_REPO: &str = "security-center";

/// Result of a successful version check.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    /// Latest version string (e.g. "1.2.0").
    pub latest_version: String,
    /// URL the user can visit to download the release.
    pub download_url: String,
    /// Release name / title (may be empty).
    #[allow(dead_code)]
    pub release_name: String,
}

/// Subset of the GitHub Releases API response we care about.
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    name: Option<String>,
}

/// Check GitHub for the latest release.
///
/// Returns `Some(UpdateInfo)` if a newer version exists,
/// `None` if the local version is current or on ANY error.
pub async fn check_for_update(current_version: &str) -> Option<UpdateInfo> {
    let url = Url::parse(&format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        GITHUB_OWNER, GITHUB_REPO
    ))
    .ok()?;

    // Defense in depth: ensure we only connect to GitHub over HTTPS
    if url.scheme() != "https" || url.host_str() != Some("api.github.com") {
        debug!("Unexpected update check URL, aborting");
        return None;
    }

    debug!("Checking for updates at {}", url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(format!("{}/{}", GITHUB_REPO, current_version))
        .build()
        .ok()?;

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Update check HTTP request failed (not an error): {}", e);
            return None;
        }
    };

    if !response.status().is_success() {
        debug!(
            "Update check got HTTP {} (repo may not have releases yet)",
            response.status()
        );
        return None;
    }

    let release: GitHubRelease = match response.json().await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to parse GitHub release JSON: {}", e);
            return None;
        }
    };

    let latest = release
        .tag_name
        .trim_start_matches('v')
        .trim_start_matches('V')
        .to_string();

    debug!("Update check: local={}, remote={}", current_version, latest);

    if is_newer(&latest, current_version) {
        Some(UpdateInfo {
            latest_version: latest,
            download_url: release.html_url,
            release_name: release.name.unwrap_or_default(),
        })
    } else {
        debug!("Application is up to date");
        None
    }
}

fn is_newer(remote: &str, local: &str) -> bool {
    let r = match semver::Version::parse(remote) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let l = match semver::Version::parse(local) {
        Ok(v) => v,
        Err(_) => return false,
    };
    r > l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("1.1.0", "1.0.0"));
        assert!(is_newer("2.0.0", "1.9.9"));
        assert!(is_newer("1.0.1", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
        // Note: semver only supports major.minor.patch; 4-component versions are treated as invalid
    }

    #[test]
    fn test_is_newer_malformed() {
        assert!(!is_newer("1.a.0", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.a.0"));
        assert!(!is_newer("", "1.0.0"));
        assert!(!is_newer("not-a-version", "1.0.0"));
    }
}
