use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::types::{
    dedupe_cookies, BrowserName, Cookie, CookieSameSite, CookieSource, GetCookiesResult,
};
use crate::util::host_match::host_matches_cookie_domain;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use url::Url;

const MOZLZ4_HEADER: &[u8] = b"mozLz40\0";

#[derive(Debug, Clone, Copy)]
pub struct FirefoxBrowser {
    pub name: BrowserName,
    label: &'static str,
    roots: fn() -> Vec<PathBuf>,
    preferred_profile_markers: &'static [&'static str],
}

#[derive(Debug, Default)]
pub struct FirefoxOptions {
    pub profile: Option<String>,
    pub include_expired: Option<bool>,
}

pub const FIREFOX: FirefoxBrowser = FirefoxBrowser {
    name: BrowserName::Firefox,
    label: "Firefox",
    roots: firefox_roots,
    preferred_profile_markers: &["default-release"],
};

pub const ZEN: FirefoxBrowser = FirefoxBrowser {
    name: BrowserName::Zen,
    label: "Zen",
    roots: zen_roots,
    preferred_profile_markers: &["Default", "default"],
};

pub async fn get_cookies_from_firefox(
    browser: FirefoxBrowser,
    options: FirefoxOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    let Some(profile_dir) = resolve_firefox_profile(
        options.profile.as_deref(),
        &(browser.roots)(),
        browser.preferred_profile_markers,
    ) else {
        return warning(format!("{} profile not found.", browser.label));
    };

    let hosts: Vec<String> = origins
        .iter()
        .filter_map(|o| {
            Url::parse(o)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
        })
        .collect();
    let include_expired = options.include_expired.unwrap_or(false);
    let profile = options.profile.clone();
    let names_owned = allowlist_names.cloned();
    let result = tokio::task::spawn_blocking(move || {
        let mut warnings = Vec::new();
        let mut raw_cookies = match read_firefox_sessionstore(&profile_dir) {
            Ok(cookies) => cookies,
            Err(error) => {
                warnings.push(format!(
                    "Failed reading {} session cookies: {error}",
                    browser.label
                ));
                Vec::new()
            }
        };
        match read_firefox_database(&profile_dir) {
            Ok(cookies) => raw_cookies.extend(cookies),
            Err(error) => warnings.push(format!(
                "Failed reading {} cookie database: {error}",
                browser.label
            )),
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let source = CookieSource {
            browser: browser.name,
            profile,
            origin: None,
            store_id: None,
        };
        let cookies = raw_cookies
            .into_iter()
            .filter_map(|cookie| {
                cookie.into_cookie(&hosts, names_owned.as_ref(), include_expired, now, &source)
            })
            .collect();

        GetCookiesResult {
            cookies: dedupe_cookies(cookies),
            warnings,
        }
    })
    .await;

    match result {
        Ok(result) => result,
        Err(e) => warning(format!("{} cookie task failed: {e}", browser.label)),
    }
}

#[derive(Debug, Deserialize)]
struct FirefoxSessionStore {
    #[serde(default)]
    cookies: Vec<FirefoxCookie>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirefoxCookie {
    name: String,
    value: String,
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    secure: bool,
    #[serde(default, rename = "httponly")]
    http_only: bool,
    same_site: Option<i32>,
    #[serde(default)]
    expiry: i64,
    #[serde(
        default,
        rename = "originAttributes",
        deserialize_with = "deserialize_origin_attributes"
    )]
    isolated: bool,
}

impl FirefoxCookie {
    fn into_cookie(
        self,
        hosts: &[String],
        allowlist_names: Option<&HashSet<String>>,
        include_expired: bool,
        now: i64,
        source: &CookieSource,
    ) -> Option<Cookie> {
        if self.name.is_empty()
            || self.isolated
            || allowlist_names.is_some_and(|names| !names.contains(&self.name))
            || !hosts
                .iter()
                .any(|host| host_matches_cookie_domain(host, &self.host))
        {
            return None;
        }

        let expires = (self.expiry > 0).then_some(self.expiry);
        if !include_expired && expires.is_some_and(|expiry| expiry <= now) {
            return None;
        }

        Some(Cookie {
            name: self.name,
            value: self.value,
            domain: Some(
                self.host
                    .strip_prefix('.')
                    .unwrap_or(&self.host)
                    .to_string(),
            ),
            path: Some(if self.path.is_empty() {
                "/".to_string()
            } else {
                self.path
            }),
            url: None,
            expires,
            secure: Some(self.secure),
            http_only: Some(self.http_only),
            same_site: match self.same_site {
                Some(2) => Some(CookieSameSite::Strict),
                Some(1) => Some(CookieSameSite::Lax),
                Some(0) => Some(CookieSameSite::None),
                _ => None,
            },
            source: Some(source.clone()),
        })
    }
}

fn deserialize_origin_attributes<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    fn is_default(value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::Bool(value) => !value,
            Value::Number(value) => value.as_f64() == Some(0.0),
            Value::String(value) => value.is_empty(),
            Value::Array(values) => values.iter().all(is_default),
            Value::Object(values) => values.values().all(is_default),
        }
    }

    Value::deserialize(deserializer).map(|attributes| !is_default(&attributes))
}

fn read_firefox_sessionstore(profile_dir: &Path) -> Result<Vec<FirefoxCookie>, String> {
    let sessionstore_paths = [
        profile_dir.join("sessionstore-backups/recovery.jsonlz4"),
        profile_dir.join("sessionstore.jsonlz4"),
    ];
    let Some(sessionstore_path) = sessionstore_paths.iter().find(|path| path.exists()) else {
        return Ok(Vec::new());
    };

    let compressed = std::fs::read(sessionstore_path)
        .map_err(|error| format!("read {}: {error}", sessionstore_path.display()))?;
    let payload = compressed
        .strip_prefix(MOZLZ4_HEADER)
        .ok_or_else(|| format!("invalid mozLz4 header in {}", sessionstore_path.display()))?;
    let json = lz4_flex::block::decompress_size_prepended(payload)
        .map_err(|error| format!("decompress {}: {error}", sessionstore_path.display()))?;
    let sessionstore: FirefoxSessionStore = serde_json::from_slice(&json)
        .map_err(|error| format!("parse {}: {error}", sessionstore_path.display()))?;

    Ok(sessionstore.cookies)
}

fn read_firefox_database(profile_dir: &Path) -> Result<Vec<FirefoxCookie>, String> {
    let source_db_path = profile_dir.join("cookies.sqlite");
    let temp_dir = tempfile::tempdir().map_err(|error| error.to_string())?;
    let temp_db_path = temp_dir.path().join("cookies.sqlite");
    std::fs::copy(&source_db_path, &temp_db_path)
        .map_err(|error| format!("copy {}: {error}", source_db_path.display()))?;
    copy_sidecar(&source_db_path, &temp_db_path, "-wal")?;
    copy_sidecar(&source_db_path, &temp_db_path, "-shm")?;

    let conn = rusqlite::Connection::open_with_flags(
        temp_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite, \
             originAttributes FROM moz_cookies ORDER BY expiry DESC;",
        )
        .map_err(|e| e.to_string())?;
    let cookies = stmt
        .query_map([], |row| {
            Ok(FirefoxCookie {
                name: row.get(0)?,
                value: row.get(1)?,
                host: row.get(2)?,
                path: row.get(3)?,
                expiry: row.get(4)?,
                secure: row.get::<_, i32>(5)? != 0,
                http_only: row.get::<_, i32>(6)? != 0,
                same_site: Some(row.get(7)?),
                isolated: !row.get::<_, String>(8)?.is_empty(),
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(cookies)
}

fn warning(message: impl Into<String>) -> GetCookiesResult {
    GetCookiesResult {
        cookies: vec![],
        warnings: vec![message.into()],
    }
}

fn resolve_firefox_profile(
    profile: Option<&str>,
    roots: &[PathBuf],
    preferred_profile_markers: &[&str],
) -> Option<PathBuf> {
    if let Some(profile) = profile {
        if looks_like_path(profile) {
            let path = PathBuf::from(profile);
            let profile_dir = if path.ends_with("cookies.sqlite") {
                path.parent()?.to_path_buf()
            } else {
                path
            };
            return profile_dir.is_dir().then_some(profile_dir);
        }
    }

    for root in roots {
        if !root.exists() {
            continue;
        }
        if let Some(profile) = profile {
            let candidate = root.join(profile);
            if candidate.is_dir() {
                return Some(candidate);
            }
            continue;
        }

        let entries = safe_readdir(root);
        let preferred_profile = preferred_profile_markers
            .iter()
            .find_map(|marker| entries.iter().find(|e| e.contains(marker)));
        let picked = preferred_profile.or(entries.first());
        if let Some(picked) = picked {
            let candidate = root.join(picked);
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn home_roots(paths: &[&str]) -> Vec<PathBuf> {
    dirs::home_dir()
        .map(|home| paths.iter().map(|path| home.join(path)).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn appdata_roots(paths: &[&str]) -> Vec<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|appdata| {
            paths
                .iter()
                .map(|path| PathBuf::from(&appdata).join(path))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn firefox_roots() -> Vec<PathBuf> {
    home_roots(&["Library/Application Support/Firefox/Profiles"])
}

#[cfg(target_os = "macos")]
fn zen_roots() -> Vec<PathBuf> {
    home_roots(&["Library/Application Support/zen/Profiles"])
}

#[cfg(target_os = "linux")]
fn firefox_roots() -> Vec<PathBuf> {
    home_roots(&[".mozilla/firefox"])
}

#[cfg(target_os = "linux")]
fn zen_roots() -> Vec<PathBuf> {
    home_roots(&[".zen", ".var/app/app.zen_browser.zen/.zen"])
}

#[cfg(target_os = "windows")]
fn firefox_roots() -> Vec<PathBuf> {
    appdata_roots(&["Mozilla/Firefox/Profiles"])
}

#[cfg(target_os = "windows")]
fn zen_roots() -> Vec<PathBuf> {
    appdata_roots(&["zen/Profiles"])
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn firefox_roots() -> Vec<PathBuf> {
    vec![]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn zen_roots() -> Vec<PathBuf> {
    vec![]
}

fn safe_readdir(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

fn copy_sidecar(source_db_path: &Path, temp_db_path: &Path, suffix: &str) -> Result<(), String> {
    let with_suffix = |path: &Path| {
        let mut path = path.as_os_str().to_os_string();
        path.push(suffix);
        PathBuf::from(path)
    };
    let sidecar = with_suffix(source_db_path);
    let target = with_suffix(temp_db_path);
    if sidecar.exists() {
        std::fs::copy(&sidecar, target)
            .map_err(|error| format!("copy {}: {error}", sidecar.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lz4_flex::block::compress_prepend_size;

    #[test]
    fn reads_filtered_sessionstore_cookies() {
        let profile_dir = tempfile::tempdir().unwrap();
        let backups = profile_dir.path().join("sessionstore-backups");
        std::fs::create_dir(&backups).unwrap();

        let json = serde_json::json!({
            "cookies": [
                {
                    "host": ".spotify.com",
                    "name": "sp_dc",
                    "value": "isolated-value",
                    "originAttributes": { "userContextId": 1 }
                },
                {
                    "host": ".spotify.com",
                    "name": "sp_dc",
                    "value": "session-value",
                    "path": "/",
                    "secure": true,
                    "httponly": true,
                    "sameSite": 0
                }
            ]
        });
        let mut encoded = MOZLZ4_HEADER.to_vec();
        encoded.extend(compress_prepend_size(&serde_json::to_vec(&json).unwrap()));
        std::fs::write(backups.join("recovery.jsonlz4"), encoded).unwrap();

        let source = CookieSource {
            browser: BrowserName::Zen,
            profile: Some("main".to_string()),
            origin: None,
            store_id: None,
        };
        let cookies: Vec<_> = read_firefox_sessionstore(profile_dir.path())
            .unwrap()
            .into_iter()
            .filter_map(|cookie| {
                cookie.into_cookie(
                    &["open.spotify.com".to_string()],
                    Some(&HashSet::from(["sp_dc".to_string()])),
                    false,
                    0,
                    &source,
                )
            })
            .collect();

        assert_eq!(cookies.len(), 1);
        let cookie = &cookies[0];
        assert_eq!(cookie.name, "sp_dc");
        assert_eq!(cookie.value, "session-value");
        assert_eq!(cookie.domain.as_deref(), Some("spotify.com"));
        assert_eq!(cookie.path.as_deref(), Some("/"));
        assert_eq!(cookie.secure, Some(true));
        assert_eq!(cookie.http_only, Some(true));
        assert_eq!(cookie.same_site, Some(CookieSameSite::None));
        assert_eq!(
            cookie
                .source
                .as_ref()
                .and_then(|source| source.profile.as_deref()),
            Some("main")
        );
    }
}
