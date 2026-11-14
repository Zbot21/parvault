//! Folder-sync pieces a zero-key plugin needs (client-side: no runtime dependencies): path
//! sanitising, `.parvaultignore`, streaming file hashes, diff types and selective filters.

use crate::sharding::merkle::Hash32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Built-in default directory names excluded by `ParvaultIgnore`.
const DEFAULT_IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    ".parvault",
    ".parvault-data",
    ".parvault-seed-data",
    "__pycache__",
    ".venv",
];

/// Built-in default exact filenames excluded by `ParvaultIgnore`.
const DEFAULT_IGNORED_FILES: &[&str] = &[
    ".parvaultignore",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".parvault_sync_manifest.bin",
    "folder_snapshot.manifest.bin",
];

/// Built-in default glob patterns (suffixes / prefixes) excluded by `ParvaultIgnore`.
const DEFAULT_IGNORED_GLOBS: &[&str] = &[
    "*.tmp",
    "*.swp",
    "*.bak",
    "*~",
    "*.parvault_restore_staging",
    ".*.tmp.*",
    ".parvault*",
    "*.manifest.bin",
    "*.catalog.bin",
    "*.envelope.bin",
];

/// Streams a file from disk in 64 KiB chunks to compute its byte length and SHA-256 digest
/// without allocating the full file in RAM.
pub fn compute_file_sha256_streaming(path: &Path) -> Result<(u64, Hash32), std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total_bytes += n as u64;
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok((total_bytes, out))
}

/// Stack/slice core backing [`sanitize_sync_relative_path`] (`ADR-33` Path-Traversal Defense).
///
/// Validates `raw_bytes` in a single flat pass with **zero heap allocations** and writes the
/// normalized `/`-joined relative path into `out[..len]` (`out.len() >= raw_bytes.len()`).
/// Rejects empty inputs, NUL (`\0`) bytes, leading `/` or `\`, Windows drive or stream colons
/// (`:`), and `.` or `..` segments, collapsing duplicate or trailing separators cleanly.
pub fn sanitize_sync_relative_path_into(raw_bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    if raw_bytes.is_empty()
        || out.len() < raw_bytes.len()
        || raw_bytes[0] == b'/'
        || raw_bytes[0] == b'\\'
    {
        return None;
    }

    let mut idx = 0usize;
    let mut w = 0usize;
    let mut seg_len = 0usize;
    let mut seg_dots = 0usize;
    let mut seg_count = 0usize;
    let mut need_sep = false;

    while idx < raw_bytes.len() {
        let b = raw_bytes[idx];
        if b == 0 || b == b':' {
            return None;
        }
        if b == b'/' || b == b'\\' {
            if seg_len > 0 {
                if (seg_len == 1 && seg_dots == 1) || (seg_len == 2 && seg_dots == 2) {
                    return None;
                }
                seg_count += 1;
                seg_len = 0;
                seg_dots = 0;
                need_sep = true;
            }
        } else {
            if need_sep {
                out[w] = b'/';
                w += 1;
                need_sep = false;
            }
            if b == b'.' {
                seg_dots += 1;
            }
            out[w] = b;
            w += 1;
            seg_len += 1;
        }
        idx += 1;
    }

    if seg_len > 0 {
        if (seg_len == 1 && seg_dots == 1) || (seg_len == 2 && seg_dots == 2) {
            return None;
        }
        seg_count += 1;
    }

    if seg_count == 0 {
        return None;
    }
    Some(w)
}

/// Validates and normalizes a relative synchronization path (`ADR-33` Path-Traversal Defense).
///
/// Rejects empty strings, NUL (`\0`) bytes, leading `/` or `\`, Windows drive prefixes or colons
/// (such as `C:` or NTFS ADS `file:stream`), and `.` or `..` components, returning a normalized
/// `/`-joined relative path with zero leading, trailing, or duplicate separators.
///
/// Formally verified panic-free and traversal-free under Kani harness
/// `proof_sanitize_sync_relative_path_no_traversal`.
pub fn sanitize_sync_relative_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.len() <= 256 {
        let mut stack = [0u8; 256];
        let len = sanitize_sync_relative_path_into(bytes, &mut stack[..bytes.len()])?;
        return core::str::from_utf8(&stack[..len]).ok().map(String::from);
    }
    let mut out = vec![0u8; bytes.len()];
    let len = sanitize_sync_relative_path_into(bytes, &mut out)?;
    out.truncate(len);
    String::from_utf8(out).ok()
}

#[derive(Debug, Clone)]
struct IgnoreRule {
    pattern: String,
    negated: bool,
    dir_only: bool,
}

/// `.parvaultignore` and built-in default exclusion matcher for `FolderSyncEngine`.
#[derive(Debug, Clone, Default)]
pub struct ParvaultIgnore {
    custom_rules: Vec<IgnoreRule>,
}

impl ParvaultIgnore {
    pub fn new() -> Self {
        Self {
            custom_rules: Vec::new(),
        }
    }

    /// Initializes `ParvaultIgnore` with built-in defaults and parses `<folder_path>/.parvaultignore`
    /// if present (supporting `#` comments, blank lines, `dir/` rules, `*` and `?` wildcards,
    /// and `!pattern` negation rules).
    pub fn from_folder(folder_path: &Path) -> Self {
        let mut ignore = Self::new();
        let ignore_path = folder_path.join(".parvaultignore");
        if ignore_path.is_file() {
            if let Ok(raw) = fs::read_to_string(&ignore_path) {
                ignore.parse_rules(&raw);
            }
        }
        ignore
    }

    /// Parses `.parvaultignore` lines and appends them to the rule list.
    pub fn parse_rules(&mut self, content: &str) {
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
                (true, stripped.trim())
            } else {
                (false, line)
            };
            if rest.is_empty() {
                continue;
            }
            let normalized = rest.replace('\\', "/");
            let (dir_only, pat) = if let Some(stripped) = normalized.strip_suffix('/') {
                (true, stripped.trim_start_matches('/').to_string())
            } else {
                (false, normalized.trim_start_matches('/').to_string())
            };
            if pat.is_empty() {
                continue;
            }
            self.custom_rules.push(IgnoreRule {
                pattern: pat,
                negated,
                dir_only,
            });
        }
    }

    /// Returns `true` if `rel_path` should be excluded from synchronization.
    pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let normalized = rel_path.replace('\\', "/");
        let norm_path = normalized
            .trim_start_matches("./")
            .trim_start_matches('/')
            .trim_end_matches('/');
        if norm_path.is_empty() {
            return false;
        }

        let parts: Vec<&str> = norm_path.split('/').filter(|s| !s.is_empty()).collect();
        let Some(&basename) = parts.last() else {
            return false;
        };

        let mut ignored = Self::matches_builtin_defaults(&parts, basename, is_dir);

        for rule in &self.custom_rules {
            if Self::matches_custom_rule(rule, norm_path, &parts, basename, is_dir) {
                ignored = !rule.negated;
            }
        }

        ignored
    }

    fn matches_builtin_defaults(parts: &[&str], basename: &str, is_dir: bool) -> bool {
        // Any ancestor directory matching a default ignored directory name excludes the path.
        if parts.len() > 1 {
            for &ancestor in &parts[..parts.len() - 1] {
                if DEFAULT_IGNORED_DIRS.contains(&ancestor)
                    || DEFAULT_IGNORED_GLOBS
                        .iter()
                        .any(|pat| Self::wildcard_match(pat, ancestor))
                {
                    return true;
                }
            }
        }

        if is_dir && DEFAULT_IGNORED_DIRS.contains(&basename) {
            return true;
        }

        if DEFAULT_IGNORED_DIRS.contains(&basename) || DEFAULT_IGNORED_FILES.contains(&basename) {
            return true;
        }

        if DEFAULT_IGNORED_GLOBS
            .iter()
            .any(|pat| Self::wildcard_match(pat, basename))
        {
            return true;
        }

        false
    }

    fn matches_custom_rule(
        rule: &IgnoreRule,
        norm_path: &str,
        parts: &[&str],
        basename: &str,
        is_dir: bool,
    ) -> bool {
        let pat = rule.pattern.as_str();
        let has_slash = pat.contains('/');

        if rule.dir_only {
            if is_dir {
                if has_slash {
                    if Self::wildcard_match(pat, norm_path)
                        || norm_path.starts_with(&format!("{pat}/"))
                    {
                        return true;
                    }
                } else if Self::wildcard_match(pat, basename)
                    || parts.iter().any(|c| Self::wildcard_match(pat, c))
                {
                    return true;
                }
            } else if parts.len() > 1 {
                if has_slash {
                    let mut prefix = String::new();
                    for (idx, comp) in parts[..parts.len() - 1].iter().enumerate() {
                        if idx > 0 {
                            prefix.push('/');
                        }
                        prefix.push_str(comp);
                        if Self::wildcard_match(pat, &prefix) {
                            return true;
                        }
                    }
                } else if parts[..parts.len() - 1]
                    .iter()
                    .any(|c| Self::wildcard_match(pat, c))
                {
                    return true;
                }
            }
            return false;
        }

        if has_slash {
            if let Some(sub_pat) = pat.strip_prefix("**/") {
                if Self::wildcard_match(sub_pat, basename)
                    || Self::wildcard_match(sub_pat, norm_path)
                {
                    return true;
                }
            }
            Self::wildcard_match(pat, norm_path) || norm_path.starts_with(&format!("{pat}/"))
        } else {
            Self::wildcard_match(pat, basename)
                || Self::wildcard_match(pat, norm_path)
                || parts.iter().any(|c| Self::wildcard_match(pat, c))
        }
    }

    /// Wildcard matcher supporting `*` (0 or more chars) and `?` (single char).
    pub fn wildcard_match(pattern: &str, text: &str) -> bool {
        let p: Vec<char> = pattern.chars().collect();
        let t: Vec<char> = text.chars().collect();
        let (mut pi, mut ti) = (0usize, 0usize);
        let mut star_idx: Option<usize> = None;
        let mut match_idx = 0usize;

        while ti < t.len() {
            if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
                pi += 1;
                ti += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star_idx = Some(pi);
                match_idx = ti;
                pi += 1;
            } else if let Some(s_idx) = star_idx {
                pi = s_idx + 1;
                match_idx += 1;
                ti = match_idx;
            } else {
                return false;
            }
        }

        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }

        pi == p.len()
    }
}

/// Tombstone record tracking a file deleted from a synchronized folder across snapshot versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeletedFileTombstone {
    pub relative_path: String,
    pub deleted_at_version: u64,
    pub previous_merkle_root: Hash32,
}

/// Dry-run folder synchronization diff report (`diff-folder` / `watch-folder --dry-run`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderSyncDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: Vec<String>,
    pub ignored: Vec<String>,
    pub total_upload_bytes: u64,
}

/// Whether `relative_path` matches any selective-restore filter (exact path, basename or
/// directory prefix); an empty filter list matches everything.
pub fn matches_selective_filters(relative_path: &str, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    let normalized = relative_path.replace('\\', "/");
    let basename = normalized.rsplit('/').next().unwrap_or(&normalized);

    for raw_filter in filters {
        let f = raw_filter.trim().replace('\\', "/");
        if f.is_empty() {
            continue;
        }
        if f == normalized || f == basename {
            return true;
        }
        let dir_prefix = f.trim_end_matches('/');
        if normalized.starts_with(&format!("{dir_prefix}/")) {
            return true;
        }
        if ParvaultIgnore::wildcard_match(&f, &normalized)
            || ParvaultIgnore::wildcard_match(&f, basename)
        {
            return true;
        }
    }
    false
}
