use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use rand::Rng;

/// Provides context-based random comments for Bjorn's speech bubble.
///
/// Ports Python `comment.py` — loads themed comments from `comments.json`
/// and returns a random one when the theme changes or a delay expires.
pub struct CommentEngine {
    themes: HashMap<String, Vec<String>>,
    last_theme: String,
    last_comment_time: Instant,
    comment_delay_min: u64,
    comment_delay_max: u64,
    current_delay: u64,
}

impl CommentEngine {
    pub fn new(comments_json: &Path, delay_min: u64, delay_max: u64) -> Self {
        let themes = load_comments(comments_json);
        let mut rng = rand::rng();
        let current_delay = rng.random_range(delay_min..=delay_max);

        Self {
            themes,
            last_theme: String::new(),
            last_comment_time: Instant::now(),
            comment_delay_min: delay_min,
            comment_delay_max: delay_max,
            current_delay,
        }
    }

    /// Get a comment for the given status theme.
    /// Returns `Some(comment)` when the theme changes or the delay has expired.
    /// Returns `None` if it's too soon for a new comment.
    pub fn get_comment(&mut self, theme: &str) -> Option<String> {
        let elapsed = self.last_comment_time.elapsed().as_secs();
        let theme_changed = theme != self.last_theme;

        if !theme_changed && elapsed < self.current_delay {
            return None;
        }

        self.last_comment_time = Instant::now();
        self.last_theme = theme.to_string();

        let mut rng = rand::rng();
        self.current_delay = rng.random_range(self.comment_delay_min..=self.comment_delay_max);

        // Look up theme, fall back to IDLE
        let comments = self.themes.get(theme).or_else(|| self.themes.get("IDLE"));

        match comments {
            Some(list) if !list.is_empty() => {
                let idx = rng.random_range(0..list.len());
                Some(list[idx].clone())
            }
            _ => Some("Hacking away...".to_string()),
        }
    }
}

/// Load comments from a JSON file. Returns empty map on error.
fn load_comments(path: &Path) -> HashMap<String, Vec<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(map) => {
                tracing::info!("comments loaded from {}", path.display());
                map
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse comments.json");
                default_comments()
            }
        },
        Err(e) => {
            tracing::warn!(%e, path = %path.display(), "failed to read comments.json");
            default_comments()
        }
    }
}

fn default_comments() -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    map.insert(
        "IDLE".to_string(),
        vec!["Hacking away...".to_string(), "Zzzz...".to_string()],
    );
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn get_comment_returns_on_theme_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comments.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{"IDLE":["idle1","idle2"],"NetworkScanner":["scan1"]}}"#
        )
        .unwrap();

        let mut engine = CommentEngine::new(&path, 5, 10);
        let c1 = engine.get_comment("IDLE");
        assert!(c1.is_some());

        // Same theme, within delay → None
        let c2 = engine.get_comment("IDLE");
        assert!(c2.is_none());

        // Different theme → Some
        let c3 = engine.get_comment("NetworkScanner");
        assert!(c3.is_some());
        assert_eq!(c3.unwrap(), "scan1");
    }

    #[test]
    fn load_from_missing_file_returns_default_comments() {
        let path = Path::new("/tmp/nonexistent_bjorn_comments_12345.json");
        let engine = CommentEngine::new(path, 1, 2);

        // Should have the default IDLE theme
        assert!(engine.themes.contains_key("IDLE"));
        let idle = engine.themes.get("IDLE").unwrap();
        assert!(idle.contains(&"Hacking away...".to_string()));
        assert!(idle.contains(&"Zzzz...".to_string()));
    }

    #[test]
    fn load_from_invalid_json_returns_default_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comments.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "this is not valid json {{{{").unwrap();

        let engine = CommentEngine::new(&path, 1, 2);

        assert!(engine.themes.contains_key("IDLE"));
        let idle = engine.themes.get("IDLE").unwrap();
        assert_eq!(idle.len(), 2);
    }

    #[test]
    fn idle_fallback_when_theme_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comments.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, r#"{{"IDLE":["idle_comment"]}}"#).unwrap();

        let mut engine = CommentEngine::new(&path, 1, 2);
        let comment = engine.get_comment("NonExistentTheme");

        assert!(comment.is_some());
        assert_eq!(comment.unwrap(), "idle_comment");
    }

    #[test]
    fn multiple_calls_within_delay_return_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comments.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, r#"{{"IDLE":["idle1"]}}"#).unwrap();

        // Use a large delay so calls within the window always return None
        let mut engine = CommentEngine::new(&path, 3600, 3600);

        // First call returns a comment
        let c1 = engine.get_comment("IDLE");
        assert!(c1.is_some());

        // Subsequent calls with same theme within delay return None
        assert!(engine.get_comment("IDLE").is_none());
        assert!(engine.get_comment("IDLE").is_none());
        assert!(engine.get_comment("IDLE").is_none());
    }
}
