use std::collections::HashMap;
use std::path::Path;

use image::GrayImage;
use rand::Rng;

/// Manages per-status character images for the bottom area of the display.
///
/// Ports Python's `image_series` — loads numbered BMP files from
/// `resources/images/status/{action_name}/` subdirectories and randomly
/// cycles through them based on the current orchestrator status.
pub struct StatusImages {
    /// Map from status name → list of character images
    series: HashMap<String, Vec<GrayImage>>,
    /// Map from status name → single status icon (used at y=60)
    status_icons: HashMap<String, GrayImage>,
    current_status: String,
    current_index: usize,
}

impl StatusImages {
    /// Load all status images from `status_dir` (e.g. `resources/images/status/`).
    /// Each subdirectory should be named after an action (e.g. `SSHBruteforce/`)
    /// and contain numbered BMP files (e.g. `SSHBruteforce1.bmp`).
    pub fn new(status_dir: &Path) -> Self {
        let mut series: HashMap<String, Vec<GrayImage>> = HashMap::new();
        let mut status_icons: HashMap<String, GrayImage> = HashMap::new();

        if let Ok(entries) = std::fs::read_dir(status_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let status_name = entry.file_name().to_string_lossy().to_string();

                // Load the main status icon: {status_name}/{status_name}.bmp
                let icon_path = path.join(format!("{status_name}.bmp"));
                if let Ok(img) = image::open(&icon_path) {
                    status_icons.insert(status_name.clone(), img.to_luma8());
                }

                // Load numbered character images: {status_name}/*{digit}*.bmp
                let mut images = Vec::new();
                if let Ok(files) = std::fs::read_dir(&path) {
                    for file in files.flatten() {
                        let fname = file.file_name().to_string_lossy().to_string();
                        if fname.ends_with(".bmp") && fname.chars().any(|c| c.is_ascii_digit()) {
                            // Skip the main status icon (exact name match)
                            if fname == format!("{status_name}.bmp") {
                                continue;
                            }
                            if let Ok(img) = image::open(file.path()) {
                                images.push(img.to_luma8());
                            }
                        }
                    }
                }

                if !images.is_empty() {
                    tracing::info!(status = %status_name, count = images.len(), "loaded character images");
                    series.insert(status_name, images);
                }
            }
        }

        tracing::info!(
            statuses = series.len(),
            icons = status_icons.len(),
            "status images loaded"
        );

        Self {
            series,
            status_icons,
            current_status: String::new(),
            current_index: 0,
        }
    }

    /// Get the status icon for the y=60 area (small icon next to action text).
    /// Falls back to the default "attack" icon via the static icons.
    pub fn status_icon(&self, status: &str) -> Option<&GrayImage> {
        self.status_icons.get(status)
    }

    /// Pick a character image for the bottom area based on current status.
    /// Randomly selects from the status's image series, falling back to IDLE.
    pub fn pick_character(&mut self, status: &str) -> Option<&GrayImage> {
        // If status changed, randomize
        if status != self.current_status {
            self.current_status = status.to_string();
            self.randomize(status);
        }

        self.get_current()
    }

    /// Advance to a new random image for the current status.
    pub fn randomize_current(&mut self) {
        let status = self.current_status.clone();
        self.randomize(&status);
    }

    fn randomize(&mut self, status: &str) {
        let images = self.series.get(status).or_else(|| self.series.get("IDLE"));

        if let Some(imgs) = images {
            if !imgs.is_empty() {
                let mut rng = rand::rng();
                self.current_index = rng.random_range(0..imgs.len());
            }
        }
    }

    fn get_current(&self) -> Option<&GrayImage> {
        let images = self
            .series
            .get(&self.current_status)
            .or_else(|| self.series.get("IDLE"));

        images.and_then(|imgs| imgs.get(self.current_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn new_with_nonexistent_directory_does_not_panic() {
        let si = StatusImages::new(Path::new("/tmp/bjorn_nonexistent_dir_12345"));
        assert!(si.series.is_empty());
        assert!(si.status_icons.is_empty());
    }

    #[test]
    fn pick_character_returns_none_when_no_images_loaded() {
        let mut si = StatusImages::new(Path::new("/tmp/bjorn_nonexistent_dir_12345"));
        let result = si.pick_character("IDLE");
        assert!(result.is_none());
    }

    #[test]
    fn status_icon_returns_none_for_unknown_status() {
        let si = StatusImages::new(Path::new("/tmp/bjorn_nonexistent_dir_12345"));
        assert!(si.status_icon("UnknownAction").is_none());
        assert!(si.status_icon("IDLE").is_none());
        assert!(si.status_icon("").is_none());
    }

    #[test]
    fn randomize_current_does_not_panic_on_empty_state() {
        let mut si = StatusImages::new(Path::new("/tmp/bjorn_nonexistent_dir_12345"));
        // Should not panic even with no images and empty current_status
        si.randomize_current();
        si.current_status = "SomeAction".to_string();
        si.randomize_current();
    }

    /// Helper to create a test BMP file at the given path.
    fn create_test_bmp(path: &std::path::Path) {
        image::GrayImage::from_pixel(10, 10, image::Luma([128u8]))
            .save(path)
            .expect("failed to save test BMP");
    }

    /// Helper that builds a status directory structure in a temp dir.
    /// Returns the temp dir (must be kept alive for the duration of the test).
    fn build_status_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let root = tmp.path();

        // Create "IDLE" status with icon + 2 numbered images
        let idle_dir = root.join("IDLE");
        std::fs::create_dir_all(&idle_dir).unwrap();
        create_test_bmp(&idle_dir.join("IDLE.bmp")); // status icon
        create_test_bmp(&idle_dir.join("IDLE1.bmp")); // character 1
        create_test_bmp(&idle_dir.join("IDLE2.bmp")); // character 2

        // Create "Attack" status with icon + 1 numbered image
        let attack_dir = root.join("Attack");
        std::fs::create_dir_all(&attack_dir).unwrap();
        create_test_bmp(&attack_dir.join("Attack.bmp")); // status icon
        create_test_bmp(&attack_dir.join("Attack1.bmp")); // character

        // Create "Empty" status with only a non-matching file (no digit)
        let empty_dir = root.join("Empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        create_test_bmp(&empty_dir.join("Empty.bmp")); // icon only, no numbered files

        tmp
    }

    #[test]
    fn new_loads_status_icons_from_subdirectories() {
        let tmp = build_status_dir();
        let si = StatusImages::new(tmp.path());

        assert!(
            si.status_icons.contains_key("IDLE"),
            "should load IDLE status icon"
        );
        assert!(
            si.status_icons.contains_key("Attack"),
            "should load Attack status icon"
        );
        assert!(
            si.status_icons.contains_key("Empty"),
            "should load Empty status icon"
        );
    }

    #[test]
    fn new_loads_numbered_character_images() {
        let tmp = build_status_dir();
        let si = StatusImages::new(tmp.path());

        assert_eq!(
            si.series.get("IDLE").map(|v| v.len()),
            Some(2),
            "IDLE should have 2 character images"
        );
        assert_eq!(
            si.series.get("Attack").map(|v| v.len()),
            Some(1),
            "Attack should have 1 character image"
        );
        assert!(
            si.series.get("Empty").is_none(),
            "Empty should have no character images (no numbered files)"
        );
    }

    #[test]
    fn status_icon_returns_correct_icon() {
        let tmp = build_status_dir();
        let si = StatusImages::new(tmp.path());

        let idle_icon = si.status_icon("IDLE");
        assert!(idle_icon.is_some(), "IDLE icon should exist");
        assert_eq!(idle_icon.unwrap().width(), 10);
        assert_eq!(idle_icon.unwrap().height(), 10);

        let attack_icon = si.status_icon("Attack");
        assert!(attack_icon.is_some(), "Attack icon should exist");

        assert!(
            si.status_icon("NonExistent").is_none(),
            "non-existent status should return None"
        );
    }

    #[test]
    fn pick_character_returns_image_when_available() {
        let tmp = build_status_dir();
        let mut si = StatusImages::new(tmp.path());

        let img = si.pick_character("IDLE");
        assert!(img.is_some(), "should return a character image for IDLE");
        assert_eq!(img.unwrap().width(), 10);
        assert_eq!(img.unwrap().height(), 10);
    }

    #[test]
    fn pick_character_falls_back_to_idle_for_unknown_status() {
        let tmp = build_status_dir();
        let mut si = StatusImages::new(tmp.path());

        let img = si.pick_character("CompletelyUnknown");
        assert!(
            img.is_some(),
            "unknown status should fall back to IDLE images"
        );
    }

    #[test]
    fn pick_character_returns_none_for_status_without_images_and_no_idle() {
        // Build a dir with only "Empty" (has icon but no numbered images)
        let tmp = tempfile::tempdir().unwrap();
        let empty_dir = tmp.path().join("Empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        create_test_bmp(&empty_dir.join("Empty.bmp"));

        let mut si = StatusImages::new(tmp.path());
        let img = si.pick_character("Empty");
        assert!(
            img.is_none(),
            "should return None when no character images and no IDLE fallback"
        );
    }

    #[test]
    fn pick_character_detects_status_change() {
        let tmp = build_status_dir();
        let mut si = StatusImages::new(tmp.path());

        // First call with IDLE
        let _ = si.pick_character("IDLE");
        assert_eq!(si.current_status, "IDLE");

        // Switch to Attack
        assert!(si.pick_character("Attack").is_some());
        assert_eq!(si.current_status, "Attack");

        // Switch back to IDLE
        assert!(si.pick_character("IDLE").is_some());
        assert_eq!(si.current_status, "IDLE");
    }

    #[test]
    fn randomize_current_changes_index_for_status_with_images() {
        let tmp = build_status_dir();
        let mut si = StatusImages::new(tmp.path());

        // Set current status to IDLE which has 2 images
        let _ = si.pick_character("IDLE");

        // Randomize many times — index should stay within bounds
        for _ in 0..20 {
            si.randomize_current();
            assert!(
                si.current_index < 2,
                "index should be within bounds of IDLE image count"
            );
        }
    }

    #[test]
    fn new_skips_files_in_root_directory() {
        let tmp = tempfile::tempdir().unwrap();
        // Place a BMP directly in root (not in a subdirectory)
        create_test_bmp(&tmp.path().join("stray.bmp"));

        let si = StatusImages::new(tmp.path());
        assert!(si.series.is_empty());
        assert!(si.status_icons.is_empty());
    }

    #[test]
    fn new_ignores_non_bmp_files_in_status_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let status_dir = tmp.path().join("TestStatus");
        std::fs::create_dir_all(&status_dir).unwrap();

        // Create a PNG file (should be ignored)
        image::GrayImage::from_pixel(10, 10, image::Luma([128u8]))
            .save(status_dir.join("TestStatus1.png"))
            .unwrap();

        // Create the icon as BMP
        create_test_bmp(&status_dir.join("TestStatus.bmp"));

        let si = StatusImages::new(tmp.path());
        assert!(
            si.series.get("TestStatus").is_none(),
            "PNG files should be ignored, only BMP counted"
        );
        assert!(
            si.status_icons.contains_key("TestStatus"),
            "icon should still be loaded"
        );
    }
}
