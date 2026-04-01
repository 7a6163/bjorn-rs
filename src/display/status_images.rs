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
        let images = self
            .series
            .get(status)
            .or_else(|| self.series.get("IDLE"));

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
