use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use ab_glyph::{FontRef, PxScale};
use image::{GrayImage, Luma, Pixel};
use imageproc::drawing::{draw_line_segment_mut, draw_text_mut};

use crate::config::BjornConfig;
use crate::state::{DisplayData, OrchestratorStatus};

use super::epd_v4::{EPD_HEIGHT, EPD_WIDTH};

const REF_WIDTH: f32 = 122.0;
const REF_HEIGHT: f32 = 250.0;
const BLACK: Luma<u8> = Luma([0u8]);
const WHITE: Luma<u8> = Luma([255u8]);

/// Embedded font (parsed once at startup via OnceLock).
const FONT_BYTES: &[u8] = include_bytes!("../../resources/fonts/DejaVuSansMono.ttf");
static FONT: OnceLock<FontRef<'static>> = OnceLock::new();

fn load_font() -> &'static FontRef<'static> {
    FONT.get_or_init(|| FontRef::try_from_slice(FONT_BYTES).expect("failed to load embedded font"))
}

/// BMP icon cache — loaded once from disk.
static ICONS: OnceLock<HashMap<String, GrayImage>> = OnceLock::new();

/// Load all BMP icons from the static images directory.
fn load_icons(static_dir: &Path) -> &'static HashMap<String, GrayImage> {
    ICONS.get_or_init(|| {
        let mut map = HashMap::new();
        let names = [
            "wifi", "usb", "connected", "bluetooth",
            "target", "port", "vuln", "cred", "data", "zombie",
            "money", "level", "networkkb", "attacks", "attack",
            "frise", "bjorn1", "gold",
        ];
        for name in &names {
            let path = static_dir.join(format!("{name}.bmp"));
            if let Ok(img) = image::open(&path) {
                map.insert(name.to_string(), img.to_luma8());
                tracing::debug!(icon = %name, "loaded BMP icon");
            }
        }
        tracing::info!(count = map.len(), "BMP icons loaded");
        map
    })
}

/// Paste a BMP icon onto the frame at the given position.
/// Converts non-white pixels to black (1-bit style).
fn paste_icon(frame: &mut GrayImage, icon: &GrayImage, x: u32, y: u32) {
    for iy in 0..icon.height() {
        for ix in 0..icon.width() {
            let px = icon.get_pixel(ix, iy).channels()[0];
            let fx = x + ix;
            let fy = y + iy;
            if fx < frame.width() && fy < frame.height() && px < 200 {
                frame.put_pixel(fx, fy, BLACK);
            }
        }
    }
}

/// Render a complete display frame matching the Python `display.py` layout.
///
/// Uses BMP icons from `$BJORN_ROOT/resources/images/static/` when available,
/// falls back to text labels when icons are not found.
pub fn render_frame(
    display: &DisplayData,
    status: &OrchestratorStatus,
    config: &BjornConfig,
    static_images_dir: &Path,
) -> GrayImage {
    let width = EPD_WIDTH;
    let height = EPD_HEIGHT;
    let sx = width as f32 / REF_WIDTH;
    let sy = height as f32 / REF_HEIGHT;

    let mut img = GrayImage::from_pixel(width, height, WHITE);
    let font: &FontRef = load_font();

    let scale_9 = PxScale::from(9.0 * sy);
    let scale_12 = PxScale::from(12.0 * sy);
    let scale_13 = PxScale::from(13.0 * sy);

    // Load icons (uses OnceLock, only loads once)
    let icons = load_icons(static_images_dir);

    // -- Border + dividers (drawn last in Python, but same result) --
    draw_rect_outline(&mut img, 1, 1, width - 2, height - 2);
    draw_hline(&mut img, 1, width - 2, s(20, sy));
    draw_hline(&mut img, 1, width - 2, s(59, sy));
    draw_hline(&mut img, 1, width - 2, s(87, sy));

    // -- Title: "BJORN" --
    draw_text_mut(&mut img, BLACK, s(37, sx) as i32, s(5, sy) as i32, scale_13, font, "BJORN");

    // -- Connection indicators (top bar) --
    if display.wifi_connected {
        paste_or_text(&mut img, icons, "wifi", s(3, sx), s(3, sy), font, scale_9, "W");
    }
    if display.usb_active {
        paste_or_text(&mut img, icons, "usb", s(90, sx), s(4, sy), font, scale_9, "U");
    }

    // -- Manual/Auto mode --
    let mode_txt = if status.manual_mode { "M" } else { "A" };
    draw_text_mut(&mut img, BLACK, s(110, sx) as i32, s(5, sy) as i32, scale_9, font, mode_txt);

    // -- Stats: icon at img_pos, text at text_pos --
    // Matches Python display.py lines 300-310 exactly
    let stats: Vec<(&str, u32, u32, u32, u32, String)> = vec![
        // (icon_name, icon_x, icon_y, text_x, text_y, value)
        ("target",    8,  22, 28,  22, display.target_count.to_string()),
        ("port",     47,  22, 67,  22, display.port_count.to_string()),
        ("vuln",     86,  22, 106, 22, display.vuln_count.to_string()),
        ("cred",      8,  41, 28,  41, display.cred_count.to_string()),
        ("zombie",   47,  41, 67,  41, display.zombie_count.to_string()),
        ("data",     86,  41, 106, 41, display.data_count.to_string()),
    ];

    for (icon_name, ix, iy, tx, ty, value) in &stats {
        paste_or_text(&mut img, icons, icon_name, s(*ix, sx), s(*iy, sy), font, scale_9, icon_name);
        draw_text_mut(&mut img, BLACK, s(*tx, sx) as i32, s(*ty, sy) as i32, scale_9, font, value);
    }

    // -- Bottom stats: money, level, networkkb, attacks --
    paste_or_text(&mut img, icons, "money", s(3, sx), s(172, sy), font, scale_9, "$");
    draw_text_mut(&mut img, BLACK, s(3, sx) as i32, s(192, sy) as i32, scale_9, font, &display.coin_count.to_string());

    paste_or_text(&mut img, icons, "level", s(2, sx), s(217, sy), font, scale_9, "L");
    draw_text_mut(&mut img, BLACK, s(4, sx) as i32, s(237, sy) as i32, scale_9, font, &display.level.to_string());

    paste_or_text(&mut img, icons, "networkkb", s(102, sx), s(190, sy), font, scale_9, "KB");
    draw_text_mut(&mut img, BLACK, s(102, sx) as i32, s(208, sy) as i32, scale_9, font, &display.network_kb_count.to_string());

    paste_or_text(&mut img, icons, "attacks", s(100, sx), s(218, sy), font, scale_9, "A");
    draw_text_mut(&mut img, BLACK, s(102, sx) as i32, s(237, sy) as i32, scale_9, font, &display.attack_count.to_string());

    // -- Status area (y=60-87): action icon + text --
    let action_text = if status.current_action.is_empty() {
        "IDLE"
    } else {
        &status.current_action
    };
    paste_or_text(&mut img, icons, "attack", s(3, sx), s(60, sy), font, scale_9, ">");
    draw_text_mut(&mut img, BLACK, s(35, sx) as i32, s(65, sy) as i32, scale_9, font, action_text);
    if !status.detail.is_empty() {
        draw_text_mut(&mut img, BLACK, s(35, sx) as i32, s(75, sy) as i32, scale_9, font, &status.detail);
    }

    // -- Frise (decorative line) at y=160 --
    if let Some(frise) = icons.get("frise") {
        paste_icon(&mut img, frise, 0, s(160, sy));
    } else {
        draw_hline(&mut img, 0, width - 1, s(160, sy));
    }

    // -- Comment area (y=88-160) --
    let comment = if display.bjorn_says.is_empty() {
        "Hacking away..."
    } else {
        &display.bjorn_says
    };
    let wrapped = wrap_text(comment, 18);
    let mut y_text = s(90, sy) as i32;
    for line in &wrapped {
        draw_text_mut(&mut img, BLACK, s(4, sx) as i32, y_text, scale_12, font, line);
        y_text += (12.0 * sy) as i32 + 3;
        if y_text > s(155, sy) as i32 {
            break;
        }
    }

    // -- Bjorn character image (bottom, centered) --
    if let Some(bjorn) = icons.get("bjorn1") {
        let x_center = (width - bjorn.width()) / 2;
        let y_bottom = height - bjorn.height();
        paste_icon(&mut img, bjorn, x_center, y_bottom);
    }

    img
}

// -- Helpers --

fn s(val: u32, scale: f32) -> u32 {
    (val as f32 * scale) as u32
}

/// Paste an icon if available, otherwise draw a text fallback.
fn paste_or_text(
    img: &mut GrayImage,
    icons: &HashMap<String, GrayImage>,
    icon_name: &str,
    x: u32,
    y: u32,
    font: &FontRef,
    scale: PxScale,
    fallback_text: &str,
) {
    if let Some(icon) = icons.get(icon_name) {
        paste_icon(img, icon, x, y);
    } else {
        draw_text_mut(img, BLACK, x as i32, y as i32, scale, font, fallback_text);
    }
}

fn draw_hline(img: &mut GrayImage, x1: u32, x2: u32, y: u32) {
    draw_line_segment_mut(img, (x1 as f32, y as f32), (x2 as f32, y as f32), BLACK);
}

fn draw_rect_outline(img: &mut GrayImage, x: u32, y: u32, w: u32, h: u32) {
    draw_hline(img, x, x + w, y);
    draw_hline(img, x, x + w, y + h);
    draw_line_segment_mut(img, (x as f32, y as f32), (x as f32, (y + h) as f32), BLACK);
    draw_line_segment_mut(img, ((x + w) as f32, y as f32), ((x + w) as f32, (y + h) as f32), BLACK);
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > max_chars && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BjornConfig;
    use crate::state::{DisplayData, OrchestratorStatus};

    #[test]
    fn render_produces_correct_size() {
        let display = DisplayData::default();
        let status = OrchestratorStatus::default();
        let config = BjornConfig::default();
        let tmp = std::path::PathBuf::from("/tmp/nonexistent");
        let img = render_frame(&display, &status, &config, &tmp);
        assert_eq!(img.width(), EPD_WIDTH);
        assert_eq!(img.height(), EPD_HEIGHT);
    }

    #[test]
    fn wrap_text_basic() {
        let lines = wrap_text("Hello world this is a test", 10);
        assert_eq!(lines, vec!["Hello", "world this", "is a test"]);
    }
}
