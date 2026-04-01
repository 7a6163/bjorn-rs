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
/// Preserves original grayscale values so dithering can produce gradients.
fn paste_icon(frame: &mut GrayImage, icon: &GrayImage, x: u32, y: u32) {
    for iy in 0..icon.height() {
        for ix in 0..icon.width() {
            let px = icon.get_pixel(ix, iy).channels()[0];
            let fx = x + ix;
            let fy = y + iy;
            if fx < frame.width() && fy < frame.height() && px < 250 {
                frame.put_pixel(fx, fy, Luma([px]));
            }
        }
    }
}

/// Two-layer rendering result.
/// - `icons`: grayscale layer with icons (will be dithered)
/// - `text_mask`: 1-bit mask where black pixels = text/lines (stays crisp)
pub struct RenderedFrame {
    pub icons: GrayImage,
    pub text_mask: GrayImage,
}

/// Render a complete display frame matching the Python `display.py` layout.
///
/// Returns two layers: an icon layer (grayscale, for dithering) and a text
/// mask (crisp black/white). The caller composites them so icons get gradients
/// while text stays sharp — matching Python PIL's 1-bit text behavior.
///
/// `character_img` — optional animated character image for the bottom area
/// (loaded from status image series). Falls back to static `bjorn1.bmp`.
///
/// `status_icon` — optional per-action icon for the y=60 status area.
/// Falls back to the static `attack.bmp` icon.
pub fn render_frame(
    display: &DisplayData,
    status: &OrchestratorStatus,
    config: &BjornConfig,
    static_images_dir: &Path,
    character_img: Option<&GrayImage>,
    status_icon: Option<&GrayImage>,
) -> RenderedFrame {
    let width = EPD_WIDTH;
    let height = EPD_HEIGHT;
    let sx = width as f32 / REF_WIDTH;
    let sy = height as f32 / REF_HEIGHT;

    let mut icon_layer = GrayImage::from_pixel(width, height, WHITE);
    let mut text_layer = GrayImage::from_pixel(width, height, WHITE);
    let font: &FontRef = load_font();

    let scale_9 = PxScale::from(9.0 * sy);
    let scale_12 = PxScale::from(12.0 * sy);
    let scale_13 = PxScale::from(13.0 * sy);

    // Load icons (uses OnceLock, only loads once)
    let icons = load_icons(static_images_dir);

    // -- Border + dividers → text layer (crisp lines) --
    draw_rect_outline(&mut text_layer, 1, 1, width - 2, height - 2);
    draw_hline(&mut text_layer, 1, width - 2, s(20, sy));
    draw_hline(&mut text_layer, 1, width - 2, s(59, sy));
    draw_hline(&mut text_layer, 1, width - 2, s(87, sy));

    // -- Title: "BJORN" → text layer --
    draw_text_mut(&mut text_layer, BLACK, s(37, sx) as i32, s(5, sy) as i32, scale_13, font, "BJORN");

    // -- Connection indicators (top bar) --
    if display.wifi_connected {
        paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "wifi", s(3, sx), s(3, sy), font, scale_9, "W");
    }
    if display.usb_active {
        paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "usb", s(90, sx), s(4, sy), font, scale_9, "U");
    }

    // -- PAN connected indicator (top bar, right side) --
    if display.pan_connected {
        paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "connected", s(104, sx), s(3, sy), font, scale_9, "P");
    }

    // -- Manual/Auto mode → text layer --
    let mode_txt = if status.manual_mode { "M" } else { "A" };
    draw_text_mut(&mut text_layer, BLACK, s(110, sx) as i32, s(5, sy) as i32, scale_9, font, mode_txt);

    // -- Stats: icon at img_pos, text at text_pos --
    let stats: Vec<(&str, u32, u32, u32, u32, String)> = vec![
        ("target",    8,  22, 28,  22, display.target_count.to_string()),
        ("port",     47,  22, 67,  22, display.port_count.to_string()),
        ("vuln",     86,  22, 106, 22, display.vuln_count.to_string()),
        ("cred",      8,  41, 28,  41, display.cred_count.to_string()),
        ("zombie",   47,  41, 67,  41, display.zombie_count.to_string()),
        ("data",     86,  41, 106, 41, display.data_count.to_string()),
    ];

    for (icon_name, ix, iy, tx, ty, value) in &stats {
        paste_or_text_split(&mut icon_layer, &mut text_layer, icons, icon_name, s(*ix, sx), s(*iy, sy), font, scale_9, icon_name);
        draw_text_mut(&mut text_layer, BLACK, s(*tx, sx) as i32, s(*ty, sy) as i32, scale_9, font, value);
    }

    // -- Bottom stats: money, level, networkkb, attacks --
    paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "money", s(3, sx), s(172, sy), font, scale_9, "$");
    draw_text_mut(&mut text_layer, BLACK, s(3, sx) as i32, s(192, sy) as i32, scale_9, font, &display.coin_count.to_string());

    paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "level", s(2, sx), s(217, sy), font, scale_9, "L");
    draw_text_mut(&mut text_layer, BLACK, s(4, sx) as i32, s(237, sy) as i32, scale_9, font, &display.level.to_string());

    paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "networkkb", s(102, sx), s(190, sy), font, scale_9, "KB");
    draw_text_mut(&mut text_layer, BLACK, s(102, sx) as i32, s(208, sy) as i32, scale_9, font, &display.network_kb_count.to_string());

    paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "attacks", s(100, sx), s(218, sy), font, scale_9, "A");
    draw_text_mut(&mut text_layer, BLACK, s(102, sx) as i32, s(237, sy) as i32, scale_9, font, &display.attack_count.to_string());

    // -- Status area (y=60-87): action icon + text --
    let action_text = if status.current_action.is_empty() {
        "IDLE"
    } else {
        &status.current_action
    };
    // Use per-action status icon if available, otherwise fall back to static "attack" icon
    if let Some(si) = status_icon {
        paste_icon(&mut icon_layer, si, s(3, sx), s(60, sy));
    } else {
        paste_or_text_split(&mut icon_layer, &mut text_layer, icons, "attack", s(3, sx), s(60, sy), font, scale_9, ">");
    }
    draw_text_mut(&mut text_layer, BLACK, s(35, sx) as i32, s(65, sy) as i32, scale_9, font, action_text);
    if !status.detail.is_empty() {
        draw_text_mut(&mut text_layer, BLACK, s(35, sx) as i32, s(75, sy) as i32, scale_9, font, &status.detail);
    }

    // -- Frise (decorative line) at y=160 → icon layer (may have gradients) --
    if let Some(frise) = icons.get("frise") {
        paste_icon(&mut icon_layer, frise, 0, s(160, sy));
    } else {
        draw_hline(&mut text_layer, 0, width - 1, s(160, sy));
    }

    // -- Comment area (y=88-160) → text layer --
    let comment = if display.bjorn_says.is_empty() {
        "Hacking away..."
    } else {
        &display.bjorn_says
    };
    let wrapped = wrap_text(comment, 18);
    let mut y_text = s(90, sy) as i32;
    for line in &wrapped {
        draw_text_mut(&mut text_layer, BLACK, s(4, sx) as i32, y_text, scale_12, font, line);
        y_text += (12.0 * sy) as i32 + 3;
        if y_text > s(155, sy) as i32 {
            break;
        }
    }

    // -- Bjorn character image (bottom, centered) → icon layer --
    // Use animated character image if available, otherwise fall back to static bjorn1.bmp
    let char_img = character_img.or_else(|| icons.get("bjorn1"));
    if let Some(img) = char_img {
        let x_center = (width - img.width()) / 2;
        let y_bottom = height - img.height();
        paste_icon(&mut icon_layer, img, x_center, y_bottom);
    }

    RenderedFrame {
        icons: icon_layer,
        text_mask: text_layer,
    }
}

/// Flatten a `RenderedFrame` into a single grayscale image for PNG output.
/// Text is rendered as crisp black on top of the icon layer.
pub fn flatten_for_png(frame: &RenderedFrame) -> GrayImage {
    let width = frame.icons.width();
    let height = frame.icons.height();
    let mut out = frame.icons.clone();

    for y in 0..height {
        for x in 0..width {
            let text_px = frame.text_mask.get_pixel(x, y).0[0];
            // Text mask: anything below 128 is text → force black
            if text_px < 128 {
                out.put_pixel(x, y, BLACK);
            }
        }
    }
    out
}

// -- Helpers --

fn s(val: u32, scale: f32) -> u32 {
    (val as f32 * scale) as u32
}

/// Route to icon layer (grayscale) or text layer (crisp) depending on availability.
fn paste_or_text_split(
    icon_layer: &mut GrayImage,
    text_layer: &mut GrayImage,
    icons: &HashMap<String, GrayImage>,
    icon_name: &str,
    x: u32,
    y: u32,
    font: &FontRef,
    scale: PxScale,
    fallback_text: &str,
) {
    if let Some(icon) = icons.get(icon_name) {
        paste_icon(icon_layer, icon, x, y);
    } else {
        draw_text_mut(text_layer, BLACK, x as i32, y as i32, scale, font, fallback_text);
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
        let frame = render_frame(&display, &status, &config, &tmp, None, None);
        assert_eq!(frame.icons.width(), EPD_WIDTH);
        assert_eq!(frame.icons.height(), EPD_HEIGHT);
        assert_eq!(frame.text_mask.width(), EPD_WIDTH);
        assert_eq!(frame.text_mask.height(), EPD_HEIGHT);
    }

    #[test]
    fn wrap_text_basic() {
        let lines = wrap_text("Hello world this is a test", 10);
        assert_eq!(lines, vec!["Hello", "world this", "is a test"]);
    }

    #[test]
    fn flatten_preserves_text() {
        let width = 10;
        let height = 10;
        let icons = GrayImage::from_pixel(width, height, WHITE);
        let mut text_mask = GrayImage::from_pixel(width, height, WHITE);
        // Draw a black text pixel
        text_mask.put_pixel(5, 5, BLACK);

        let frame = RenderedFrame { icons, text_mask };
        let flat = flatten_for_png(&frame);
        assert_eq!(flat.get_pixel(5, 5).0[0], 0); // text pixel stays black
        assert_eq!(flat.get_pixel(0, 0).0[0], 255); // background stays white
    }
}
