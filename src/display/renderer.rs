use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use ab_glyph::{FontRef, PxScale};
use image::{GrayImage, Luma, Pixel};
use imageproc::drawing::{draw_line_segment_mut, draw_text_mut};

use crate::config::BjornConfig;
use crate::state::{DisplayData, OrchestratorStatus};

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
            "wifi",
            "usb",
            "connected",
            "bluetooth",
            "target",
            "port",
            "vuln",
            "cred",
            "data",
            "zombie",
            "money",
            "level",
            "networkkb",
            "attacks",
            "attack",
            "frise",
            "bjorn1",
            "gold",
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

/// Paste a BMP icon preserving grayscale values for dithering.
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
/// - `icons`: grayscale layer with icons (will be dithered for gradients)
/// - `text_mask`: pure 1-bit layer with text/lines (stays crisp, no dithering)
pub struct RenderedFrame {
    pub icons: GrayImage,
    pub text_mask: GrayImage,
}

/// Render a complete display frame in two layers:
/// - Icon layer: grayscale (caller applies Floyd-Steinberg dithering)
/// - Text layer: pure 1-bit black/white (crisp, no anti-aliasing artifacts)
///
/// This matches Python PIL's behavior: `image.paste()` auto-dithers icons
/// when pasting onto mode '1', while `draw.text()` is inherently 1-bit.
pub fn render_frame(
    display: &DisplayData,
    status: &OrchestratorStatus,
    _config: &BjornConfig,
    static_images_dir: &Path,
    character_img: Option<&GrayImage>,
    status_icon: Option<&GrayImage>,
    epd_width: u32,
    epd_height: u32,
) -> RenderedFrame {
    let width = epd_width;
    let height = epd_height;
    let sx = width as f32 / REF_WIDTH;
    let sy = height as f32 / REF_HEIGHT;

    let mut icon_layer = GrayImage::from_pixel(width, height, WHITE);
    let mut text_layer = GrayImage::from_pixel(width, height, WHITE);
    let font: &FontRef = load_font();

    // Font sizes — bumped from Python's 9/12/13 to compensate for
    // ab_glyph rendering smaller than PIL at the same nominal size.
    let scale_9 = PxScale::from(11.0 * sy);
    let scale_12 = PxScale::from(14.0 * sy);
    let scale_13 = PxScale::from(15.0 * sy);

    let icons = load_icons(static_images_dir);

    // -- Title: "BJORN" → text layer --
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(37, sx) as i32,
        s(5, sy) as i32,
        scale_13,
        font,
        "BJORN",
    );

    // -- Connection indicators --
    if display.wifi_connected {
        paste_or_text_split(
            &mut icon_layer,
            &mut text_layer,
            icons,
            "wifi",
            s(3, sx),
            s(3, sy),
            font,
            scale_9,
            "W",
        );
    }
    if display.usb_active {
        paste_or_text_split(
            &mut icon_layer,
            &mut text_layer,
            icons,
            "usb",
            s(90, sx),
            s(4, sy),
            font,
            scale_9,
            "U",
        );
    }
    if display.pan_connected {
        paste_or_text_split(
            &mut icon_layer,
            &mut text_layer,
            icons,
            "connected",
            s(104, sx),
            s(3, sy),
            font,
            scale_9,
            "P",
        );
    }

    // -- Manual/Auto mode → text layer --
    let mode_txt = if status.manual_mode { "M" } else { "A" };
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(110, sx) as i32,
        s(5, sy) as i32,
        scale_9,
        font,
        mode_txt,
    );

    // -- Stats --
    let stats: Vec<(&str, u32, u32, u32, u32, String)> = vec![
        ("target", 8, 22, 28, 22, display.target_count.to_string()),
        ("port", 47, 22, 67, 22, display.port_count.to_string()),
        ("vuln", 86, 22, 106, 22, display.vuln_count.to_string()),
        ("cred", 8, 41, 28, 41, display.cred_count.to_string()),
        ("zombie", 47, 41, 67, 41, display.zombie_count.to_string()),
        ("data", 86, 41, 106, 41, display.data_count.to_string()),
    ];

    for (icon_name, ix, iy, tx, ty, value) in &stats {
        paste_or_text_split(
            &mut icon_layer,
            &mut text_layer,
            icons,
            icon_name,
            s(*ix, sx),
            s(*iy, sy),
            font,
            scale_9,
            icon_name,
        );
        draw_text_mut(
            &mut text_layer,
            BLACK,
            s(*tx, sx) as i32,
            s(*ty, sy) as i32,
            scale_9,
            font,
            value,
        );
    }

    // -- Bottom stats --
    paste_or_text_split(
        &mut icon_layer,
        &mut text_layer,
        icons,
        "money",
        s(3, sx),
        s(172, sy),
        font,
        scale_9,
        "$",
    );
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(3, sx) as i32,
        s(192, sy) as i32,
        scale_9,
        font,
        &display.coin_count.to_string(),
    );

    paste_or_text_split(
        &mut icon_layer,
        &mut text_layer,
        icons,
        "level",
        s(2, sx),
        s(217, sy),
        font,
        scale_9,
        "L",
    );
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(4, sx) as i32,
        s(237, sy) as i32,
        scale_9,
        font,
        &display.level.to_string(),
    );

    // networkkb: same row as money (y=172)
    paste_or_text_split(
        &mut icon_layer,
        &mut text_layer,
        icons,
        "networkkb",
        s(102, sx),
        s(172, sy),
        font,
        scale_9,
        "KB",
    );
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(102, sx) as i32,
        s(190, sy) as i32,
        scale_9,
        font,
        &display.network_kb_count.to_string(),
    );

    // attacks: same row as level (y=217)
    paste_or_text_split(
        &mut icon_layer,
        &mut text_layer,
        icons,
        "attacks",
        s(100, sx),
        s(217, sy),
        font,
        scale_9,
        "A",
    );
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(102, sx) as i32,
        s(235, sy) as i32,
        scale_9,
        font,
        &display.attack_count.to_string(),
    );

    // -- Status area (y=60-87) --
    let action_text = if status.current_action.is_empty() {
        "IDLE"
    } else {
        &status.current_action
    };
    if let Some(si) = status_icon {
        paste_icon(&mut icon_layer, si, s(3, sx), s(60, sy));
    } else {
        paste_or_text_split(
            &mut icon_layer,
            &mut text_layer,
            icons,
            "attack",
            s(3, sx),
            s(60, sy),
            font,
            scale_9,
            ">",
        );
    }
    draw_text_mut(
        &mut text_layer,
        BLACK,
        s(35, sx) as i32,
        s(65, sy) as i32,
        scale_9,
        font,
        action_text,
    );
    if !status.detail.is_empty() {
        draw_text_mut(
            &mut text_layer,
            BLACK,
            s(35, sx) as i32,
            s(75, sy) as i32,
            scale_9,
            font,
            &status.detail,
        );
    }

    // -- Frise at y=160 --
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
        draw_text_mut(
            &mut text_layer,
            BLACK,
            s(4, sx) as i32,
            y_text,
            scale_12,
            font,
            line,
        );
        y_text += (12.0 * sy) as i32 + 3;
        if y_text > s(155, sy) as i32 {
            break;
        }
    }

    // -- Character image (bottom, centered) → icon layer --
    let char_img = character_img.or_else(|| icons.get("bjorn1"));
    if let Some(cimg) = char_img {
        let x_center = (width - cimg.width()) / 2;
        let y_bottom = height - cimg.height();
        paste_icon(&mut icon_layer, cimg, x_center, y_bottom);
    }

    // -- Border + dividers → text layer (crisp lines) --
    draw_rect_outline(&mut text_layer, 1, 1, width - 2, height - 2);
    draw_hline(&mut text_layer, 1, width - 2, s(20, sy));
    draw_hline(&mut text_layer, 1, width - 2, s(59, sy));
    draw_hline(&mut text_layer, 1, width - 2, s(87, sy));

    // Snap text layer to pure 1-bit: threshold at 128 removes anti-aliased
    // gray edges from imageproc. Every pixel becomes either 0 or 255.
    for pixel in text_layer.pixels_mut() {
        pixel.0[0] = if pixel.0[0] < 128 { 0 } else { 255 };
    }

    RenderedFrame {
        icons: icon_layer,
        text_mask: text_layer,
    }
}

/// Flatten for PNG output (web UI). Dithers icons, stamps crisp text on top.
pub fn flatten_for_png(frame: &RenderedFrame) -> GrayImage {
    let width = frame.icons.width();
    let height = frame.icons.height();
    let mut out = frame.icons.clone();

    // Overlay text mask: where text is black, force output to black
    for y in 0..height {
        for x in 0..width {
            if frame.text_mask.get_pixel(x, y).0[0] == 0 {
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
        draw_text_mut(
            text_layer,
            BLACK,
            x as i32,
            y as i32,
            scale,
            font,
            fallback_text,
        );
    }
}

fn draw_hline(img: &mut GrayImage, x1: u32, x2: u32, y: u32) {
    draw_line_segment_mut(img, (x1 as f32, y as f32), (x2 as f32, y as f32), BLACK);
}

fn draw_rect_outline(img: &mut GrayImage, x: u32, y: u32, w: u32, h: u32) {
    draw_hline(img, x, x + w, y);
    draw_hline(img, x, x + w, y + h);
    draw_line_segment_mut(img, (x as f32, y as f32), (x as f32, (y + h) as f32), BLACK);
    draw_line_segment_mut(
        img,
        ((x + w) as f32, y as f32),
        ((x + w) as f32, (y + h) as f32),
        BLACK,
    );
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
        let frame = render_frame(&display, &status, &config, &tmp, None, None, 122, 250);
        assert_eq!(frame.icons.width(), 122);
        assert_eq!(frame.icons.height(), 250);
        assert_eq!(frame.text_mask.width(), 122);
        assert_eq!(frame.text_mask.height(), 250);
    }

    #[test]
    fn text_mask_is_pure_1bit() {
        let display = DisplayData::default();
        let status = OrchestratorStatus::default();
        let config = BjornConfig::default();
        let tmp = std::path::PathBuf::from("/tmp/nonexistent");
        let frame = render_frame(&display, &status, &config, &tmp, None, None, 122, 250);
        for pixel in frame.text_mask.pixels() {
            assert!(
                pixel.0[0] == 0 || pixel.0[0] == 255,
                "text_mask has gray pixel: {}",
                pixel.0[0]
            );
        }
    }

    #[test]
    fn wrap_text_basic() {
        let lines = wrap_text("Hello world this is a test", 10);
        assert_eq!(lines, vec!["Hello", "world this", "is a test"]);
    }

    // -- paste_icon tests --

    #[test]
    fn paste_icon_copies_dark_pixels() {
        let mut frame = GrayImage::from_pixel(10, 10, WHITE);
        // Create a 3x3 icon with a dark center pixel and white border
        let mut icon = GrayImage::from_pixel(3, 3, WHITE);
        icon.put_pixel(1, 1, Luma([0u8])); // black center
        icon.put_pixel(0, 0, Luma([100u8])); // dark corner

        paste_icon(&mut frame, &icon, 2, 3);

        // Dark pixels should be copied
        assert_eq!(
            frame.get_pixel(3, 4).0[0],
            0,
            "black center should be pasted"
        );
        assert_eq!(
            frame.get_pixel(2, 3).0[0],
            100,
            "dark corner should be pasted"
        );
        // White/near-white pixels (>=250) should NOT be copied (stay white)
        assert_eq!(
            frame.get_pixel(4, 3).0[0],
            255,
            "white icon pixel should not overwrite frame"
        );
        // Pixels outside the icon area should remain white
        assert_eq!(
            frame.get_pixel(0, 0).0[0],
            255,
            "untouched pixel stays white"
        );
    }

    #[test]
    fn paste_icon_boundary_no_panic() {
        // Icon extends beyond the frame — should silently clip, not panic
        let mut frame = GrayImage::from_pixel(5, 5, WHITE);
        let icon = GrayImage::from_pixel(10, 10, Luma([50u8]));

        paste_icon(&mut frame, &icon, 3, 3);

        // Only the portion that fits (3..5, 3..5) should be written
        assert_eq!(frame.get_pixel(3, 3).0[0], 50);
        assert_eq!(frame.get_pixel(4, 4).0[0], 50);
        // Pixels before the paste origin remain white
        assert_eq!(frame.get_pixel(0, 0).0[0], 255);
    }

    #[test]
    fn paste_icon_fully_outside_frame() {
        let mut frame = GrayImage::from_pixel(5, 5, WHITE);
        let icon = GrayImage::from_pixel(3, 3, Luma([0u8]));

        // Paste at position beyond frame dimensions — nothing written, no panic
        paste_icon(&mut frame, &icon, 100, 100);

        for pixel in frame.pixels() {
            assert_eq!(pixel.0[0], 255, "frame should be untouched");
        }
    }

    // -- flatten_for_png tests --

    #[test]
    fn flatten_for_png_text_overrides_icons() {
        let width = 10;
        let height = 10;
        // Icon layer: mid-gray everywhere
        let icons = GrayImage::from_pixel(width, height, Luma([128u8]));
        // Text mask: white everywhere except one black pixel at (5,5)
        let mut text_mask = GrayImage::from_pixel(width, height, WHITE);
        text_mask.put_pixel(5, 5, BLACK);

        let frame = RenderedFrame { icons, text_mask };
        let out = flatten_for_png(&frame);

        // The text pixel should override the icon layer
        assert_eq!(
            out.get_pixel(5, 5).0[0],
            0,
            "text black overrides icon gray"
        );
        // Non-text pixels keep the icon value
        assert_eq!(
            out.get_pixel(0, 0).0[0],
            128,
            "non-text pixel keeps icon value"
        );
    }

    #[test]
    fn flatten_for_png_all_white_text_preserves_icons() {
        let icons = GrayImage::from_pixel(4, 4, Luma([42u8]));
        let text_mask = GrayImage::from_pixel(4, 4, WHITE);
        let frame = RenderedFrame { icons, text_mask };
        let out = flatten_for_png(&frame);

        for pixel in out.pixels() {
            assert_eq!(
                pixel.0[0], 42,
                "icon value preserved when text mask is all white"
            );
        }
    }

    // -- wrap_text edge cases --

    #[test]
    fn wrap_text_empty_string() {
        let lines = wrap_text("", 10);
        assert!(lines.is_empty(), "empty input should produce no lines");
    }

    #[test]
    fn wrap_text_single_long_word() {
        // A single word longer than max_chars cannot be split, so it stays on one line
        let lines = wrap_text("abcdefghijklmnopqrstuvwxyz", 10);
        assert_eq!(lines, vec!["abcdefghijklmnopqrstuvwxyz"]);
    }

    #[test]
    fn wrap_text_exact_fit() {
        // "hello five" is exactly 10 chars — should fit on one line
        let lines = wrap_text("hello five", 10);
        assert_eq!(lines, vec!["hello five"]);
    }

    #[test]
    fn wrap_text_one_char_over() {
        // "hello fiver" is 11 chars — should wrap
        let lines = wrap_text("hello fiver", 10);
        assert_eq!(lines, vec!["hello", "fiver"]);
    }

    #[test]
    fn wrap_text_whitespace_only() {
        let lines = wrap_text("   \t  ", 10);
        assert!(lines.is_empty(), "whitespace-only input produces no lines");
    }

    // -- render_frame with character_img and status_icon --

    #[test]
    fn render_frame_with_character_and_status_icon() {
        let display = DisplayData::default();
        let status = OrchestratorStatus {
            current_action: "scanning".into(),
            ..Default::default()
        };
        let config = BjornConfig::default();
        let tmp = std::path::PathBuf::from("/tmp/nonexistent");

        // Small grayscale images to serve as character and status icon
        let character_img = GrayImage::from_pixel(20, 30, Luma([80u8]));
        let status_icon = GrayImage::from_pixel(12, 12, Luma([60u8]));

        let frame = render_frame(
            &display,
            &status,
            &config,
            &tmp,
            Some(&character_img),
            Some(&status_icon),
            122,
            250,
        );

        // Frame should still be the correct size
        assert_eq!(frame.icons.width(), 122);
        assert_eq!(frame.icons.height(), 250);

        // Character image is pasted at bottom center of icon layer
        // x_center = (122 - 20) / 2 = 51, y_bottom = 250 - 30 = 220
        assert_eq!(
            frame.icons.get_pixel(51, 220).0[0],
            80,
            "character image top-left should be pasted at (51,220)"
        );

        // Status icon is pasted at approximately (3*sx, 60*sy) = (3,60) for 122x250
        // Since sx=1.0 and sy=1.0, it should be at (3, 60)
        assert_eq!(
            frame.icons.get_pixel(3, 60).0[0],
            60,
            "status icon should be pasted near (3,60)"
        );
    }

    // -- Border / divider line verification --

    #[test]
    fn border_and_dividers_are_drawn() {
        let display = DisplayData::default();
        let status = OrchestratorStatus::default();
        let config = BjornConfig::default();
        let tmp = std::path::PathBuf::from("/tmp/nonexistent");

        let frame = render_frame(&display, &status, &config, &tmp, None, None, 122, 250);
        let text = &frame.text_mask;

        // Border rectangle at (1,1) to (120,248)
        // Top-left corner of border
        assert_eq!(
            text.get_pixel(1, 1).0[0],
            0,
            "top-left border pixel should be black"
        );
        // Top-right corner of border
        assert_eq!(
            text.get_pixel(120, 1).0[0],
            0,
            "top-right border pixel should be black"
        );
        // Bottom-left corner of border
        assert_eq!(
            text.get_pixel(1, 248).0[0],
            0,
            "bottom-left border pixel should be black"
        );

        // Horizontal divider at y=20 (for 122x250 with sy=1.0)
        assert_eq!(
            text.get_pixel(60, 20).0[0],
            0,
            "divider at y=20 should be black"
        );

        // Horizontal divider at y=59
        assert_eq!(
            text.get_pixel(60, 59).0[0],
            0,
            "divider at y=59 should be black"
        );

        // Horizontal divider at y=87
        assert_eq!(
            text.get_pixel(60, 87).0[0],
            0,
            "divider at y=87 should be black"
        );

        // Pixel well inside a non-drawn area should be white (e.g., center of a stat box area)
        // Picking (60, 30) which is in the stats area, between divider y=20 and y=59
        // This pixel could have text on it, so let's pick a corner that's likely empty
        assert_eq!(
            text.get_pixel(70, 50).0[0],
            255,
            "interior pixel away from text/lines should be white"
        );
    }

    // -- Helper function s() --

    #[test]
    fn scale_helper() {
        assert_eq!(s(10, 1.0), 10);
        assert_eq!(s(10, 2.0), 20);
        assert_eq!(s(10, 0.5), 5);
        assert_eq!(s(0, 3.0), 0);
    }

    // -- draw_hline / draw_rect_outline --

    #[test]
    fn draw_hline_sets_pixels() {
        let mut img = GrayImage::from_pixel(20, 10, WHITE);
        draw_hline(&mut img, 2, 8, 5);
        // Pixels on the line should be black
        for x in 2..=8 {
            assert_eq!(
                img.get_pixel(x, 5).0[0],
                0,
                "pixel at ({x},5) should be black"
            );
        }
        // Pixel before the line should be white
        assert_eq!(img.get_pixel(0, 5).0[0], 255);
    }

    #[test]
    fn draw_rect_outline_draws_all_four_sides() {
        let mut img = GrayImage::from_pixel(30, 30, WHITE);
        draw_rect_outline(&mut img, 5, 5, 10, 10);
        // Top side
        assert_eq!(img.get_pixel(10, 5).0[0], 0, "top side pixel");
        // Bottom side
        assert_eq!(img.get_pixel(10, 15).0[0], 0, "bottom side pixel");
        // Left side
        assert_eq!(img.get_pixel(5, 10).0[0], 0, "left side pixel");
        // Right side
        assert_eq!(img.get_pixel(15, 10).0[0], 0, "right side pixel");
        // Center should be white
        assert_eq!(
            img.get_pixel(10, 10).0[0],
            255,
            "center pixel should be white"
        );
    }
}
