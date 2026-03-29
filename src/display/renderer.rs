use ab_glyph::{FontRef, PxScale};
use image::{GrayImage, Luma};
use imageproc::drawing::{draw_line_segment_mut, draw_text_mut};

use crate::config::BjornConfig;
use crate::state::{DisplayData, OrchestratorStatus};

use super::epd_v4::{EPD_HEIGHT, EPD_WIDTH};

const REF_WIDTH: f32 = 122.0;
const REF_HEIGHT: f32 = 250.0;
const BLACK: Luma<u8> = Luma([0u8]);
const WHITE: Luma<u8> = Luma([255u8]);

/// Embedded DejaVu Sans Mono font (free license, ~300KB).
const FONT_BYTES: &[u8] = include_bytes!("../../resources/fonts/DejaVuSansMono.ttf");

fn load_font() -> FontRef<'static> {
    FontRef::try_from_slice(FONT_BYTES).expect("failed to load embedded font")
}

/// Render a complete display frame matching the Python `display.py` layout.
///
/// Returns a 122x250 grayscale image (white background, black drawing).
pub fn render_frame(
    display: &DisplayData,
    status: &OrchestratorStatus,
    _config: &BjornConfig,
) -> GrayImage {
    let width = EPD_WIDTH;
    let height = EPD_HEIGHT;
    let sx = width as f32 / REF_WIDTH;
    let sy = height as f32 / REF_HEIGHT;

    let mut img = GrayImage::from_pixel(width, height, WHITE);
    let font = load_font();

    let scale_9 = PxScale::from(9.0 * sy);
    let scale_11 = PxScale::from(11.0 * sy);
    let scale_12 = PxScale::from(12.0 * sy);
    let scale_13 = PxScale::from(13.0 * sy);

    // -- Border --
    draw_rect_outline(&mut img, 1, 1, width - 2, height - 2);

    // -- Horizontal dividers --
    draw_hline(&mut img, 1, width - 2, s(20, sy));
    draw_hline(&mut img, 1, width - 2, s(59, sy));
    draw_hline(&mut img, 1, width - 2, s(87, sy));

    // -- Title: "BJORN" --
    draw_text_mut(&mut img, BLACK, s(37, sx) as i32, s(5, sy) as i32, scale_13, &font, "BJORN");

    // -- WiFi indicator --
    if display.wifi_connected {
        draw_text_mut(&mut img, BLACK, s(3, sx) as i32, s(5, sy) as i32, scale_9, &font, "W");
    }

    // -- Manual/Auto mode --
    let mode_txt = if status.manual_mode { "M" } else { "A" };
    draw_text_mut(&mut img, BLACK, s(110, sx) as i32, s(5, sy) as i32, scale_9, &font, mode_txt);

    // -- Stats row 1 (y=22): targets, ports, vulns --
    draw_stat(&mut img, &font, scale_9, sx, sy, 8, 22, "T", display.target_count);
    draw_stat(&mut img, &font, scale_9, sx, sy, 47, 22, "P", display.port_count);
    draw_stat(&mut img, &font, scale_9, sx, sy, 86, 22, "V", display.vuln_count);

    // -- Stats row 2 (y=41): creds, zombies, data --
    draw_stat(&mut img, &font, scale_9, sx, sy, 8, 41, "C", display.cred_count);
    draw_stat(&mut img, &font, scale_9, sx, sy, 47, 41, "Z", display.zombie_count);
    draw_stat(&mut img, &font, scale_9, sx, sy, 86, 41, "D", display.data_count);

    // -- Status area (y=60-87) --
    let action_text = if status.current_action.is_empty() {
        "IDLE"
    } else {
        &status.current_action
    };
    draw_text_mut(
        &mut img, BLACK,
        s(5, sx) as i32, s(63, sy) as i32,
        scale_11, &font,
        &format!("[{}]", action_text),
    );
    if !status.detail.is_empty() {
        draw_text_mut(
            &mut img, BLACK,
            s(5, sx) as i32, s(75, sy) as i32,
            scale_9, &font,
            &status.detail,
        );
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
        draw_text_mut(&mut img, BLACK, s(4, sx) as i32, y_text, scale_12, &font, line);
        y_text += (12.0 * sy) as i32 + 3;
        if y_text > s(155, sy) as i32 {
            break;
        }
    }

    // -- Bottom stats --
    draw_text_mut(&mut img, BLACK, s(3, sx) as i32, s(175, sy) as i32, scale_9, &font, &format!("${}", display.coin_count));
    draw_text_mut(&mut img, BLACK, s(3, sx) as i32, s(220, sy) as i32, scale_9, &font, &format!("L{}", display.level));
    draw_text_mut(&mut img, BLACK, s(85, sx) as i32, s(195, sy) as i32, scale_9, &font, &format!("KB:{}", display.network_kb_count));
    draw_text_mut(&mut img, BLACK, s(85, sx) as i32, s(220, sy) as i32, scale_9, &font, &format!("A:{}", display.attack_count));

    // -- Frise line at y=160 --
    draw_hline(&mut img, 0, width - 1, s(160, sy));

    img
}

// -- Helpers --

fn s(val: u32, scale: f32) -> u32 {
    (val as f32 * scale) as u32
}

fn draw_stat(
    img: &mut GrayImage,
    font: &FontRef,
    scale: PxScale,
    sx: f32,
    sy: f32,
    x: u32,
    y: u32,
    icon: &str,
    value: u32,
) {
    draw_text_mut(img, BLACK, s(x, sx) as i32, s(y, sy) as i32, scale, font, &format!("{icon}:{value}"));
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
        let img = render_frame(&display, &status, &config);
        assert_eq!(img.width(), EPD_WIDTH);
        assert_eq!(img.height(), EPD_HEIGHT);
    }

    #[test]
    fn wrap_text_basic() {
        let lines = wrap_text("Hello world this is a test", 10);
        assert_eq!(lines, vec!["Hello", "world this", "is a test"]);
    }
}
