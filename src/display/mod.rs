pub mod comments;
pub mod epd;
pub mod epd_v4;
pub mod renderer;
pub mod status_images;

use std::sync::Arc;
use std::time::{Duration, Instant};

use image::Luma;
use tokio::time::sleep;

use crate::state::AppState;
use comments::CommentEngine;
use status_images::StatusImages;

/// Main display loop — renders PNG for web UI + starts EPD hardware thread.
pub async fn run(state: Arc<AppState>) {
    let config = state.config();
    let web_dir = state.paths.web_dir.clone();
    let png_path = web_dir.join("screen.png");

    let _ = tokio::fs::create_dir_all(&web_dir).await;

    let epd_state = Arc::clone(&state);
    let epd_handle = std::thread::spawn(move || run_epd_thread(epd_state));

    tracing::info!(png = %png_path.display(), "display loop starting");

    let mut comments = CommentEngine::new(
        &state.paths.comments_json,
        config.comment_delaymin,
        config.comment_delaymax,
    );
    let mut frame_count: u64 = 0;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        let orch_status = state.status.read().await.clone();
        let action = if orch_status.current_action.is_empty() {
            "IDLE"
        } else {
            &orch_status.current_action
        };

        if let Some(comment) = comments.get_comment(action) {
            state.display.write().await.bjorn_says = comment;
        }

        let display_data = state.display.read().await.clone();
        let (epd_w, epd_h) = epd::display_dimensions(&config.epd_type);
        let frame = renderer::render_frame(
            &display_data,
            &orch_status,
            &config,
            &state.paths.static_images_dir,
            None,
            None,
            epd_w,
            epd_h,
        );

        let png_img = renderer::flatten_for_png(&frame);
        if let Err(e) = png_img.save(&png_path) {
            tracing::error!(%e, "failed to save screen.png");
        }

        frame_count += 1;
        if frame_count <= 3 {
            tracing::info!(frame = frame_count, "display frame rendered");
        }

        sleep(Duration::from_secs(config.screen_delay)).await;
    }

    let _ = epd_handle.join();
    tracing::info!("display task stopped");
}

/// Runs on a dedicated OS thread — handles all blocking SPI operations.
fn run_epd_thread(state: Arc<AppState>) {
    let config = state.config();
    let screen_reversed = true;

    let mut epd = match epd::create_display(&config.epd_type) {
        Some(epd) => epd,
        None => {
            tracing::info!("no SPI hardware detected, EPD thread exiting");
            return;
        }
    };

    if let Err(e) = epd.init() {
        tracing::warn!(%e, "e-Paper init failed");
        return;
    }
    let epd_w = epd.width();
    let epd_h = epd.height();
    tracing::info!(epd_type = %config.epd_type, width = epd_w, height = epd_h, "e-Paper initialized");
    let _ = epd.init_partial();

    let mut status_imgs = StatusImages::new(&state.paths.status_images_dir);
    let mut comments = CommentEngine::new(
        &state.paths.comments_json,
        config.comment_delaymin,
        config.comment_delaymax,
    );

    let mut last_image_change = Instant::now();
    let mut image_change_interval =
        rand_duration(config.image_display_delaymin, config.image_display_delaymax);
    let mut frame_count: u64 = 0;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        let orch_status = state.status.blocking_read().clone();
        let action = if orch_status.current_action.is_empty() {
            "IDLE"
        } else {
            &orch_status.current_action
        };

        if let Some(comment) = comments.get_comment(action) {
            state.display.blocking_write().bjorn_says = comment;
        }

        let display_data = state.display.blocking_read().clone();

        if last_image_change.elapsed() >= image_change_interval {
            status_imgs.randomize_current();
            last_image_change = Instant::now();
            image_change_interval =
                rand_duration(config.image_display_delaymin, config.image_display_delaymax);
        }

        let status_icon = status_imgs.status_icon(action).cloned();
        let character_img = status_imgs.pick_character(action).cloned();

        let frame = renderer::render_frame(
            &display_data,
            &orch_status,
            &config,
            &state.paths.static_images_dir,
            character_img.as_ref(),
            status_icon.as_ref(),
            epd_w,
            epd_h,
        );

        // Composite: dither icon layer for gradients, stamp crisp 1-bit text on top
        let buf = composite_to_epd_buffer(&frame, screen_reversed);

        if frame_count == 0 {
            tracing::info!("sending base image to EPD (full update)");
            epd.display_base_image(&buf);
        } else {
            if let Err(e) = epd.display_partial(&buf) {
                tracing::error!(%e, "epd display_partial failed");
            }
            let _ = epd.display_partial(&buf);
        }

        frame_count += 1;
        if frame_count <= 3 {
            tracing::info!(frame = frame_count, "EPD frame sent to hardware");
        }

        std::thread::sleep(Duration::from_secs(config.screen_delay));
    }

    let _ = epd.sleep();
    tracing::info!("EPD thread stopped");
}

/// Composite two layers into EPD buffer:
/// 1. Floyd-Steinberg dither the icon layer (grayscale → 1-bit with gradients)
/// 2. Stamp pure 1-bit text mask on top (no dithering, already thresholded)
/// 3. Pack into EPD bit buffer
fn composite_to_epd_buffer(frame: &renderer::RenderedFrame, rotate: bool) -> Vec<u8> {
    let mut merged = floyd_steinberg_dither(&frame.icons);

    let width = merged.width();
    let height = merged.height();

    // Text mask is already pure 0/255. Stamp black text pixels on top.
    for y in 0..height {
        for x in 0..width {
            if frame.text_mask.get_pixel(x, y).0[0] == 0 {
                merged.put_pixel(x, y, Luma([0u8]));
            }
        }
    }

    let final_img = if rotate {
        image::imageops::rotate180(&merged)
    } else {
        merged
    };

    gray_to_epd_buffer(&final_img)
}

/// Floyd-Steinberg dithering — matches Python PIL `convert('1')`.
fn floyd_steinberg_dither(img: &image::GrayImage) -> image::GrayImage {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let mut pixels: Vec<i16> = img.pixels().map(|p| p.0[0] as i16).collect();

    for y in 0..height {
        for x in 0..width {
            let idx = y * width + x;
            let old = pixels[idx];
            let new = if old >= 128 { 255 } else { 0 };
            let err = old - new;
            pixels[idx] = new;

            if x + 1 < width {
                pixels[idx + 1] += err * 7 / 16;
            }
            if y + 1 < height {
                if x > 0 {
                    pixels[(y + 1) * width + x - 1] += err * 3 / 16;
                }
                pixels[(y + 1) * width + x] += err * 5 / 16;
                if x + 1 < width {
                    pixels[(y + 1) * width + x + 1] += err * 1 / 16;
                }
            }
        }
    }

    let out: Vec<u8> = pixels.iter().map(|&v| v.clamp(0, 255) as u8).collect();
    image::GrayImage::from_raw(width as u32, height as u32, out).unwrap()
}

fn gray_to_epd_buffer(img: &image::GrayImage) -> Vec<u8> {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let line_width = (width + 7) / 8;
    let mut buf = vec![0xFFu8; line_width * height];

    for y in 0..height {
        for x in 0..width {
            if img.get_pixel(x as u32, y as u32).0[0] < 128 {
                let byte_idx = y * line_width + x / 8;
                let bit_idx = 7 - (x % 8);
                buf[byte_idx] &= !(1 << bit_idx);
            }
        }
    }
    buf
}

fn rand_duration(min_secs: u64, max_secs: u64) -> Duration {
    let mut rng = rand::rng();
    Duration::from_secs(rand::Rng::random_range(&mut rng, min_secs..=max_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, Luma};

    // ── floyd_steinberg_dither ──────────────────────────────────────────

    #[test]
    fn dither_pure_white_stays_white() {
        let img = GrayImage::from_pixel(16, 16, Luma([255u8]));
        let out = floyd_steinberg_dither(&img);
        assert!(
            out.pixels().all(|p| p.0[0] == 255),
            "every pixel in an all-white image should remain 255 after dithering"
        );
    }

    #[test]
    fn dither_pure_black_stays_black() {
        let img = GrayImage::from_pixel(16, 16, Luma([0u8]));
        let out = floyd_steinberg_dither(&img);
        assert!(
            out.pixels().all(|p| p.0[0] == 0),
            "every pixel in an all-black image should remain 0 after dithering"
        );
    }

    #[test]
    fn dither_mid_gray_produces_mixed_pattern() {
        let img = GrayImage::from_pixel(32, 32, Luma([128u8]));
        let out = floyd_steinberg_dither(&img);

        let total = out.pixels().count();
        let white_count = out.pixels().filter(|p| p.0[0] == 255).count();
        let black_count = out.pixels().filter(|p| p.0[0] == 0).count();

        // All output pixels must be pure black or white (1-bit)
        assert_eq!(
            white_count + black_count,
            total,
            "dithered output must contain only 0 or 255 values"
        );

        // 50% gray should produce roughly half black, half white (allow 20% tolerance)
        let ratio = white_count as f64 / total as f64;
        assert!(
            (0.30..=0.70).contains(&ratio),
            "expected ~50% white pixels for mid-gray input, got {:.1}%",
            ratio * 100.0
        );
    }

    #[test]
    fn dither_output_is_pure_one_bit() {
        // Gradient image: values 0..=255 spread across rows
        let img = GrayImage::from_fn(256, 4, |x, _y| Luma([x as u8]));
        let out = floyd_steinberg_dither(&img);
        assert!(
            out.pixels().all(|p| p.0[0] == 0 || p.0[0] == 255),
            "all dithered pixels must be exactly 0 or 255"
        );
    }

    // ── gray_to_epd_buffer ─────────────────────────────────────────────

    #[test]
    fn epd_buffer_all_white() {
        let img = GrayImage::from_pixel(16, 2, Luma([255u8]));
        let buf = gray_to_epd_buffer(&img);
        // 16px wide → 2 bytes per row, 2 rows → 4 bytes, all 0xFF
        assert_eq!(buf.len(), 4);
        assert!(buf.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn epd_buffer_all_black() {
        let img = GrayImage::from_pixel(16, 2, Luma([0u8]));
        let buf = gray_to_epd_buffer(&img);
        assert_eq!(buf.len(), 4);
        assert!(buf.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn epd_buffer_known_pattern() {
        // 8px wide, 1 row: first pixel black (value 0), rest white (255)
        let mut img = GrayImage::from_pixel(8, 1, Luma([255u8]));
        img.put_pixel(0, 0, Luma([0u8])); // leftmost pixel → MSB of byte

        let buf = gray_to_epd_buffer(&img);
        assert_eq!(buf.len(), 1);
        // bit 7 cleared (black pixel at x=0), rest set: 0b0111_1111 = 0x7F
        assert_eq!(buf[0], 0x7F);
    }

    #[test]
    fn epd_buffer_alternating_pixels() {
        // 8px wide, 1 row: alternating black/white starting with black
        let img = GrayImage::from_fn(8, 1, |x, _| {
            if x % 2 == 0 {
                Luma([0u8])
            } else {
                Luma([255u8])
            }
        });

        let buf = gray_to_epd_buffer(&img);
        assert_eq!(buf.len(), 1);
        // x=0 → bit7=0, x=1 → bit6=1, x=2 → bit5=0, ...
        // 0b01010101 = 0x55
        assert_eq!(buf[0], 0x55);
    }

    #[test]
    fn epd_buffer_width_not_multiple_of_8() {
        // 10px wide → line_width = (10+7)/8 = 2 bytes per row
        let img = GrayImage::from_pixel(10, 1, Luma([0u8]));
        let buf = gray_to_epd_buffer(&img);
        assert_eq!(buf.len(), 2);
        // First byte: all 10 pixels are black but only 8 fit → 0x00
        assert_eq!(buf[0], 0x00);
        // Second byte: 2 black pixels in bits 7,6; remaining bits stay 1 (padding)
        // 0b00111111 = 0x3F
        assert_eq!(buf[1], 0x3F);
    }

    // ── composite_to_epd_buffer ────────────────────────────────────────

    #[test]
    fn composite_text_overrides_icon_layer() {
        // Icon layer: all white (255)
        let icons = GrayImage::from_pixel(8, 8, Luma([255u8]));
        // Text mask: top-left pixel is black text (0), rest white (255 = no text)
        let mut text_mask = GrayImage::from_pixel(8, 8, Luma([255u8]));
        text_mask.put_pixel(0, 0, Luma([0u8]));

        let frame = renderer::RenderedFrame { icons, text_mask };
        let buf = composite_to_epd_buffer(&frame, false);

        // 8px wide → 1 byte per row, 8 rows → 8 bytes
        assert_eq!(buf.len(), 8);
        // Row 0: pixel 0 is black (text stamp) → bit 7 cleared → 0x7F
        assert_eq!(buf[0], 0x7F);
        // Remaining rows: all white
        assert!(buf[1..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn composite_text_stamps_over_dithered_icons() {
        // Icon layer: mid-gray (will be dithered to mixed black/white)
        let icons = GrayImage::from_pixel(16, 16, Luma([128u8]));
        // Text mask: entire first row is black text
        let mut text_mask = GrayImage::from_pixel(16, 16, Luma([255u8]));
        for x in 0..16 {
            text_mask.put_pixel(x, 0, Luma([0u8]));
        }

        let frame = renderer::RenderedFrame { icons, text_mask };
        let buf = composite_to_epd_buffer(&frame, false);

        // First row (bytes 0..2) should be all-black (0x00) because text overrides
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x00);
    }

    #[test]
    fn composite_rotation_flips_image() {
        // 8x2 image: row 0 all black icons, row 1 all white icons, no text
        let mut icons = GrayImage::from_pixel(8, 2, Luma([255u8]));
        for x in 0..8 {
            icons.put_pixel(x, 0, Luma([0u8]));
        }
        let text_mask = GrayImage::from_pixel(8, 2, Luma([255u8])); // no text

        let frame_no_rotate = renderer::RenderedFrame {
            icons: icons.clone(),
            text_mask: text_mask.clone(),
        };
        let frame_rotated = renderer::RenderedFrame { icons, text_mask };

        let buf_normal = composite_to_epd_buffer(&frame_no_rotate, false);
        let buf_rotated = composite_to_epd_buffer(&frame_rotated, true);

        // Without rotation: row 0 = 0x00 (black), row 1 = 0xFF (white)
        assert_eq!(buf_normal[0], 0x00);
        assert_eq!(buf_normal[1], 0xFF);

        // With 180° rotation: row order reverses → row 0 = 0xFF, row 1 = 0x00
        assert_eq!(buf_rotated[0], 0xFF);
        assert_eq!(buf_rotated[1], 0x00);
    }

    // ── rand_duration ──────────────────────────────────────────────────

    #[test]
    fn rand_duration_within_bounds() {
        for _ in 0..100 {
            let d = rand_duration(5, 10);
            assert!(d >= Duration::from_secs(5));
            assert!(d <= Duration::from_secs(10));
        }
    }

    #[test]
    fn rand_duration_equal_min_max() {
        let d = rand_duration(7, 7);
        assert_eq!(d, Duration::from_secs(7));
    }
}
