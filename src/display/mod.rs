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
        let action = if orch_status.current_action.is_empty() { "IDLE" } else { &orch_status.current_action };

        if let Some(comment) = comments.get_comment(action) {
            state.display.write().await.bjorn_says = comment;
        }

        let display_data = state.display.read().await.clone();
        let (epd_w, epd_h) = epd::display_dimensions(&config.epd_type);
        let frame = renderer::render_frame(
            &display_data, &orch_status, &config,
            &state.paths.static_images_dir, None, None, epd_w, epd_h,
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
    let mut image_change_interval = rand_duration(config.image_display_delaymin, config.image_display_delaymax);
    let mut frame_count: u64 = 0;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        let orch_status = state.status.blocking_read().clone();
        let action = if orch_status.current_action.is_empty() { "IDLE" } else { &orch_status.current_action };

        if let Some(comment) = comments.get_comment(action) {
            state.display.blocking_write().bjorn_says = comment;
        }

        let display_data = state.display.blocking_read().clone();

        if last_image_change.elapsed() >= image_change_interval {
            status_imgs.randomize_current();
            last_image_change = Instant::now();
            image_change_interval = rand_duration(config.image_display_delaymin, config.image_display_delaymax);
        }

        let status_icon = status_imgs.status_icon(action).cloned();
        let character_img = status_imgs.pick_character(action).cloned();

        let frame = renderer::render_frame(
            &display_data, &orch_status, &config,
            &state.paths.static_images_dir,
            character_img.as_ref(), status_icon.as_ref(),
            epd_w, epd_h,
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
