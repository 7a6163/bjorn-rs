pub mod comments;
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

/// Main display loop.
///
/// Renders the Bjorn UI to the e-Paper HAT and saves a PNG for the web UI.
/// On non-Pi systems (no SPI), it only generates the PNG.
///
/// The e-Paper SPI operations are blocking (thread::sleep in wait_busy),
/// so we run the hardware part on a dedicated OS thread to avoid blocking
/// the tokio runtime.
pub async fn run(state: Arc<AppState>) {
    let config = state.config();

    let web_dir = state.paths.web_dir.clone();
    let png_path = web_dir.join("screen.png");

    // Ensure web dir exists
    let _ = tokio::fs::create_dir_all(&web_dir).await;

    // Start the EPD hardware on a dedicated thread
    let epd_state = Arc::clone(&state);
    let epd_handle = std::thread::spawn(move || {
        run_epd_thread(epd_state);
    });

    tracing::info!(png = %png_path.display(), "display loop starting (headless PNG + EPD thread)");

    // Initialize comment engine
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

        // Update comments based on current action
        let action = if orch_status.current_action.is_empty() {
            "IDLE"
        } else {
            &orch_status.current_action
        };
        if let Some(comment) = comments.get_comment(action) {
            let mut display = state.display.write().await;
            display.bjorn_says = comment;
        }

        let display_data = state.display.read().await.clone();

        // Render two-layer frame (no character animation in headless PNG)
        let frame = renderer::render_frame(
            &display_data,
            &orch_status,
            &config,
            &state.paths.static_images_dir,
            None,
            None,
        );

        // Flatten to single image for PNG (web UI)
        let png_img = renderer::flatten_for_png(&frame);
        if let Err(e) = png_img.save(&png_path) {
            tracing::error!(%e, "failed to save screen.png");
        }

        frame_count += 1;
        if frame_count <= 3 {
            tracing::info!(frame = frame_count, "display frame rendered (PNG saved)");
        }

        sleep(Duration::from_secs(config.screen_delay)).await;
    }

    // Wait for EPD thread to finish (it checks shutdown too)
    let _ = epd_handle.join();
    tracing::info!("display task stopped");
}

/// Runs on a dedicated OS thread — handles all blocking SPI operations.
fn run_epd_thread(state: Arc<AppState>) {
    let config = state.config();
    let screen_reversed = true;

    let mut epd = match epd_v4::Epd2in13V4::new() {
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
    tracing::info!("e-Paper V4 initialized (122x250)");

    if let Err(e) = epd.init_partial() {
        tracing::warn!(%e, "e-Paper partial init failed");
    }

    // Load status images (per-action character animations + status icons)
    let mut status_imgs = StatusImages::new(&state.paths.status_images_dir);

    // Comment engine for the EPD thread
    let mut comments = CommentEngine::new(
        &state.paths.comments_json,
        config.comment_delaymin,
        config.comment_delaymax,
    );

    // Image randomizer timer — switch character image periodically
    let image_delay_min = config.image_display_delaymin;
    let image_delay_max = config.image_display_delaymax;
    let mut last_image_change = Instant::now();
    let mut image_change_interval = rand_duration(image_delay_min, image_delay_max);

    let mut frame_count: u64 = 0;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Read display data (blocking read on the RwLock)
        let orch_status = state.status.blocking_read().clone();

        // Update comments
        let action = if orch_status.current_action.is_empty() {
            "IDLE"
        } else {
            &orch_status.current_action
        };
        if let Some(comment) = comments.get_comment(action) {
            let mut display = state.display.blocking_write();
            display.bjorn_says = comment;
        }

        let display_data = state.display.blocking_read().clone();

        // Periodically randomize character image
        if last_image_change.elapsed() >= image_change_interval {
            status_imgs.randomize_current();
            last_image_change = Instant::now();
            image_change_interval = rand_duration(image_delay_min, image_delay_max);
        }

        // Pick status icon first (immutable borrow), then character (mutable borrow)
        let status_icon = status_imgs.status_icon(action).cloned();
        let character_img = status_imgs.pick_character(action).cloned();

        // Render two-layer frame
        let frame = renderer::render_frame(
            &display_data,
            &orch_status,
            &config,
            &state.paths.static_images_dir,
            character_img.as_ref(),
            status_icon.as_ref(),
        );

        // Composite: dither icon layer, then stamp crisp text on top
        let buf = composite_to_epd_buffer(&frame, screen_reversed);

        if frame_count == 0 {
            // First frame: write base image to both RAM banks (required for partial updates)
            tracing::info!("sending base image to EPD (full update)");
            epd.display_base_image(&buf);
        } else {
            if let Err(e) = epd.display_partial(&buf) {
                tracing::error!(%e, "epd display_partial failed");
            }
            // Send twice like Python version for reliable partial update
            let _ = epd.display_partial(&buf);
        }

        frame_count += 1;
        if frame_count <= 3 {
            tracing::info!(frame = frame_count, "EPD frame sent to hardware");
        }

        std::thread::sleep(Duration::from_secs(config.screen_delay));
    }

    // Sleep the display on shutdown
    let _ = epd.sleep();
    tracing::info!("EPD thread stopped");
}

fn rand_duration(min_secs: u64, max_secs: u64) -> Duration {
    let mut rng = rand::rng();
    let secs = rand::Rng::random_range(&mut rng, min_secs..=max_secs);
    Duration::from_secs(secs)
}

/// Composite two-layer frame into EPD buffer:
/// 1. Dither the icon layer (grayscale → 1-bit with gradients)
/// 2. Overlay crisp text mask (no dithering, hard threshold)
/// 3. Pack into 1-bit EPD buffer
fn composite_to_epd_buffer(frame: &renderer::RenderedFrame, rotate: bool) -> Vec<u8> {
    let dithered_icons = floyd_steinberg_dither(&frame.icons);

    let width = dithered_icons.width();
    let height = dithered_icons.height();

    // Merge: text mask wins (crisp black), otherwise use dithered icon
    let mut merged = dithered_icons;
    for y in 0..height {
        for x in 0..width {
            let text_px = frame.text_mask.get_pixel(x, y).0[0];
            if text_px < 128 {
                merged.put_pixel(x, y, Luma([0u8]));
            }
        }
    }

    // Apply rotation for V4
    let final_img = if rotate {
        image::imageops::rotate180(&merged)
    } else {
        merged
    };

    gray_to_epd_buffer(&final_img)
}

/// Apply Floyd-Steinberg dithering to a grayscale image, converting it to 1-bit
/// with simulated gradients — matches Python PIL `convert('1')` behavior.
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

/// Pack a 1-bit (thresholded) grayscale image into EPD buffer format.
fn gray_to_epd_buffer(img: &image::GrayImage) -> Vec<u8> {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let line_width = (width + 7) / 8;
    let mut buf = vec![0xFFu8; line_width * height];

    for y in 0..height {
        for x in 0..width {
            let pixel = img.get_pixel(x as u32, y as u32).0[0];
            if pixel < 128 {
                let byte_idx = y * line_width + x / 8;
                let bit_idx = 7 - (x % 8);
                buf[byte_idx] &= !(1 << bit_idx);
            }
        }
    }
    buf
}
