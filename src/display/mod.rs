pub mod epd_v4;
pub mod renderer;

use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;

use crate::state::AppState;

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
    let screen_reversed = true; // V4 needs 180° rotation

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

    let mut frame_count: u64 = 0;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Read display data
        let display_data = state.display.read().await.clone();
        let orch_status = state.status.read().await.clone();

        // Render frame
        let frame = renderer::render_frame(&display_data, &orch_status, &config);

        // Save PNG for web UI (always, regardless of hardware)
        if let Err(e) = frame.save(&png_path) {
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

    let mut frame_count: u64 = 0;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Read display data (blocking read on the RwLock)
        let display_data = state.display.blocking_read().clone();
        let orch_status = state.status.blocking_read().clone();

        // Render frame
        let frame = renderer::render_frame(&display_data, &orch_status, &config);

        // Apply rotation for V4
        let frame = if screen_reversed {
            image::imageops::rotate180(&frame)
        } else {
            frame
        };

        // Send to e-Paper (blocking SPI)
        let buf = image_to_epd_buffer(&frame);
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

/// Convert a grayscale image to the EPD buffer format (1 bit per pixel, packed).
fn image_to_epd_buffer(img: &image::GrayImage) -> Vec<u8> {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let line_width = (width + 7) / 8;
    let mut buf = vec![0xFFu8; line_width * height];

    for y in 0..height {
        for x in 0..width {
            let pixel = img.get_pixel(x as u32, y as u32).0[0];
            if pixel < 128 {
                // Black pixel
                let byte_idx = y * line_width + x / 8;
                let bit_idx = 7 - (x % 8);
                buf[byte_idx] &= !(1 << bit_idx);
            }
        }
    }
    buf
}
