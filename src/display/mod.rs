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
pub async fn run(state: Arc<AppState>) {
    let config = state.config();
    let screen_reversed = true; // V4 needs 180° rotation

    // Try to initialize the e-Paper hardware
    let mut epd = epd_v4::Epd2in13V4::new();
    let has_hardware = if let Some(ref mut epd) = epd {
        match epd.init() {
            Ok(()) => {
                tracing::info!("e-Paper V4 initialized (122x250)");
                true
            }
            Err(e) => {
                tracing::warn!(%e, "e-Paper init failed, running in headless mode");
                false
            }
        }
    } else {
        tracing::info!("no SPI hardware detected, running in headless mode (PNG only)");
        false
    };

    // Init partial update mode
    if has_hardware {
        if let Some(ref mut epd) = epd {
            let _ = epd.init_partial();
        }
    }

    let web_dir = state.paths.web_dir.clone();
    let png_path = web_dir.join("screen.png");

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Read display data
        let display_data = state.display.read().await.clone();
        let status = state.status.read().await.clone();

        // Render frame
        let frame = renderer::render_frame(&display_data, &status, &config);

        // Apply rotation for V4
        let frame = if screen_reversed {
            image::imageops::rotate180(&frame)
        } else {
            frame
        };

        // Send to e-Paper
        if has_hardware {
            if let Some(ref mut epd) = epd {
                let buf = image_to_epd_buffer(&frame);
                let _ = epd.display_partial(&buf);
            }
        }

        // Save PNG for web UI (un-rotate for web display)
        let web_frame = if screen_reversed {
            image::imageops::rotate180(&frame)
        } else {
            frame
        };
        if let Err(e) = web_frame.save(&png_path) {
            tracing::error!(%e, "failed to save screen.png");
        }

        sleep(Duration::from_secs(config.screen_delay)).await;
    }

    // Sleep the display on shutdown
    if has_hardware {
        if let Some(ref mut epd) = epd {
            let _ = epd.sleep();
        }
    }

    tracing::info!("display task stopped");
}

/// Convert a 1-bit image to the EPD buffer format.
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
