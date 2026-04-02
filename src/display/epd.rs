/// Unified e-Paper display driver supporting multiple Waveshare models.
///
/// Supported displays (configured via `epd_type` in config):
/// - `epd2in13`    — 2.13" V1 (122×250, full update only)
/// - `epd2in13_V2` — 2.13" V2 (122×250, partial update)
/// - `epd2in13_V3` — 2.13" V3 (122×250, partial update)
/// - `epd2in13_V4` — 2.13" V4 (122×250, partial update)
/// - `epd2in7`     — 2.7"    (176×264, full update only)

/// Display dimensions for each model.
pub fn display_dimensions(epd_type: &str) -> (u32, u32) {
    match epd_type {
        "epd2in7" => (176, 264),
        _ => (122, 250), // All 2.13" variants
    }
}

// GPIO pin assignments (BCM numbering) — matches epdconfig.py
const RST_PIN: u8 = 17;
const DC_PIN: u8 = 25;
const BUSY_PIN: u8 = 24;
const PWR_PIN: u8 = 18;

/// Common trait for all e-Paper displays.
pub trait EpdDisplay {
    fn width(&self) -> u32;
    fn height(&self) -> u32;
    fn init(&mut self) -> Result<(), String>;
    fn init_partial(&mut self) -> Result<(), String>;
    fn display(&mut self, buf: &[u8]);
    fn display_base_image(&mut self, buf: &[u8]);
    fn display_partial(&mut self, buf: &[u8]) -> Result<(), String>;
    fn clear(&mut self);
    fn sleep(&mut self) -> Result<(), String>;
}

/// Create the appropriate display driver based on config `epd_type`.
/// Returns `None` on non-Linux or if hardware is not available.
pub fn create_display(epd_type: &str) -> Option<Box<dyn EpdDisplay>> {
    hw::create_display(epd_type)
}

#[cfg(target_os = "linux")]
mod hw {
    use rppal::gpio::{Gpio, InputPin, OutputPin};
    use rppal::spi::{Bus, Mode, SlaveSelect, Spi};
    use std::thread;
    use std::time::Duration;

    use super::*;

    /// Shared SPI/GPIO hardware handle.
    struct SpiHw {
        spi: Spi,
        rst: OutputPin,
        dc: OutputPin,
        busy: InputPin,
        pwr: OutputPin,
    }

    impl SpiHw {
        fn new() -> Option<Self> {
            let gpio = Gpio::new().ok()?;
            let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 4_000_000, Mode::Mode0).ok()?;
            let rst = gpio.get(RST_PIN).ok()?.into_output();
            let dc = gpio.get(DC_PIN).ok()?.into_output();
            let busy = gpio.get(BUSY_PIN).ok()?.into_input();
            let mut pwr = gpio.get(PWR_PIN).ok()?.into_output();
            pwr.set_high();
            Some(Self {
                spi,
                rst,
                dc,
                busy,
                pwr,
            })
        }

        fn send_command(&mut self, cmd: u8) {
            self.dc.set_low();
            let _ = self.spi.write(&[cmd]);
        }

        fn send_data(&mut self, data: u8) {
            self.dc.set_high();
            let _ = self.spi.write(&[data]);
        }

        fn send_data_bulk(&mut self, data: &[u8]) {
            self.dc.set_high();
            for chunk in data.chunks(4096) {
                let _ = self.spi.write(chunk);
            }
        }

        /// Wait for busy pin — HIGH=busy for 2.13", LOW=busy for 2.7".
        fn wait_busy(&self, busy_high: bool) {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let is_busy = if busy_high {
                    self.busy.is_high()
                } else {
                    self.busy.is_low()
                };
                if !is_busy {
                    return;
                }
                if std::time::Instant::now() > deadline {
                    tracing::warn!("e-Paper busy timeout (10s)");
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn reset(&mut self, delay_ms: u64) {
            self.rst.set_high();
            thread::sleep(Duration::from_millis(delay_ms));
            self.rst.set_low();
            thread::sleep(Duration::from_millis(if delay_ms > 50 { 5 } else { 2 }));
            self.rst.set_high();
            thread::sleep(Duration::from_millis(delay_ms));
        }

        fn set_window(&mut self, x_start: u32, y_start: u32, x_end: u32, y_end: u32) {
            self.send_command(0x44);
            self.send_data((x_start >> 3) as u8);
            self.send_data((x_end >> 3) as u8);
            self.send_command(0x45);
            self.send_data(y_start as u8);
            self.send_data((y_start >> 8) as u8);
            self.send_data(y_end as u8);
            self.send_data((y_end >> 8) as u8);
        }

        fn set_cursor(&mut self, x: u32, y: u32) {
            self.send_command(0x4E);
            self.send_data(x as u8);
            self.send_command(0x4F);
            self.send_data(y as u8);
            self.send_data((y >> 8) as u8);
        }

        fn power_off(&mut self) {
            self.pwr.set_low();
            self.rst.set_low();
            self.dc.set_low();
        }
    }

    // ---- LUT tables ----

    #[rustfmt::skip]
    const LUT_V1_FULL: [u8; 30] = [
        0x22, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x11,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    const LUT_V2_FULL: [u8; 76] = [
        0x80, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x03, 0x00, 0x00, 0x02,
        0x09, 0x09, 0x00, 0x00, 0x02,
        0x03, 0x03, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x15, 0x41, 0xA8, 0x32, 0x30, 0x0A,
    ];

    #[rustfmt::skip]
    const LUT_V2_PARTIAL: [u8; 76] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0A, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x15, 0x41, 0xA8, 0x32, 0x30, 0x0A,
    ];

    // V3 LUT tables (159 bytes: 153 data + 6 config)
    // Timing rows are 7 bytes each (not 5), matching Python epd2in13_V3.py
    #[rustfmt::skip]
    const LUT_V3_FULL: [u8; 159] = [
        0x80, 0x4A, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x4A, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x4A, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x4A, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x02,
        0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x00, 0x00,
        // Config bytes: gate_voltage_ctrl, gate_voltage, source_voltage x3, vcom
        0x22, 0x17, 0x41, 0x00, 0x32, 0x36,
    ];

    #[rustfmt::skip]
    const LUT_V3_PARTIAL: [u8; 159] = [
        0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x00, 0x00,
        0x22, 0x17, 0x41, 0x00, 0x32, 0x36,
    ];

    // 2.7" LUT tables
    #[rustfmt::skip]
    const LUT_27_VCOM_DC: [u8; 44] = [
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02,
        0x60, 0x28, 0x28, 0x00, 0x00, 0x01, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x12, 0x12, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    const LUT_27_WW: [u8; 42] = [
        0x40, 0x08, 0x00, 0x00, 0x00, 0x02,
        0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
        0x40, 0x14, 0x00, 0x00, 0x00, 0x01,
        0xA0, 0x12, 0x12, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    const LUT_27_BW: [u8; 42] = [
        0x40, 0x08, 0x00, 0x00, 0x00, 0x02,
        0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
        0x40, 0x14, 0x00, 0x00, 0x00, 0x01,
        0xA0, 0x12, 0x12, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    const LUT_27_BB: [u8; 42] = [
        0x80, 0x08, 0x00, 0x00, 0x00, 0x02,
        0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
        0x80, 0x14, 0x00, 0x00, 0x00, 0x01,
        0x50, 0x12, 0x12, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    const LUT_27_WB: [u8; 42] = [
        0x80, 0x08, 0x00, 0x00, 0x00, 0x02,
        0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
        0x80, 0x14, 0x00, 0x00, 0x00, 0x01,
        0x50, 0x12, 0x12, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // ==== 2.13" V1 ====
    struct Epd2in13V1 {
        hw: SpiHw,
    }

    impl EpdDisplay for Epd2in13V1 {
        fn width(&self) -> u32 {
            122
        }
        fn height(&self) -> u32 {
            250
        }

        fn init(&mut self) -> Result<(), String> {
            self.hw.reset(200);
            self.hw.send_command(0x01); // Driver output control
            self.hw.send_data(0xF9);
            self.hw.send_data(0x00);
            self.hw.send_data(0x00);
            self.hw.send_command(0x0C); // Booster soft start
            self.hw.send_data(0xD7);
            self.hw.send_data(0xD6);
            self.hw.send_data(0x9D);
            self.hw.send_command(0x2C); // VCOM
            self.hw.send_data(0xA8);
            self.hw.send_command(0x3A); // Dummy line period
            self.hw.send_data(0x1A);
            self.hw.send_command(0x3B); // Gate time
            self.hw.send_data(0x08);
            self.hw.send_command(0x3C); // Border waveform
            self.hw.send_data(0x03);
            self.hw.send_command(0x11); // Data entry mode
            self.hw.send_data(0x03);
            // Write LUT
            self.hw.send_command(0x32);
            self.hw.send_data_bulk(&LUT_V1_FULL);
            Ok(())
        }

        fn init_partial(&mut self) -> Result<(), String> {
            self.init()
        }

        fn display(&mut self, buf: &[u8]) {
            self.hw.set_window(0, 0, 122 - 1, 250 - 1);
            self.hw.set_cursor(0, 0);
            self.hw.wait_busy(true);
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            // Turn on display
            self.hw.send_command(0x22);
            self.hw.send_data(0xC4);
            self.hw.send_command(0x20);
            self.hw.send_command(0xFF);
            self.hw.wait_busy(true);
        }

        fn display_base_image(&mut self, buf: &[u8]) {
            self.display(buf);
        }

        fn display_partial(&mut self, buf: &[u8]) -> Result<(), String> {
            // V1 has no partial update — do full update
            self.display(buf);
            Ok(())
        }

        fn clear(&mut self) {
            let buf = vec![0xFF; ((122 + 7) / 8) as usize * 250];
            self.display(&buf);
        }

        fn sleep(&mut self) -> Result<(), String> {
            self.hw.send_command(0x10);
            self.hw.send_data(0x01);
            thread::sleep(Duration::from_secs(2));
            self.hw.power_off();
            Ok(())
        }
    }

    // ==== 2.13" V2 ====
    struct Epd2in13V2 {
        hw: SpiHw,
    }

    impl EpdDisplay for Epd2in13V2 {
        fn width(&self) -> u32 {
            122
        }
        fn height(&self) -> u32 {
            250
        }

        fn init(&mut self) -> Result<(), String> {
            self.hw.reset(200);
            self.hw.wait_busy(true);
            self.hw.send_command(0x12); // Soft reset
            self.hw.wait_busy(true);
            self.hw.send_command(0x74); // Analog block control
            self.hw.send_data(0x54);
            self.hw.send_command(0x7E); // Digital block control
            self.hw.send_data(0x3B);
            self.hw.send_command(0x01); // Driver output control
            self.hw.send_data(0xF9);
            self.hw.send_data(0x00);
            self.hw.send_data(0x00);
            self.hw.send_command(0x11); // Data entry mode
            self.hw.send_data(0x01);
            self.hw.set_window(0, 0, 122 - 1, 250 - 1);
            self.hw.send_command(0x3C); // Border waveform
            self.hw.send_data(0x03);
            self.hw.send_command(0x2C); // VCOM
            self.hw.send_data(0x55);
            self.hw.send_command(0x03); // Gate voltage
            self.hw.send_data(LUT_V2_FULL[70]);
            self.hw.send_command(0x04); // Source voltage
            self.hw.send_data(LUT_V2_FULL[71]);
            self.hw.send_data(LUT_V2_FULL[72]);
            self.hw.send_data(LUT_V2_FULL[73]);
            self.hw.send_command(0x3A); // Dummy line
            self.hw.send_data(LUT_V2_FULL[74]);
            self.hw.send_command(0x3B); // Gate time
            self.hw.send_data(LUT_V2_FULL[75]);
            self.hw.send_command(0x32); // LUT
            self.hw.send_data_bulk(&LUT_V2_FULL[..70]);
            self.hw.set_cursor(0, 249);
            self.hw.wait_busy(true);
            Ok(())
        }

        fn init_partial(&mut self) -> Result<(), String> {
            self.hw.reset(200);
            self.hw.send_command(0x2C); // VCOM
            self.hw.send_data(0x26);
            self.hw.wait_busy(true);
            self.hw.send_command(0x32); // LUT
            self.hw.send_data_bulk(&LUT_V2_PARTIAL[..70]);
            self.hw.send_command(0x37); // Display option
            for &b in &[0x00u8, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00] {
                self.hw.send_data(b);
            }
            self.hw.send_command(0x22);
            self.hw.send_data(0xC0);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
            self.hw.send_command(0x3C); // Border waveform
            self.hw.send_data(0x01);
            Ok(())
        }

        fn display(&mut self, buf: &[u8]) {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xC7);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
        }

        fn display_base_image(&mut self, buf: &[u8]) {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x26);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xC7);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
        }

        fn display_partial(&mut self, buf: &[u8]) -> Result<(), String> {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0x0C);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
            Ok(())
        }

        fn clear(&mut self) {
            let buf = vec![0xFF; ((122 + 7) / 8) as usize * 250];
            self.display(&buf);
        }

        fn sleep(&mut self) -> Result<(), String> {
            self.hw.send_command(0x10);
            self.hw.send_data(0x03);
            thread::sleep(Duration::from_secs(2));
            self.hw.power_off();
            Ok(())
        }
    }

    // ==== 2.13" V3 ====
    struct Epd2in13V3 {
        hw: SpiHw,
    }

    impl Epd2in13V3 {
        fn set_lut(&mut self, lut: &[u8; 159]) {
            self.hw.send_command(0x32);
            self.hw.send_data_bulk(&lut[..153]);
            self.hw.wait_busy(true);
            self.hw.send_command(0x3F);
            self.hw.send_data(lut[153]);
            self.hw.send_command(0x03);
            self.hw.send_data(lut[154]);
            self.hw.send_command(0x04);
            self.hw.send_data(lut[155]);
            self.hw.send_data(lut[156]);
            self.hw.send_data(lut[157]);
            self.hw.send_command(0x2C);
            self.hw.send_data(lut[158]);
        }
    }

    impl EpdDisplay for Epd2in13V3 {
        fn width(&self) -> u32 {
            122
        }
        fn height(&self) -> u32 {
            250
        }

        fn init(&mut self) -> Result<(), String> {
            self.hw.reset(20);
            self.hw.wait_busy(true);
            self.hw.send_command(0x12); // Soft reset
            self.hw.wait_busy(true);
            self.hw.send_command(0x01);
            self.hw.send_data(0xF9);
            self.hw.send_data(0x00);
            self.hw.send_data(0x00);
            self.hw.send_command(0x11);
            self.hw.send_data(0x03);
            self.hw.set_window(0, 0, 122 - 1, 250 - 1);
            self.hw.set_cursor(0, 0);
            self.hw.send_command(0x3C);
            self.hw.send_data(0x05);
            self.hw.send_command(0x21);
            self.hw.send_data(0x00);
            self.hw.send_data(0x80);
            self.hw.send_command(0x18);
            self.hw.send_data(0x80);
            self.hw.wait_busy(true);
            self.set_lut(&LUT_V3_FULL);
            Ok(())
        }

        fn init_partial(&mut self) -> Result<(), String> {
            self.init()
        }

        fn display(&mut self, buf: &[u8]) {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xC7);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
        }

        fn display_base_image(&mut self, buf: &[u8]) {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x26);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xC7);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
        }

        fn display_partial(&mut self, buf: &[u8]) -> Result<(), String> {
            self.hw.rst.set_low();
            thread::sleep(Duration::from_millis(1));
            self.hw.rst.set_high();
            self.set_lut(&LUT_V3_PARTIAL);
            self.hw.send_command(0x37); // Display option
            for &b in &[0x00u8, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00] {
                self.hw.send_data(b);
            }
            self.hw.send_command(0x3C);
            self.hw.send_data(0x80);
            self.hw.send_command(0x22);
            self.hw.send_data(0xC0);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
            self.hw.set_window(0, 0, 122 - 1, 250 - 1);
            self.hw.set_cursor(0, 0);
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0x0F);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
            Ok(())
        }

        fn clear(&mut self) {
            let buf = vec![0xFF; ((122 + 7) / 8) as usize * 250];
            self.display(&buf);
        }

        fn sleep(&mut self) -> Result<(), String> {
            self.hw.send_command(0x10);
            self.hw.send_data(0x01);
            thread::sleep(Duration::from_secs(2));
            self.hw.power_off();
            Ok(())
        }
    }

    // ==== 2.13" V4 ====
    struct Epd2in13V4 {
        hw: SpiHw,
    }

    impl EpdDisplay for Epd2in13V4 {
        fn width(&self) -> u32 {
            122
        }
        fn height(&self) -> u32 {
            250
        }

        fn init(&mut self) -> Result<(), String> {
            self.hw.reset(20);
            self.hw.wait_busy(true);
            self.hw.send_command(0x12); // Soft reset
            self.hw.wait_busy(true);
            self.hw.send_command(0x01);
            self.hw.send_data(0xF9);
            self.hw.send_data(0x00);
            self.hw.send_data(0x00);
            self.hw.send_command(0x11);
            self.hw.send_data(0x03);
            self.hw.set_window(0, 0, 122 - 1, 250 - 1);
            self.hw.set_cursor(0, 0);
            self.hw.send_command(0x3C);
            self.hw.send_data(0x05);
            self.hw.send_command(0x21);
            self.hw.send_data(0x00);
            self.hw.send_data(0x80);
            self.hw.send_command(0x18);
            self.hw.send_data(0x80);
            self.hw.wait_busy(true);
            Ok(())
        }

        fn init_partial(&mut self) -> Result<(), String> {
            self.init()
        }

        fn display(&mut self, buf: &[u8]) {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xF7);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
        }

        fn display_base_image(&mut self, buf: &[u8]) {
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x26);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xF7);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
        }

        fn display_partial(&mut self, buf: &[u8]) -> Result<(), String> {
            self.hw.rst.set_low();
            thread::sleep(Duration::from_millis(1));
            self.hw.rst.set_high();
            self.hw.send_command(0x3C);
            self.hw.send_data(0x80);
            self.hw.send_command(0x01);
            self.hw.send_data(0xF9);
            self.hw.send_data(0x00);
            self.hw.send_data(0x00);
            self.hw.send_command(0x11);
            self.hw.send_data(0x03);
            self.hw.set_window(0, 0, 122 - 1, 250 - 1);
            self.hw.set_cursor(0, 0);
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x22);
            self.hw.send_data(0xFF);
            self.hw.send_command(0x20);
            self.hw.wait_busy(true);
            Ok(())
        }

        fn clear(&mut self) {
            let buf = vec![0xFF; ((122 + 7) / 8) as usize * 250];
            self.display(&buf);
        }

        fn sleep(&mut self) -> Result<(), String> {
            self.hw.send_command(0x10);
            self.hw.send_data(0x01);
            thread::sleep(Duration::from_secs(2));
            self.hw.power_off();
            Ok(())
        }
    }

    // ==== 2.7" ====
    struct Epd2in7 {
        hw: SpiHw,
    }

    impl Epd2in7 {
        fn set_lut(&mut self) {
            self.hw.send_command(0x20);
            self.hw.send_data_bulk(&LUT_27_VCOM_DC);
            self.hw.send_command(0x21);
            self.hw.send_data_bulk(&LUT_27_WW);
            self.hw.send_command(0x22);
            self.hw.send_data_bulk(&LUT_27_BW);
            self.hw.send_command(0x23);
            self.hw.send_data_bulk(&LUT_27_BB);
            self.hw.send_command(0x24);
            self.hw.send_data_bulk(&LUT_27_WB);
        }
    }

    impl EpdDisplay for Epd2in7 {
        fn width(&self) -> u32 {
            176
        }
        fn height(&self) -> u32 {
            264
        }

        fn init(&mut self) -> Result<(), String> {
            self.hw.reset(200);
            self.hw.send_command(0x01); // Power setting
            for &b in &[0x03u8, 0x00, 0x2B, 0x2B, 0x09] {
                self.hw.send_data(b);
            }
            self.hw.send_command(0x06); // Booster soft start
            for &b in &[0x07u8, 0x07, 0x17] {
                self.hw.send_data(b);
            }
            // Power optimization
            for &(cmd2, val) in &[
                (0x60u8, 0xA5u8),
                (0x89, 0xA5),
                (0x90, 0x00),
                (0x93, 0x2A),
                (0xA0, 0xA5),
                (0xA1, 0x00),
                (0x73, 0x41),
            ] {
                self.hw.send_command(0xF8);
                self.hw.send_data(cmd2);
                self.hw.send_data(val);
            }
            self.hw.send_command(0x16); // Partial display refresh
            self.hw.send_data(0x00);
            self.hw.send_command(0x04); // Power on
            self.hw.wait_busy(false); // 2.7": LOW=busy
            self.hw.send_command(0x00); // Panel setting
            self.hw.send_data(0xAF);
            self.hw.send_command(0x30); // PLL control
            self.hw.send_data(0x3A);
            self.hw.send_command(0x50); // VCOM interval
            self.hw.send_data(0x57);
            self.hw.send_command(0x82); // VCM DC
            self.hw.send_data(0x12);
            self.set_lut();
            Ok(())
        }

        fn init_partial(&mut self) -> Result<(), String> {
            self.init()
        }

        fn display(&mut self, buf: &[u8]) {
            let size = ((176 + 7) / 8) * 264;
            // Write old RAM (0x10) with white
            self.hw.send_command(0x10);
            self.hw.send_data_bulk(&vec![0xFF; size as usize]);
            // Write new RAM (0x13) with image
            self.hw.send_command(0x13);
            self.hw.send_data_bulk(buf);
            self.hw.send_command(0x12); // Display refresh
            self.hw.wait_busy(false);
        }

        fn display_base_image(&mut self, buf: &[u8]) {
            self.display(buf);
        }

        fn display_partial(&mut self, buf: &[u8]) -> Result<(), String> {
            // 2.7" has no partial update — do full update
            self.display(buf);
            Ok(())
        }

        fn clear(&mut self) {
            let size = ((176 + 7) / 8) * 264;
            let buf = vec![0xFF; size as usize];
            self.hw.send_command(0x10);
            self.hw.send_data_bulk(&buf);
            self.hw.send_command(0x13);
            self.hw.send_data_bulk(&buf);
            self.hw.send_command(0x12);
            self.hw.wait_busy(false);
        }

        fn sleep(&mut self) -> Result<(), String> {
            self.hw.send_command(0x50);
            self.hw.send_data(0xF7);
            self.hw.send_command(0x02); // Power off
            self.hw.send_command(0x07); // Deep sleep
            self.hw.send_data(0xA5);
            thread::sleep(Duration::from_secs(2));
            self.hw.power_off();
            Ok(())
        }
    }

    pub fn create_display(epd_type: &str) -> Option<Box<dyn EpdDisplay>> {
        let hw = SpiHw::new()?;
        let display: Box<dyn EpdDisplay> = match epd_type {
            "epd2in13" => Box::new(Epd2in13V1 { hw }),
            "epd2in13_V2" => Box::new(Epd2in13V2 { hw }),
            "epd2in13_V3" => Box::new(Epd2in13V3 { hw }),
            "epd2in13_V4" => Box::new(Epd2in13V4 { hw }),
            "epd2in7" => Box::new(Epd2in7 { hw }),
            other => {
                tracing::warn!(epd_type = %other, "unknown epd_type, defaulting to V4");
                Box::new(Epd2in13V4 { hw })
            }
        };
        Some(display)
    }
}

#[cfg(not(target_os = "linux"))]
mod hw {
    use super::*;

    struct StubDisplay {
        w: u32,
        h: u32,
    }

    impl EpdDisplay for StubDisplay {
        fn width(&self) -> u32 {
            self.w
        }
        fn height(&self) -> u32 {
            self.h
        }
        fn init(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn init_partial(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn display(&mut self, _buf: &[u8]) {}
        fn display_base_image(&mut self, _buf: &[u8]) {}
        fn display_partial(&mut self, _buf: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn clear(&mut self) {}
        fn sleep(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    pub fn create_display(_epd_type: &str) -> Option<Box<dyn EpdDisplay>> {
        None
    }
}
