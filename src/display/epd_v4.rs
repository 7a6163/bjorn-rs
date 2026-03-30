/// Waveshare 2.13" e-Paper V4 driver.
///
/// Directly ports the SPI command sequences from
/// `resources/waveshare_epd/epd2in13_V4.py` and `epdconfig.py`.
///
/// Uses `rppal` for GPIO/SPI on Raspberry Pi.
/// On non-Linux platforms, this module compiles but `new()` returns `None`.

pub const EPD_WIDTH: u32 = 122;
pub const EPD_HEIGHT: u32 = 250;

// GPIO pin assignments (BCM numbering) — matches epdconfig.py
const RST_PIN: u8 = 17;
const DC_PIN: u8 = 25;
const BUSY_PIN: u8 = 24;
const PWR_PIN: u8 = 18;

#[cfg(target_os = "linux")]
mod hw {
    use rppal::gpio::{Gpio, InputPin, OutputPin};
    use rppal::spi::{Bus, Mode, SlaveSelect, Spi};
    use std::thread;
    use std::time::Duration;

    use super::*;

    pub struct Epd2in13V4 {
        spi: Spi,
        rst: OutputPin,
        dc: OutputPin,
        busy: InputPin,
        pwr: OutputPin,
    }

    impl Epd2in13V4 {
        pub fn new() -> Option<Self> {
            let gpio = Gpio::new().ok()?;
            let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 4_000_000, Mode::Mode0).ok()?;
            let rst = gpio.get(RST_PIN).ok()?.into_output();
            let dc = gpio.get(DC_PIN).ok()?.into_output();
            let busy = gpio.get(BUSY_PIN).ok()?.into_input();
            let mut pwr = gpio.get(PWR_PIN).ok()?.into_output();
            pwr.set_high();

            Some(Self { spi, rst, dc, busy, pwr })
        }

        fn reset(&mut self) {
            self.rst.set_high();
            thread::sleep(Duration::from_millis(20));
            self.rst.set_low();
            thread::sleep(Duration::from_millis(2));
            self.rst.set_high();
            thread::sleep(Duration::from_millis(20));
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
            // SPI transfer in chunks (rppal max ~4096 per transfer)
            for chunk in data.chunks(4096) {
                let _ = self.spi.write(chunk);
            }
        }

        fn wait_busy(&self) {
            // V4: 0=idle, 1=busy. Timeout after 10 seconds to prevent hanging.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while self.busy.is_high() {
                if std::time::Instant::now() > deadline {
                    tracing::warn!("e-Paper busy timeout (10s)");
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn set_window(&mut self, x_start: u32, y_start: u32, x_end: u32, y_end: u32) {
            self.send_command(0x44); // SET_RAM_X_ADDRESS_START_END_POSITION
            self.send_data((x_start >> 3) as u8);
            self.send_data((x_end >> 3) as u8);

            self.send_command(0x45); // SET_RAM_Y_ADDRESS_START_END_POSITION
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

        fn turn_on_display(&mut self) {
            self.send_command(0x22);
            self.send_data(0xF7);
            self.send_command(0x20);
            self.wait_busy();
        }

        fn turn_on_display_partial(&mut self) {
            self.send_command(0x22);
            self.send_data(0xFF);
            self.send_command(0x20);
            self.wait_busy();
        }

        /// Full initialization — matches epd2in13_V4.py `init()`.
        pub fn init(&mut self) -> Result<(), String> {
            self.reset();
            self.wait_busy();

            self.send_command(0x12); // SWRESET
            self.wait_busy();

            self.send_command(0x01); // Driver output control
            self.send_data(0xF9);   // (height - 1) & 0xFF = 249
            self.send_data(0x00);
            self.send_data(0x00);

            self.send_command(0x11); // Data entry mode
            self.send_data(0x03);

            self.set_window(0, 0, EPD_WIDTH - 1, EPD_HEIGHT - 1);
            self.set_cursor(0, 0);

            self.send_command(0x3C); // BorderWaveform
            self.send_data(0x05);

            self.send_command(0x21); // Display update control
            self.send_data(0x00);
            self.send_data(0x80);

            self.send_command(0x18); // Temperature sensor
            self.send_data(0x80);

            self.wait_busy();
            Ok(())
        }

        /// Initialize for partial update mode.
        pub fn init_partial(&mut self) -> Result<(), String> {
            // V4 uses the same init, partial mode is triggered by different
            // display update commands
            self.init()
        }

        /// Full display update.
        pub fn display(&mut self, buf: &[u8]) {
            self.send_command(0x24);
            self.send_data_bulk(buf);
            self.turn_on_display();
        }

        /// Write base image to both RAM banks (0x24 and 0x26).
        /// Must be called before `display_partial()` — matches
        /// epd2in13_V4.py `displayPartBaseImage()`.
        pub fn display_base_image(&mut self, buf: &[u8]) {
            self.send_command(0x24); // Write to RAM bank 1
            self.send_data_bulk(buf);
            self.send_command(0x26); // Write to RAM bank 2 (partial reference)
            self.send_data_bulk(buf);
            self.turn_on_display();
        }

        /// Partial display update — matches epd2in13_V4.py `displayPartial()`.
        pub fn display_partial(&mut self, buf: &[u8]) -> Result<(), String> {
            // Quick reset for partial
            self.rst.set_low();
            thread::sleep(Duration::from_millis(1));
            self.rst.set_high();

            self.send_command(0x3C); // BorderWaveform
            self.send_data(0x80);

            self.send_command(0x01); // Driver output control
            self.send_data(0xF9);
            self.send_data(0x00);
            self.send_data(0x00);

            self.send_command(0x11); // Data entry mode
            self.send_data(0x03);

            self.set_window(0, 0, EPD_WIDTH - 1, EPD_HEIGHT - 1);
            self.set_cursor(0, 0);

            self.send_command(0x24); // WRITE_RAM
            self.send_data_bulk(buf);
            self.turn_on_display_partial();

            Ok(())
        }

        /// Clear the display.
        pub fn clear(&mut self) {
            let line_width = ((EPD_WIDTH + 7) / 8) as usize;
            let buf = vec![0xFF; EPD_HEIGHT as usize * line_width];
            self.send_command(0x24);
            self.send_data_bulk(&buf);
            self.turn_on_display();
        }

        /// Enter deep sleep mode.
        pub fn sleep(&mut self) -> Result<(), String> {
            self.send_command(0x10);
            self.send_data(0x01);
            thread::sleep(Duration::from_secs(2));
            // Turn off power
            self.pwr.set_low();
            self.rst.set_low();
            self.dc.set_low();
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod hw {
    /// Stub for non-Linux platforms — allows compilation on macOS/Windows.
    pub struct Epd2in13V4;

    impl Epd2in13V4 {
        pub fn new() -> Option<Self> {
            None
        }
        pub fn init(&mut self) -> Result<(), String> { Ok(()) }
        pub fn init_partial(&mut self) -> Result<(), String> { Ok(()) }
        pub fn display(&mut self, _buf: &[u8]) {}
        pub fn display_base_image(&mut self, _buf: &[u8]) {}
        pub fn display_partial(&mut self, _buf: &[u8]) -> Result<(), String> { Ok(()) }
        pub fn clear(&mut self) {}
        pub fn sleep(&mut self) -> Result<(), String> { Ok(()) }
    }
}

pub use hw::Epd2in13V4;
