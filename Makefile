.PHONY: build build-pi-zero build-pi64 test clean install-deps

# Default: build for host
build:
	cargo build --release

# Pi Zero W (ARMv6, 32-bit)
build-pi-zero:
	cross build --release --target arm-unknown-linux-gnueabihf

# Pi Zero W2 / Pi 3/4/5 (64-bit)
build-pi64:
	cross build --release --target aarch64-unknown-linux-gnu

test:
	cargo test

clean:
	cargo clean

# Install cross-compilation tool
install-deps:
	cargo install cross
	rustup target add arm-unknown-linux-gnueabihf
	rustup target add aarch64-unknown-linux-gnu

# Deploy to Pi via SSH (usage: make deploy PI=bjorn@192.168.1.x)
deploy: build-pi-zero
	scp target/arm-unknown-linux-gnueabihf/release/bjorn $(PI):/home/bjorn/bjorn
	scp -r deploy/bjorn.service $(PI):/tmp/bjorn.service
	ssh $(PI) 'sudo mv /tmp/bjorn.service /etc/systemd/system/ && sudo systemctl daemon-reload'

deploy64: build-pi64
	scp target/aarch64-unknown-linux-gnu/release/bjorn $(PI):/home/bjorn/bjorn
	scp -r deploy/bjorn.service $(PI):/tmp/bjorn.service
	ssh $(PI) 'sudo mv /tmp/bjorn.service /etc/systemd/system/ && sudo systemctl daemon-reload'
