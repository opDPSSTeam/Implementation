.PHONY: build clean

build:
	cd vc_api && cargo build --release
	go build -o go-rust -ldflags="-r ./target/release" main.go

run: build
	./go-rust

clean:
	rm go-rust 
