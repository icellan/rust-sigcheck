build:
	cargo build --release
	cp target/release/libsigcheck.dylib ./lib
	go build -o sigcheck -ldflags="-r ./lib" sigcheck.go

header:
	cbindgen -c cbindgen.toml > ./lib/sigcheck.h

