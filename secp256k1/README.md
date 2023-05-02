# C bindings for secp256k1 signature verification
> Experimental bindings for secp256k1 signature verification

> From: https://github.com/btccom/secp256k1-go

## Usage

```shell
git submodule update --init
cd secp256k1
./autogen.sh && ./configure --enable-experimental --enable-module-ecdh --enable-module-recovery && make -j4
cd ..
go build -o secp256k1.run main.go
```
