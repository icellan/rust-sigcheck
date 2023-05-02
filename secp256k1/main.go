package main

// #include <stdlib.h>
// #include "secp256k1/include/secp256k1.h"
// #include "secp256k1/include/secp256k1_ecdh.h"
// #include "secp256k1/include/secp256k1_recovery.h"
/*
// https://groups.google.com/forum/#!topic/golang-nuts/pQueMFdY0mk
// for secp256k1_pubkey**
static secp256k1_pubkey** makePubkeyArray(int size) {
        return calloc(sizeof(secp256k1_pubkey*), size);
}
static void setArrayPubkey(secp256k1_pubkey **a, secp256k1_pubkey *pubkey, int n) {
        a[n] = pubkey;
}
static void freePubkeyArray(secp256k1_pubkey **a) {
        free(a);
}
*/
// #cgo LDFLAGS: ${SRCDIR}/secp256k1/.libs/libsecp256k1.a -lgmp
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

const (
	ContextVerify         = uint(C.SECP256K1_CONTEXT_VERIFY)
	ContextSign           = uint(C.SECP256K1_CONTEXT_SIGN)
	LenMsgHash     int    = 32
	ErrorMsg32Size string = "message hash must be exactly 32 bytes"
)

// Context wraps a *secp256k1_context, required to use all
// functions. It can be initialized for signing, verification,
// or both.
type Context struct {
	ctx *C.secp256k1_context
}

// EcdsaSignature wraps a *secp256k1_ecdsa_signature, containing the R
// and S values.
type EcdsaSignature struct {
	sig *C.secp256k1_ecdsa_signature
}

// PublicKey wraps a *secp256k1_pubkey, which contains the prefix plus
// the X+Y coordidnates
type PublicKey struct {
	pk *C.secp256k1_pubkey
}

// EcdsaVerify Verify an ECDSA signature. Return code is 1 for a correct signature,
// or 0 if incorrect. To avoid accepting malleable signature, only ECDSA
// signatures in lower-S form are accepted. If you need to accept ECDSA
// signatures from sources that do not obey this rule, apply
// EcdsaSignatureNormalize() prior to validation (however, this results in
// malleable signatures)
func EcdsaVerify(ctx *Context, sig *EcdsaSignature, msg32 []byte, pubkey *PublicKey) (int, error) {
	if len(msg32) != LenMsgHash {
		return 0, errors.New(ErrorMsg32Size)
	}
	result := C.secp256k1_ecdsa_verify(ctx.ctx, sig.sig, cBuf(msg32[:]), pubkey.pk)
	return int(result), nil
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}

func main() {
	msgBytes, err := hex.DecodeString("269d204413554cf4099df30554c8060ecc5f28302252167e6cc6c563c28dad7f")
	if err != nil {
		panic(err)
	}

	sigBytes, err := hex.DecodeString("304402206BA39DD04FCDDF34CA26F79FDD82E6238A1607BE01EB7F64A53CC83C567E46EE022039265C4D4CA4817FECBB42C943BEF51166C63F640DAD0A555A7A23221A894ECB")
	if err != nil {
		panic(err)
	}

	pubkeyBytes, err := hex.DecodeString("0390c85d6d1f222d2780996ca0666c483986e1762fd46be8fe80750285787186fd")
	if err != nil {
		panic(err)
	}

	ctx := &Context{
		ctx: C.secp256k1_context_create(C.uint(ContextSign | ContextVerify)),
	}
	sig := &EcdsaSignature{
		sig: &C.secp256k1_ecdsa_signature{},
	}
	sigResult := int(C.secp256k1_ecdsa_signature_parse_der(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&sigBytes[0])),
		(C.size_t)(len(sigBytes))))
	if sigResult != 1 {
		panic("signature parse failed")
	}

	pubkey := &PublicKey{
		pk: &C.secp256k1_pubkey{},
	}
	pubkeyResult := int(C.secp256k1_ec_pubkey_parse(ctx.ctx, pubkey.pk, cBuf(pubkeyBytes), C.size_t(len(pubkeyBytes))))
	if pubkeyResult != 1 {
		panic("pubkey parse failed")
	}

	result, err := EcdsaVerify(ctx, sig, msgBytes, pubkey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("result: %d\n", result)
}
