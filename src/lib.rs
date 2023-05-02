extern crate libc;
extern crate secp256k1;

use secp256k1::{Message, PublicKey, Secp256k1};
use secp256k1::ecdsa::{Signature};
use std::os::raw::c_int;

#[no_mangle]
pub extern "C" fn verify_signature(c_msg: *const u8, c_sig:  *const u8, c_sig_length: libc::size_t, c_pubkey:  *const u8) -> c_int {
    let msg_slice = unsafe { std::slice::from_raw_parts(c_msg, 32) };
    let msg = Message::from_slice(&msg_slice).expect("32 bytes");
    let sig_slice = unsafe { std::slice::from_raw_parts(c_sig, c_sig_length) };
    let sig = Signature::from_der(&sig_slice).expect("a valid signature");
    let pubkey_slice = unsafe { std::slice::from_raw_parts(c_pubkey, 33) };
    let pubkey = PublicKey::from_slice(&pubkey_slice).expect("a valid pubkey");

    let secp256k1 = Secp256k1::new();
    if secp256k1.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
        1
    } else {
        0
    }
}
