#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Positive 256-bit integer guaranteed to be less than the secp256k1 curve order.
 *
 * The difference between `PrivateKey` and `Scalar` is that `Scalar` doesn't guarantee being
 * securely usable as a private key.
 *
 * **Warning: the operations on this type are NOT constant time!**
 * Using this with secret values is not advised.
 */
typedef struct Scalar Scalar;







int verify_signature(const uint8_t *c_msg,
                     const uint8_t *c_sig,
                     size_t c_sig_length,
                     const uint8_t *c_pubkey);
