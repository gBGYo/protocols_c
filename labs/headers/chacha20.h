#ifndef CHACHA20_H
#define CHACHA20_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>

    typedef struct ChaCha20
    {
        uint8_t key[32];   // 256-bit key
        uint32_t nonce[3]; // 96-bit nonce
        uint32_t counter;  // 32-bit counter
    } ChaCha20;

    void chacha_new(ChaCha20 *chacha, const uint8_t *key, const uint32_t *nonce, uint32_t counter);
    void chacha_clear(ChaCha20 *chacha);
    void chacha_encrypt(ChaCha20 *chacha, const uint8_t *input, uint8_t *output, size_t length);
    void chacha_prng(ChaCha20 *chacha, FILE *fp, size_t len);
    void chacha_clear_buf(uint8_t *buf, ssize_t size);

#ifdef __cplusplus
}
#endif

#endif // CHACHA20_H
