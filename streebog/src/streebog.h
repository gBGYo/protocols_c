#ifndef STREEBOG_H
#define STREEBOG_H

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

#define STREEBOG_BLOCK_SIZE 64 // n
    typedef uint8_t streebog_block_t[STREEBOG_BLOCK_SIZE];

#define HMAC_BLOCK_SIZE 32
    typedef uint8_t hmac_block_t[HMAC_BLOCK_SIZE];

    typedef struct Streebog
    {
        streebog_block_t h;
        streebog_block_t N;
        streebog_block_t Sigma;
    } Streebog;

    void streebog_X(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t size);
    void streebog_P(streebog_block_t a, size_t size);
    void streebog_L(streebog_block_t a);
    void streebog_Add_mod512(streebog_block_t a, streebog_block_t b, streebog_block_t out);
    void streebog_E(streebog_block_t K, const streebog_block_t m, streebog_block_t out);
    void streebog_g(streebog_block_t h, const streebog_block_t m, streebog_block_t N);

    void streebog_new(Streebog *sb);
    void streebog_stage2(Streebog *sb, streebog_block_t m);
    void streebog_stage3(Streebog *sb, streebog_block_t m, size_t size);

    void streebog_hash_file(Streebog *sb, FILE *f_in, FILE *f_out);
    void streebog_hash_array(Streebog *sb, uint8_t *array, size_t len, uint8_t *out);

    void streebog_clear_buf(uint8_t *buf, ssize_t size);

    void streebog_hmac_256(uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, hmac_block_t out);

#ifdef __cplusplus
}
#endif

#endif // STREEBOG_H
