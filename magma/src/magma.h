#ifndef KUZNYECHIK_H
#define KUZNYECHIK_H

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

#define MAGMA_BLOCK_SIZE 8 // n
#define MAGMA_KEY_SIZE 32

    typedef struct magma_iter_keys
    {
        uint32_t enc_keys[32];
    } magma_iter_keys;

    typedef struct Magma
    {
        magma_iter_keys iter_keys;
        uint8_t iv[4]; // IV \in V_{n/2}
    } Magma;

    void magma_expand_key(magma_iter_keys *iter_keys, const uint8_t key[32]);
    void magma_new(Magma *magma, const uint8_t key[32]);
    void magma_clear(Magma *magma);

    void magma_add_mod32(const uint32_t *a, const uint32_t *b, uint32_t *out);
    void magma_t(const uint32_t *a, uint32_t *out);
    void magma_g(const uint32_t *a, const uint32_t *k, uint32_t *out);
    void magma_G(uint32_t *a1, uint32_t *a0, const uint32_t *k);
    void magma_G_star(uint32_t *a1, uint32_t *a0, const uint32_t *k, uint64_t *out);

    void magma_encrypt(const uint8_t in[MAGMA_BLOCK_SIZE], uint8_t out[MAGMA_BLOCK_SIZE], magma_iter_keys *iter_keys);
    void magma_ctr_encrypt(Magma *magma, const uint8_t *in, uint8_t *out, size_t len);
    void magma_ctr_encrypt_file(Magma *magma, FILE *f_in, FILE *f_out);

#ifdef __cplusplus
}
#endif

#endif // KUZNYECHIK_H