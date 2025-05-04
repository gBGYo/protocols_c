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

#define KUZ_BLOCK_SIZE 16 // n
#define KUZ_KEY_SIZE 32

    typedef uint8_t kuz_block_t[KUZ_BLOCK_SIZE];
    typedef uint8_t kuz_key_t[KUZ_KEY_SIZE];

    typedef struct kuz_iter_keys
    {
        kuz_block_t enc_keys[10];
    } kuz_iter_keys;

    typedef struct Kuznyechik
    {
        kuz_iter_keys iter_keys;
        uint8_t iv[2 * KUZ_BLOCK_SIZE]; // IV \in V_m, m = 2*n
    } Kuznyechik;

    void kuz_new(Kuznyechik *kuz, kuz_key_t key);
    void kuz_clear(Kuznyechik *kuz);

    uint8_t kuz_gf_mult(uint8_t a, uint8_t b);
    uint8_t kuz_linear(kuz_block_t a);
    void kuz_shift_right(kuz_block_t a);
    void kuz_shift_left(kuz_block_t a);

    void kuz_X(kuz_block_t a, kuz_block_t b, kuz_block_t out, size_t size);
    void kuz_S(kuz_block_t a);
    void kuz_R(kuz_block_t a);
    void kuz_L(kuz_block_t a);
    void kuz_F(kuz_block_t a0, kuz_block_t a1, kuz_block_t iter_const, kuz_block_t out1, kuz_block_t out2);
    void kuz_inv_S(kuz_block_t a);
    void kuz_inv_R(kuz_block_t a);
    void kuz_inv_L(kuz_block_t a);

    void kuz_clear_buf(uint8_t *buf, ssize_t size);

    // void kuz_gen_iter_C();
    // void kuz_print_iter_C();

    void kuz_expand_key(kuz_iter_keys *iter_keys, kuz_key_t key);
    void kuz_encrypt(const kuz_block_t in, kuz_block_t out, kuz_iter_keys *iter_keys);
    void kuz_decrypt(const kuz_block_t in, kuz_block_t out, kuz_iter_keys *iter_keys);

    // OFB -- Output Feedback
    void kuz_ofb_encrypt(FILE *f_in, FILE *f_out, Kuznyechik *kuz);
#define kuz_ofb_decrypt(f_in, f_out, kuz) kuz_ofb_encrypt(f_in, f_out, kuz)

#ifdef __cplusplus
}
#endif

#endif // KUZNYECHIK_H