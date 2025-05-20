#include "chacha20.h"

const char *file_1Mb_out = "./out/1Mb";
const char *file_100Mb_out = "./out/100Mb";
const char *file_1000Mb_out = "./out/1000Mb";
const char *file_keys_out = "./out/keys";

void prng(const char *file_path, int bytes_count)
{
    uint8_t key[32] = {0};
    chacha_clear_buf(key, 32);

    ChaCha20 chacha = {0};
    uint32_t nonce[3] = {0x1, 0x20000000, 0x3};
    chacha_new(&chacha, key, (const uint32_t *)nonce, 0);

    FILE *fp = fopen(file_path, "wb");
    chacha_prng(&chacha, fp, bytes_count);
}

void generate_keys()
{
    uint8_t key[32] = {0};
    chacha_clear_buf(key, 32);

    ChaCha20 chacha = {0};
    uint32_t nonce[3] = {0x1, 0x20000000, 0x3};
    chacha_new(&chacha, key, (const uint32_t *)nonce, 0);

    FILE *fp = fopen(file_keys_out, "wb");
    chacha_prng(&chacha, fp, 10000 * 64);
}

void run_test_suite()
{
    // prng(file_1Mb_out, 1048576);
    // prng(file_100Mb_out, 104857600);
    // prng(file_1000Mb_out, 1048576000);
    generate_keys();
}

int main()
{
    run_test_suite();
    return 0;
}