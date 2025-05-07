#include "chacha20.h"
#include "kdf_tree_gostr3411_2012_256.h"

void usage(char *argv[])
{
    printf("Usage: %s <input_file> <output_file>\n", argv[0]);
    exit(1);
}

int main(int argc, char *argv[])
{
    // ШАГ 1
    // Диверсифицируем ключ, полученный из /dev/urandom
    uint8_t key[32] = {0};
    chacha_clear_buf(key, sizeof(key));
    uint8_t label[5] = {0x61, 0x62, 0x6f, 0x62, 0x61};
    uint8_t seed[] = {
        0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78};
    uint8_t derived_key[32] = {0};
    kdf_tree_gostr3411_2012_256(
        key, sizeof(key) / sizeof(key[0]) * 8,
        label, sizeof(label) / sizeof(label[0]),
        seed, sizeof(seed) / sizeof(seed[0]),
        1,
        derived_key, sizeof(derived_key) / sizeof(derived_key[0]));

    // ШАГ 2
    // Генерируем случайные байты с помощью ChaCha20 и
    // записываем их в файл
    ChaCha20 chacha = {0};
    uint32_t nonce[3] = {0x1, 0x20000000, 0x3};
    chacha_new(&chacha, derived_key, (const uint32_t *)nonce, 0);

    FILE *fp = fopen("output.bin", "wb");
    chacha_prng(&chacha, fp, 10000000);
    return 0;
}
