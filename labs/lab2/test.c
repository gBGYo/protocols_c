#include "kdf_tree_gostr3411_2012_256.h"

const char *file_keys_out = "./out/keys";

uint8_t label[5] = {0x61, 0x62, 0x6f, 0x62, 0x61};
uint8_t seed[] = {0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78};

__attribute__((optimize(0))) void get_initial_key(uint8_t *buf, ssize_t size)
{
    if (getrandom(buf, size, 0) != size)
    {
        perror("getrandom");
        exit(1);
    }
}

void generate_keys()
{
    uint8_t key[32] = {0};
    // Получаем ключ из /dev/urandom
    get_initial_key(key, 32);

    for (size_t i = 0; i < 10000; i++)
    {
        kdf_tree_gostr3411_2012_256(
            key, 32 * 8,
            label, sizeof(label) / sizeof(label[0]),
            seed, sizeof(seed) / sizeof(seed[0]),
            1,
            key, 32 * 8);
    }
}

void run_test_suite()
{
    generate_keys();
}

int main()
{
    run_test_suite();
    return 0;
}