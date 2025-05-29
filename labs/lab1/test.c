#include "kuznyechik.h"
#include "kdf_tree_gostr3411_2012_256.h"

const char *file_1Mb_in = "./in/1Mb";
const char *file_1Mb_out = "./out/1Mb";
const char *file_1Mb_dec = "./dec/1Mb";

const char *file_100Mb_in = "./in/100Mb";
const char *file_100Mb_out = "./out/100Mb";
const char *file_100Mb_dec = "./dec/100Mb";

const char *file_1000Mb_in = "./in/1000Mb";
const char *file_1000Mb_out = "./out/1000Mb";
const char *file_1000Mb_dec = "./dec/1000Mb";

const char *file_mil_blocks_in = "./in/mil_blocks";
const char *file_mil_blocks_out = "./out/mil_blocks";
const char *file_mil_blocks_dec = "./dec/mil_blocks";

void encrypt_1Mb()
{
    const char *path_in = file_1Mb_in;
    const char *path_out = file_1Mb_out;
    const char *path_dec = file_1Mb_dec;

    FILE *f_in = fopen(path_in, "rb");
    if (f_in == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_in);
        perror("fopen");
        exit(1);
    }
    FILE *f_out = fopen(path_out, "w+b");
    if (f_out == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_out);
        perror("fopen");
        exit(1);
    }
    FILE *f_dec = fopen(path_dec, "w+b");
    if (f_dec == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_dec);
        perror("fopen");
        exit(1);
    }

    kuz_key_t key = {
        0x83, 0xf6, 0x1e, 0x13, 0xde, 0x22, 0x50, 0x51,
        0x6c, 0x80, 0x53, 0xc3, 0xc2, 0xea, 0x92, 0x63,
        0xf5, 0x1d, 0x17, 0xae, 0xdc, 0x37, 0xd3, 0x7e,
        0x51, 0x54, 0x52, 0xb1, 0xfe, 0xf8, 0x04, 0x32};
    Kuznyechik kuz;
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_in, f_out, &kuz);
    fseek(f_out, 0, SEEK_SET);

    kuz_clear(&kuz);
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_out, f_dec, &kuz);

    kuz_clear(&kuz);
    fclose(f_dec);
    fclose(f_out);
    fclose(f_in);
}

void encrypt_100Mb()
{
    const char *path_in = file_100Mb_in;
    const char *path_out = file_100Mb_out;
    const char *path_dec = file_100Mb_dec;

    FILE *f_in = fopen(path_in, "rb");
    if (f_in == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_in);
        perror("fopen");
        exit(1);
    }
    FILE *f_out = fopen(path_out, "w+b");
    if (f_out == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_out);
        perror("fopen");
        exit(1);
    }
    FILE *f_dec = fopen(path_dec, "w+b");
    if (f_dec == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_dec);
        perror("fopen");
        exit(1);
    }

    kuz_key_t key = {
        0x83, 0xf6, 0x1e, 0x13, 0xde, 0x22, 0x50, 0x51,
        0x6c, 0x80, 0x53, 0xc3, 0xc2, 0xea, 0x92, 0x63,
        0xf5, 0x1d, 0x17, 0xae, 0xdc, 0x37, 0xd3, 0x7e,
        0x51, 0x54, 0x52, 0xb1, 0xfe, 0xf8, 0x04, 0x32};
    Kuznyechik kuz;
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_in, f_out, &kuz);
    fseek(f_out, 0, SEEK_SET);

    kuz_clear(&kuz);
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_out, f_dec, &kuz);

    kuz_clear(&kuz);
    fclose(f_dec);
    fclose(f_out);
    fclose(f_in);
}

void encrypt_1000Mb()
{
    const char *path_in = file_1000Mb_in;
    const char *path_out = file_1000Mb_out;
    const char *path_dec = file_1000Mb_dec;

    FILE *f_in = fopen(path_in, "rb");
    if (f_in == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_in);
        perror("fopen");
        exit(1);
    }
    FILE *f_out = fopen(path_out, "w+b");
    if (f_out == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_out);
        perror("fopen");
        exit(1);
    }
    FILE *f_dec = fopen(path_dec, "w+b");
    if (f_dec == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_dec);
        perror("fopen");
        exit(1);
    }

    kuz_key_t key = {
        0x83, 0xf6, 0x1e, 0x13, 0xde, 0x22, 0x50, 0x51,
        0x6c, 0x80, 0x53, 0xc3, 0xc2, 0xea, 0x92, 0x63,
        0xf5, 0x1d, 0x17, 0xae, 0xdc, 0x37, 0xd3, 0x7e,
        0x51, 0x54, 0x52, 0xb1, 0xfe, 0xf8, 0x04, 0x32};
    Kuznyechik kuz;
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_in, f_out, &kuz);
    fseek(f_out, 0, SEEK_SET);

    kuz_clear(&kuz);
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_out, f_dec, &kuz);

    kuz_clear(&kuz);
    fclose(f_dec);
    fclose(f_out);
    fclose(f_in);
}

void encrypt_blocks_key_change(int cycles)
{
    const char *path_in = file_mil_blocks_in;
    const char *path_out = file_mil_blocks_out;
    const char *path_dec = file_mil_blocks_dec;

    FILE *f_in = fopen(path_in, "rb");
    if (f_in == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_in);
        perror("fopen");
        exit(1);
    }
    FILE *f_out = fopen(path_out, "w+b");
    if (f_out == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_out);
        perror("fopen");
        exit(1);
    }
    FILE *f_dec = fopen(path_dec, "w+b");
    if (f_dec == NULL)
    {
        fprintf(stderr, "fopen: %s\n", path_dec);
        perror("fopen");
        exit(1);
    }

    kuz_key_t key = {0}, old_key = {0};
    // Получаем ключ из /dev/urandom
    kuz_clear_buf(key, 32);
    memcpy(old_key, key, 32);
    Kuznyechik kuz;
    kuz_new(&kuz, key);

    kuz_ofb_encrypt_key_change(f_in, f_out, &kuz, cycles, key);
    fseek(f_out, 0, SEEK_SET);

    kuz_clear(&kuz);
    kuz_new(&kuz, old_key);

    kuz_ofb_encrypt_key_change(f_out, f_dec, &kuz, cycles, old_key);

    kuz_clear(&kuz);
    fclose(f_dec);
    fclose(f_out);
    fclose(f_in);
}

void run_test_suite()
{
    // encrypt_1Mb();
    // encrypt_100Mb();
    // encrypt_1000Mb();
    // encrypt_blocks_key_change(10);
    // encrypt_blocks_key_change(100);
    encrypt_blocks_key_change(1000);
}

int main()
{
    run_test_suite();
    return 0;
}