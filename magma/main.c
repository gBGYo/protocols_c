#include "magma.h"

void usage(char *argv[])
{
    printf("Usage: %s <input_file> <output_file>\n", argv[0]);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage(argv);
    }

    FILE *f_in = fopen(argv[1], "rb");
    if (f_in == NULL)
    {
        fprintf(stderr, "fopen: %s\n", argv[2]);
        perror("fopen");
        exit(1);
    }
    FILE *f_out = fopen(argv[2], "wb");
    if (f_out == NULL)
    {
        fprintf(stderr, "fopen: %s\n", argv[2]);
        perror("fopen");
        exit(1);
    }

    uint8_t key[MAGMA_KEY_SIZE] = {
        0x83, 0xf6, 0x1e, 0x13, 0xde, 0x22, 0x50, 0x51,
        0x6c, 0x80, 0x53, 0xc3, 0xc2, 0xea, 0x92, 0x63,
        0xf5, 0x1d, 0x17, 0xae, 0xdc, 0x37, 0xd3, 0x7e,
        0x51, 0x54, 0x52, 0xb1, 0xfe, 0xf8, 0x04, 0x32};
    Magma magma;
    magma_new(&magma, key, NULL);

    fseek(f_in, 0, SEEK_END);
    size_t len = ftell(f_in);
    printf("len = %zu\n", len);
    fseek(f_in, 0, SEEK_SET);
    uint8_t *buf_in = malloc(len);
    if (fread(buf_in, 1, len, f_in) != len)
    {
        fprintf(stderr, "fread: %s\n", argv[1]);
        perror("fread");
        exit(1);
    }

    uint8_t *buf_out = malloc(len);
    magma_ctr_encrypt(&magma, buf_in, buf_out, len);

    fwrite(buf_out, 1, len, f_out);

    magma_clear(&magma);

    free(buf_in);
    free(buf_out);
    fclose(f_in);
    fclose(f_out);
    return 0;
}