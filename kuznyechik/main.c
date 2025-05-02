#include "kuznyechik.h"

void usage(char *argv[]) {
    printf("Usage: %s <input_file> <output_file>\n", argv[0]);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv);
    }

    FILE *f_in = fopen(argv[1], "rb");
    if (f_in == NULL) {
        fprintf(stderr, "fopen: %s\n", argv[2]);
        perror("fopen");
        exit(1);
    }
    FILE *f_out = fopen(argv[2], "wb");
    if (f_out == NULL) {
        fprintf(stderr, "fopen: %s\n", argv[2]);
        perror("fopen");
        exit(1);
    }

    kuz_key_t key = {
        0x83, 0xf6, 0x1e, 0x13, 0xde, 0x22, 0x50, 0x51,
        0x6c, 0x80, 0x53, 0xc3, 0xc2, 0xea, 0x92, 0x63, 
        0xf5, 0x1d, 0x17, 0xae, 0xdc, 0x37, 0xd3, 0x7e, 
        0x51, 0x54, 0x52, 0xb1, 0xfe, 0xf8, 0x04, 0x32
    };
    Kuznyechik kuz;
    kuz_new(&kuz, key);

    kuz_ofb_encrypt(f_in, f_out, &kuz);

    fclose(f_in);
    fclose(f_out);
    return 0;
}