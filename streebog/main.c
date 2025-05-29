#include "streebog.h"

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
        fprintf(stderr, "fopen: %s\n", argv[1]);
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

    Streebog sb = {0};
    streebog_new(&sb);
    streebog_hash_file(&sb, f_in, f_out);

    fclose(f_in);
    fclose(f_out);
    return 0;
}
