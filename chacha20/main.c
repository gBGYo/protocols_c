#include "chacha20.h"

void usage(char *argv[])
{
    printf("Usage: %s <input_file> <output_file>\n", argv[0]);
    exit(1);
}

int main(int argc, char *argv[])
{
    ChaCha20 chacha = {0};
    // chacha_new(&chacha, key, s);
    return 0;
}
