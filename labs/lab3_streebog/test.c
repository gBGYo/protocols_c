#include "streebog.h"

const char *file_1Mb_out = "./out/1Mb";
const char *file_100Mb_out = "./out/100Mb";
const char *file_1000Mb_out = "./out/1000Mb";
const char *file_keys_out = "./out/keys";

void prng(const char *file_path, int bytes_count)
{
    FILE *fp = fopen(file_path, "wb");
    streebog_prng(fp, bytes_count);
}

void generate_keys()
{
    FILE *fp = fopen(file_keys_out, "wb");
    streebog_prng(fp, 10000 * 32);
}

void run_test_suite()
{
    // prng(file_1Mb_out, 131072);
    prng(file_100Mb_out, 13107200);
    // prng(file_1000Mb_out, 131072000);
    // generate_keys(10000);
}

int main()
{
    run_test_suite();
    return 0;
}