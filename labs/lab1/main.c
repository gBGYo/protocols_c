#include "kuznyechik.h"
#include "streebog.h"
#include "log.h"
#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <string.h>

int check_exe_integrity(char *exe_path)
{
    FILE *digest_fp = fopen("./lab1.digest", "rb");
    if (digest_fp == NULL)
    {
        log_error("не удается открыть файл lab1.digest");
        return 1;
    }
    uint8_t digest_buf[32] = {0};
    if (fread(digest_buf, 1, 32, digest_fp) != 32)
    {
        log_error("не удается прочитать содержимое файла lab1.digest");
        return 1;
    }
    fseek(digest_fp, 0, SEEK_SET);

    FILE *exe_fp = fopen(exe_path, "rb");
    if (exe_fp == NULL)
    {
        log_error("не удается открыть файл %s", exe_path);
        return 1;
    }
    fseek(exe_fp, 0, SEEK_END);
    size_t exe_len = ftell(exe_fp);
    fseek(exe_fp, 0, SEEK_SET);
    uint8_t *exe_buf = (uint8_t *)malloc(sizeof(uint8_t) * exe_len);
    if (fread(exe_buf, 1, exe_len, exe_fp) != exe_len)
    {
        log_error("не удается прочитать содержимое файла %s: %s", exe_path, strerror(errno));
        return 1;
    }
    fseek(exe_fp, 0, SEEK_SET);

    uint8_t exe_digest_buf[32] = {0};
    Streebog sb = {0};
    streebog_new(&sb);
    streebog_hash_array(&sb, exe_buf, exe_len, exe_digest_buf);

    for (size_t i = 0; i < 32; i++)
    {
        if (exe_digest_buf[i] != digest_buf[i])
        {
            log_warn("хэш-сумма расходится в байтовой позиции i=%ld", i);
            return 1;
        }
    }

    streebog_clear(&sb);
    free(exe_buf);
    fclose(exe_fp);
    fclose(digest_fp);
    return 0;
}

int check_valid_user(struct passwd *pw)
{
    FILE *user_db_fp = fopen("./users.db", "rb");
    if (user_db_fp == NULL)
    {
        log_error("не удается открыть файл users.db");
        return 1;
    }

    uint8_t username_digest[32] = {0};
    Streebog sb = {0};
    streebog_new(&sb);
    streebog_hash_array(&sb, (uint8_t *)pw->pw_name, strlen(pw->pw_name), username_digest);

    fseek(user_db_fp, 0, SEEK_END);
    uint32_t user_db_len = ftell(user_db_fp) / 32;
    fseek(user_db_fp, 0, SEEK_SET);
    for (size_t i = 0; i < user_db_len; i++)
    {
        uint8_t tmp_digest[32] = {0};
        if (fread(tmp_digest, 1, 32, user_db_fp) != 32)
        {
            log_error("не удается прочитать запись в файле users.db");
            streebog_clear(&sb);
            fclose(user_db_fp);
            return 1;
        }

        for (size_t j = 0; j < 32; j++)
        {
            if (username_digest[j] != tmp_digest[j])
            {
                log_warn("неизвестная учетная запись `%s` попыталась получить доступ", pw->pw_name);
                streebog_clear(&sb);
                fclose(user_db_fp);
                return 1;
            }
        }

        log_info("учетная запись `%s` получила доступ", pw->pw_name);
        streebog_clear(&sb);
        fclose(user_db_fp);
        return 0;
    }
    return 0;
}

int check_key_expiration(uint8_t key[32])
{
    FILE *key_fp = fopen("./key.db", "r");
    if (key_fp == NULL)
    {
        log_error("не удается открыть файл key.db");
        return 1;
    }
    if (fread(key, 1, 32, key_fp) != 32)
    {
        log_error("не удается прочитать содержимое файла key.db");
        fclose(key_fp);
        return 1;
    }

    time_t expire = 0;
    if (fread(&expire, 1, sizeof(time_t), key_fp) != sizeof(time_t))
    {
        log_error("не удается прочитать содержимое файла key.db");
        kuz_clear_buf(key, 32);
        fclose(key_fp);
        return 1;
    }

    time_t now = time(NULL);
    if (now >= expire)
    {
        log_error("срок действия ключа истек в %ld; текущее время %ld", expire, now);
        kuz_clear_buf(key, 32);
        fclose(key_fp);
        return 1;
    }

    fclose(key_fp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("USAGE: %s <file_in> <file_out>\n", argv[0]);
        return 1;
    }
    FILE *log_fp = fopen("./lab1.log", "a+");
    if (log_add_fp(log_fp, LOG_TRACE) < 0)
    {
        fprintf(stderr, "не удается открыть файл lab1.log\n");
        return 1;
    }

    if (check_exe_integrity(argv[0]) != 0)
    {
        fclose(log_fp);
        return 2;
    }

    struct passwd *pw = getpwuid(geteuid());
    if (pw == NULL)
    {
        log_error("не удается получить информацию об учетной записе пользователя с помощью getpwuid()");
        fclose(log_fp);
        return 1;
    }

    if (check_valid_user(pw) != 0)
    {
        fclose(log_fp);
        return 3;
    }

    uint8_t key[32] = {0};
    if (check_key_expiration(key) != 0)
    {
        fclose(log_fp);
        return 4;
    }

    FILE *in_fp = fopen(argv[1], "rb");
    if (in_fp == NULL)
    {
        log_error("не удается открыть файл %s", argv[1]);
        kuz_clear_buf(key, 32);
        fclose(log_fp);
        return 1;
    }
    fseek(in_fp, 0, SEEK_END);
    log_info("файл %s открыт на чтение; размер: %ld байт", argv[1], ftell(in_fp));
    fseek(in_fp, 0, SEEK_SET);

    FILE *out_fp = fopen(argv[2], "w+b");
    if (out_fp == NULL)
    {
        log_error("не удается открыть файл %s", argv[2]);
        kuz_clear_buf(key, 32);
        fclose(in_fp);
        fclose(log_fp);
        return 1;
    }
    fseek(out_fp, 0, SEEK_END);
    log_info("файл %s открыт на запись; размер: %ld байт", argv[2], ftell(out_fp));
    fseek(out_fp, 0, SEEK_SET);

    Kuznyechik kuz = {0};
    kuz_new(&kuz, key);
    kuz_ofb_encrypt(in_fp, out_fp, &kuz);

    log_info("успешно зашифровано %ld байт", ftell(out_fp));

    fclose(in_fp);
    fclose(out_fp);
    kuz_clear(&kuz);
    kuz_clear_buf(key, 32);
    fclose(log_fp);
    return 0;
}