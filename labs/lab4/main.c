#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "streebog.h"
#include "crisp.h"

int check_exe_integrity(char *exe_path)
{
    FILE *digest_fp = fopen("./lab4.digest", "rb");
    if (digest_fp == NULL)
    {
        log_error("не удается открыть файл lab4.digest");
        return 1;
    }
    uint8_t digest_buf[32] = {0};
    if (fread(digest_buf, 1, 32, digest_fp) != 32)
    {
        log_error("не удается прочитать содержимое файла lab4.digest");
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
                goto next_entry;
            }
        }

        log_info("учетная запись `%s` получила доступ", pw->pw_name);
        streebog_clear(&sb);
        fclose(user_db_fp);
        return 0;
    next_entry:
    }

    log_warn("неизвестная учетная запись `%s` попыталась получить доступ", pw->pw_name);
    streebog_clear(&sb);
    fclose(user_db_fp);
    return 1;
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
        streebog_clear_buf(key, 32);
        fclose(key_fp);
        return 1;
    }

    time_t now = time(NULL);
    if (now >= expire)
    {
        log_error("срок действия ключа истек в %ld; текущее время %ld", expire, now);
        streebog_clear_buf(key, 32);
        fclose(key_fp);
        return 1;
    }

    fclose(key_fp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 1)
    {
        printf("USAGE: %s\n", argv[0]);
        return 1;
    }
    FILE *log_fp = fopen("./lab4.log", "a+");
    if (log_add_fp(log_fp, LOG_TRACE) < 0)
    {
        fprintf(stderr, "не удается открыть файл lab4.log\n");
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

    uint8_t pt[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e};
    uint8_t seed[8] = {0};
    Crisp crisp_out = {0};
    crisp_new(&crisp_out, key, seed);
    uint8_t raw_crisp_message[2048] = {0};
    uint16_t raw_crisp_message_len = 0;
    crisp_encode(&crisp_out, pt, sizeof(pt) / sizeof(pt[0]), raw_crisp_message, &raw_crisp_message_len);
    log_trace("данные были успешно закодированы в CRISP-сообщение");

    Crisp crisp_in = {0};
    crisp_new(&crisp_in, key, seed);
    CrispMessage cm = {0};
    crisp_decode(&crisp_in, raw_crisp_message, raw_crisp_message_len, &cm);
    log_trace("данные были успешно декодированы из CRISP-сообщения");

    for (size_t i = 0; i < sizeof(pt) / sizeof(pt[0]); i++)
    {
        if (cm.payloadData[i] != pt[i])
        {
            log_error("cm.payloadData[%ld] != pt[%ld]: %02x != %02x", i, i, cm.payloadData[i], pt[i]);
            streebog_clear_buf(key, 32);
            crisp_clear(&crisp_out);
            crisp_clear(&crisp_in);
            return 1;
        }
        log_trace("cm.payloadData[%ld] == pt[%ld]: %02x == %02x", i, i, cm.payloadData[i], pt[i]);
    }

    streebog_clear_buf(key, 32);
    crisp_clear(&crisp_out);
    crisp_clear(&crisp_in);
    return 0;
}