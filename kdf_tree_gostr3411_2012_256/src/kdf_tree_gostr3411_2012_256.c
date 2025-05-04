#include "kdf_tree_gostr3411_2012_256.h"
#include "streebog.h"

static void encode_value_to_be(uint64_t value, uint8_t *out, uint8_t number_of_bytes)
{
    for (uint8_t i = 0; i < number_of_bytes; ++i)
    {
        out[i] = (value >> (8 * (number_of_bytes - 1 - i))) & 0xFF;
    }
}

/**
 * @brief Диверсификация ключа с использованием алгоритма kdf_tree_gostr3411_2012_256.
 *
 * @param key Ключ диверсфикации
 * @param key_len длина `key` в битах
 * @param label фиксируемый протоколом параметр
 * @param label_len длина `label` в байтах
 * @param seed фиксируемый протоколом параметр
 * @param seed_len длина `seed` в байтах
 * @param R параметр со значениями от 1 до 4, определяющий длину [i]_b
 * @param derived_key буффер для хранения диверсифицированного ключа
 * @param derived_key_len длина `derived_key` в битах
 */
void kdf_tree_gostr3411_2012_256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *label,
    size_t label_len,
    const uint8_t *seed,
    size_t seed_len,
    size_t R,
    uint8_t *derived_key,
    size_t derived_key_len)
{
    size_t n = (derived_key_len + 255) / 256;
    // K(i)
    for (size_t i = 0; i < n; i++)
    {
        Streebog sb = {0};
        streebog_new(&sb);

        size_t L_len = (derived_key_len == 0) ? 1 : (32 - __builtin_clz(derived_key_len) + 7) / 8;
        size_t buf_len = sizeof(uint8_t) * R +         // [i]_b
                         sizeof(uint8_t) * label_len + // label
                         sizeof(uint8_t) * 1 +         // 0x00
                         sizeof(uint8_t) * seed_len +  // seed
                         sizeof(uint8_t) * L_len;      // [L]_b
        uint8_t *buf = (uint8_t *)malloc(buf_len);

        memset(buf, 0, buf_len);
        // buf = [i]_b
        uint8_t *i_byte = (uint8_t *)malloc(sizeof(uint8_t) * R);
        encode_value_to_be(i + 1, i_byte, R);
        memcpy(buf, i_byte, R);

        // buf = [i]_b | label
        memcpy(buf + R, label, label_len);

        // buf = [i]_b | label | 0x00
        buf[R + label_len] = 0x00;

        // buf = [i]_b | label | 0x00 | seed
        memcpy(buf + R + label_len + 1, seed, seed_len);

        // buf = [i]_b | label | 0x00 | seed | [L]_b
        uint8_t *L_byte = (uint8_t *)malloc(sizeof(uint8_t) * L_len);
        encode_value_to_be(derived_key_len, L_byte, L_len);
        memcpy(buf + R + label_len + 1 + seed_len, L_byte, L_len);

        streebog_hmac_256(key, key_len, buf, buf_len, derived_key + (i * 32));

        streebog_clear_buf(i_byte, sizeof(uint8_t) * R);
        streebog_clear_buf(L_byte, sizeof(uint8_t) * L_len);
        streebog_clear_buf(buf, sizeof(uint8_t) * buf_len);

        free(L_byte);
        free(i_byte);
        free(buf);
    }
}