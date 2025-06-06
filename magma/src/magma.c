#include "magma.h"

#define STATIC_IV

// static const uint8_t magma_Pi[8][16] = {
//     {1, 15, 3, 0, 7, 13, 8, 14, 9, 11, 5, 10, 2, 6, 4, 12},
//     {15, 0, 13, 11, 7, 4, 14, 1, 12, 5, 10, 9, 3, 2, 8, 6},
//     {0, 6, 9, 12, 4, 7, 1, 14, 13, 10, 15, 2, 8, 5, 3, 11},
//     {11, 9, 14, 3, 5, 10, 0, 7, 6, 15, 4, 13, 1, 2, 8, 12},
//     {12, 2, 4, 11, 14, 3, 9, 0, 13, 6, 1, 8, 10, 5, 15, 7},
//     {0, 14, 3, 4, 1, 8, 7, 11, 10, 12, 2, 9, 6, 15, 13, 5},
//     {7, 3, 10, 13, 0, 11, 4, 15, 12, 1, 9, 6, 5, 2, 14, 8},
//     {2, 11, 12, 9, 6, 10, 15, 4, 3, 8, 5, 0, 13, 14, 7, 1},

// };
static const uint8_t magma_Pi[8][16] = {
    {0x0c, 0x04, 0x06, 0x02, 0x0a, 0x05, 0x0b, 0x09, 0x0e, 0x08, 0x0d, 0x07, 0x00, 0x03, 0x0f, 0x01},
    {0x06, 0x08, 0x02, 0x03, 0x09, 0x0a, 0x05, 0x0c, 0x01, 0x0e, 0x04, 0x07, 0x0b, 0x0d, 0x00, 0x0f},
    {0x0b, 0x03, 0x05, 0x08, 0x02, 0x0f, 0x0a, 0x0d, 0x0e, 0x01, 0x07, 0x04, 0x0c, 0x09, 0x06, 0x00},
    {0x0c, 0x08, 0x02, 0x01, 0x0d, 0x04, 0x0f, 0x06, 0x07, 0x00, 0x0a, 0x05, 0x03, 0x0e, 0x09, 0x0b},
    {0x07, 0x0f, 0x05, 0x0a, 0x08, 0x01, 0x06, 0x0d, 0x00, 0x09, 0x03, 0x0e, 0x0b, 0x04, 0x02, 0x0c},
    {0x05, 0x0d, 0x0f, 0x06, 0x09, 0x02, 0x0c, 0x0a, 0x0b, 0x07, 0x08, 0x01, 0x04, 0x03, 0x0e, 0x00},
    {0x08, 0x0e, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0c, 0x0f, 0x04, 0x0b, 0x00, 0x0d, 0x0a, 0x03, 0x07},
    {0x01, 0x07, 0x0e, 0x0d, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0f, 0x0a, 0x06, 0x09, 0x0c, 0x0b, 0x02},
};

// Секция 2.2
// Неприводимый многочлен
// p(x) = x^8 + x^7 + x^6 + x + 1 = 0b11000011 = 0xc3
#define MAGMA_POLY 0xc3

/**
 * @brief Очищает буфер `buf` размером `size` данными из /dev/urandom.
 */
__attribute__((optimize(0))) void magma_clear_buf(uint8_t *buf, ssize_t size)
{
    if (getrandom(buf, size, 0) != size)
    {
        perror("getrandom");
        exit(1);
    }
}

/**
 * @brief Инициализация структуры Magma
 *
 * @param magma Указатель на структуру Magma
 * @param key Ключ шифрования
 */
void magma_new(Magma *magma, const uint8_t key[32], const uint8_t iv[4])
{
    magma_expand_key(&magma->iter_keys, key);
    if (iv != NULL)
    {
        memcpy(magma->iv, iv, 4);
    }
    else
    {
#ifdef STATIC_IV
        uint8_t static_iv[4] = {0x50, 0x04, 0xae, 0x49};
        memcpy(magma->iv, static_iv, 4);
#else
        uint8_t random_iv[4];
        magma_clear_buf(random_iv, 4);
        memcpy(magma->iv, random_iv, 4);
        // Clear local iv
        magma_clear_buf(random_iv, 4);
#endif
    }
}

/**
 * @brief Очистка структуры Magma
 *
 * @param magma Указатель на структуру Magma
 */
void magma_clear(Magma *magma)
{
    magma_clear_buf(magma->iv, 4);
    for (int i = 0; i < 32; i++)
    {
        magma_clear_buf((uint8_t *)&magma->iter_keys.enc_keys[i], 4);
    }
}

/**
 * @brief Сложение по модулю 2^32
 *
 * @param a Входные данные
 * @param b Входные данные
 * @param out a + b (mod 2^32)
 */
void magma_add_mod32(const uint32_t *a, const uint32_t *b, uint32_t *out)
{
    uint32_t tmp = 0;
    *out = 0;
    for (int i = 0; i < 4; i++)
    {
        tmp = ((*a >> (i * 8)) & 0xff) + ((*b >> (i * 8)) & 0xff) + (tmp >> 8);
        *out |= (tmp & 0xff) << (i * 8);
    }
}

/**
 * @brief Сложение по модулю 2^64
 *
 * @param a Входные данные
 * @param b Входные данные
 * @param out a + b (mod 2^64)
 */
void magma_add_mod64(const uint64_t *a, const uint64_t *b, uint64_t *out)
{
    uint64_t tmp = 0;
    *out = 0;
    for (int i = 0; i < 8; i++)
    {
        tmp = ((*a >> (i * 8)) & 0xff) + ((*b >> (i * 8)) & 0xff) + (tmp >> 8);
        *out |= (tmp & 0xff) << (i * 8);
    }
}

/**
 * @brief Увеличение счетчика `ctr` на 1
 *
 * @param ctr Счетчик
 */
void magma_ctr_add(uint8_t *ctr)
{
    uint64_t one = 1;
    uint64_t tmp = ((uint64_t)ctr[0] << 56) | ((uint64_t)ctr[1] << 48) | ((uint64_t)ctr[2] << 40) | ((uint64_t)ctr[3] << 32) | ((uint64_t)ctr[4] << 24) | ((uint64_t)ctr[5] << 16) | ((uint64_t)ctr[6] << 8) | (uint64_t)ctr[7];
    uint64_t tmp2 = 0;
    magma_add_mod64(&tmp, &one, &tmp2);
    tmp = tmp2;
    for (size_t i = 0; i < 8; i++)
    {
        ctr[i] = (tmp >> (8 * (7 - i))) & 0xff;
    }
    magma_clear_buf((uint8_t *)&tmp, 8);
    magma_clear_buf((uint8_t *)&tmp2, 8);
}

/**
 * @brief Преобразование t из секции 5.2
 *
 * @param a Входные данные
 * @param out t(a) = pi_7(a_7) || ... || pi_0(a_0)
 */
void magma_t(const uint32_t *a, uint32_t *out)
{
    *out = 0;
    for (size_t i = 0; i < 8; i++)
    {
        *out |= magma_Pi[i][(*a >> (i * 4)) & 0x0f] << (i * 4);
    }
}

/**
 * @brief Преобразование g из секции 5.2
 *
 * @param a Входные данные
 * @param k Ключ
 * @param out g[k](a) = (t(Vec32(Int32(a) ⊞ Int32(k)))) ⋘_{11}
 */
void magma_g(const uint32_t *a, const uint32_t *k, uint32_t *out)
{
    uint32_t sum_out = 0;
    magma_add_mod32(a, k, &sum_out);
    magma_t(&sum_out, out);
    *out = (*out << 11) | (*out >> 21);
    magma_clear_buf((uint8_t *)&sum_out, 4);
}

/**
 * @brief Преобразование G[k](a1, a0) = (a0, g[k](a0) ⊕ a1) из секции 5.2
 *
 * @param a1 Входные данные
 * @param a0 Входные данные
 * @param k Ключ
 */
void magma_G(uint32_t *a1, uint32_t *a0, const uint32_t *k)
{
    uint32_t tmp = *a0;
    magma_g(a0, k, a0);
    *a0 ^= *a1;
    *a1 = tmp;
}

/**
 * @brief Преобразование G* из секции 5.2
 *
 * @param a1 Входные данные
 * @param a0 Входные данные
 * @param k Ключ
 * @param out G*[k](a1, a0) = (g[k](a0) ⊕ a1)||a0
 */
void magma_G_star(uint32_t *a1, uint32_t *a0, const uint32_t *k, uint64_t *out)
{
    uint32_t tmp = *a0;
    magma_g(a0, k, a0);
    *out = ((uint64_t)(*a0 ^ *a1) << 32) | tmp;
}

/**
 * @brief Алгоритм развертывания ключа из секции 5.3
 *
 * @param iter_keys Указатель на структуру итерационных ключей
 * @param key Ключ для развертывания
 */
void magma_expand_key(magma_iter_keys *iter_keys, const uint8_t key[32])
{
    for (size_t i = 0; i < 8; i++)
    {
        // memcpy(&iter_keys->enc_keys[i], key + (4 * i), sizeof(uint8_t) * 4);
        iter_keys->enc_keys[i] = key[4 * i + 3] | key[4 * i + 2] << 8 | key[4 * i + 1] << 16 | key[4 * i + 0] << 24;
    }
    for (size_t i = 0; i < 8; i++)
    {
        memcpy(&iter_keys->enc_keys[i + 8], &iter_keys->enc_keys[i], sizeof(uint8_t) * 4);
        memcpy(&iter_keys->enc_keys[i + 16], &iter_keys->enc_keys[i], sizeof(uint8_t) * 4);
        memcpy(&iter_keys->enc_keys[i + 24], &iter_keys->enc_keys[7 - i], sizeof(uint8_t) * 4);
    }
}

/**
 * @brief Шифрование блока данных
 *
 * @param in Входные данные
 * @param out Выходные данные
 * @param iter_keys Указатель на структуру итерационных ключей
 */
void magma_encrypt(const uint8_t in[MAGMA_BLOCK_SIZE], uint8_t out[MAGMA_BLOCK_SIZE], magma_iter_keys *iter_keys)
{
    uint64_t tmp = 0;
    uint32_t a1 = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
    uint32_t a0 = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
    for (size_t i = 0; i < 31; i++)
    {
        magma_G(&a1, &a0, &iter_keys->enc_keys[i]);
    }
    magma_G_star(&a1, &a0, &iter_keys->enc_keys[31], &tmp);
    for (size_t i = 0; i < 8; i++)
    {
        out[i] = (tmp >> (8 * (7 - i))) & 0xff;
    }
}

/**
 * @brief Шифрование данных в режиме CTR (ГОСТ 34.13-2018 секция 5.2)
 *
 * @param magma Указатель на структуру Magma
 * @param in Входные данные
 * @param out Выходные данные
 * @param len Длина данных
 */
void magma_ctr_encrypt(Magma *magma, const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ctr[MAGMA_BLOCK_SIZE] = {0};
    uint8_t gamma[MAGMA_BLOCK_SIZE] = {0};
    memcpy(ctr, magma->iv, 4);
    size_t bytes_encrypted = 0;
    for (size_t i = 0; i < len; i += 8)
    {
        magma_encrypt(ctr, gamma, &magma->iter_keys);
        magma_ctr_add(ctr);
        if (len - bytes_encrypted < MAGMA_BLOCK_SIZE)
        {
            for (size_t j = 0; j < len - bytes_encrypted; j++)
            {
                out[i + j] = in[i + j] ^ gamma[j];
            }
            break;
        }
        else
        {
            for (size_t j = 0; j < 8; j++)
            {
                out[i + j] = in[i + j] ^ gamma[j];
            }
        }
        bytes_encrypted += 8;
    }
    magma_clear_buf(gamma, MAGMA_BLOCK_SIZE);
}

/**
 * @brief Выработка имитовставки в режиме CMAC (ГОСТ 34.13-2018 секция 5.6)
 */
void magma_cmac(Magma *magma, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    uint8_t R[MAGMA_BLOCK_SIZE] = {0};
    magma_encrypt(R, R, &magma->iter_keys);
    uint64_t R_value = ((uint64_t)R[0] << 56) | ((uint64_t)R[1] << 48) | ((uint64_t)R[2] << 40) | ((uint64_t)R[3] << 32) | ((uint64_t)R[4] << 24) | ((uint64_t)R[5] << 16) | ((uint64_t)R[6] << 8) | (uint64_t)R[7];
    uint8_t R_MSB_1 = R[0] & 0x80;
    if (R_MSB_1 == 0)
    {
        R_value <<= 1; // R << 1
    }
    else
    {
        R_value = (R_value << 1) ^ (uint64_t)0x1b; // (R << 1) ^ B_64 (=0^{59}||11011)
    }
    uint8_t K1[MAGMA_BLOCK_SIZE] = {0};
    for (size_t i = 0; i < 8; i++)
    {
        K1[i] = (R_value >> ((7 - i) * 8)) & 0xff;
    }

    uint64_t K1_value = ((uint64_t)K1[0] << 56) | ((uint64_t)K1[1] << 48) | ((uint64_t)K1[2] << 40) | ((uint64_t)K1[3] << 32) | ((uint64_t)K1[4] << 24) | ((uint64_t)K1[5] << 16) | ((uint64_t)K1[6] << 8) | (uint64_t)K1[7];
    uint8_t K1_MSB_1 = K1[0] & 0x80;
    if (K1_MSB_1 == 0)
    {
        K1_value <<= 1; // K1 << 1
    }
    else
    {
        K1_value = (K1_value << 1) ^ (uint64_t)0x1b; // (K1 << 1) ^ B_64 (=0^{59}||11011)
    }
    uint8_t K2[MAGMA_BLOCK_SIZE] = {0};
    for (size_t i = 0; i < 8; i++)
    {
        K2[i] = (K1_value >> ((7 - i) * 8)) & 0xff;
    }

    size_t bytes_encrypted = 0;
    uint8_t block[MAGMA_BLOCK_SIZE] = {0};
    for (size_t i = 0; i + MAGMA_BLOCK_SIZE < in_len; i += 8)
    {
        for (size_t j = 0; j < 8; j++)
        {
            block[j] ^= in[i + j];
        }
        magma_encrypt(block, block, &magma->iter_keys);
        bytes_encrypted += 8;
    }
    // Шифруем последний блок
    if (in_len - bytes_encrypted == MAGMA_BLOCK_SIZE) // Используем K1
    {
        for (size_t i = 0; i < 8; i++)
        {
            block[i] = in[in_len - MAGMA_BLOCK_SIZE + i] ^ block[i] ^ K1[i];
        }
        magma_encrypt(block, block, &magma->iter_keys);
    }
    else if (in_len - bytes_encrypted > MAGMA_BLOCK_SIZE) // Используем K2
    {
        for (size_t i = 0; i < 8; i++)
        {
            block[i] = in[bytes_encrypted + i] ^ block[i] ^ K1[i];
        }
        bytes_encrypted += 8;
        magma_encrypt(block, block, &magma->iter_keys);

        uint8_t tmp[8] = {0};
        memcpy(tmp, in + bytes_encrypted, in_len - bytes_encrypted);
        tmp[in_len - bytes_encrypted] = 0x80;
        for (size_t i = 0; i < 8; i++)
        {
            block[i] = tmp[i] ^ block[i] ^ K2[i];
        }
        magma_encrypt(block, block, &magma->iter_keys);
        magma_clear_buf(tmp, MAGMA_BLOCK_SIZE);
    }
    else
    {
        uint8_t tmp[8] = {0};
        memcpy(tmp, in + bytes_encrypted, in_len - bytes_encrypted);
        tmp[in_len - bytes_encrypted] = 0x80;
        for (size_t i = 0; i < 8; i++)
        {
            block[i] = tmp[i] ^ block[i] ^ K2[i];
        }
        magma_encrypt(block, block, &magma->iter_keys);
        magma_clear_buf(tmp, MAGMA_BLOCK_SIZE);
    }
    memcpy(out, block, (int)out_len / 8);

    magma_clear_buf(block, MAGMA_BLOCK_SIZE);
    magma_clear_buf(K2, MAGMA_BLOCK_SIZE);
    magma_clear_buf((uint8_t *)&K1_value, MAGMA_BLOCK_SIZE);
    magma_clear_buf(K1, MAGMA_BLOCK_SIZE);
    magma_clear_buf((uint8_t *)&R_value, MAGMA_BLOCK_SIZE);
    magma_clear_buf(R, MAGMA_BLOCK_SIZE);
}