#include "chacha20.h"

// ChaCha20 constants (hex of "expand 32-byte k")
static const uint32_t chacha_constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

/**
 * @brief Очищает буфер `buf` размером `size` данными из /dev/urandom.
 */
__attribute__((optimize(0))) void chacha_clear_buf(uint8_t *buf, ssize_t size)
{
    if (getrandom(buf, size, 0) != size)
    {
        perror("getrandom");
        exit(1);
    }
}

/**
 * @brief Инициализирует структуру `ChaCha20` с заданным ключом, nonce и счетчиком.
 *
 * @param chacha Указатель на структуру `ChaCha20`.
 * @param key Указатель на 256-битный ключ.
 * @param nonce Указатель на 96-битный nonce.
 * @param counter Значение счетчика.
 */
void chacha_new(ChaCha20 *chacha, const uint8_t *key, const uint32_t *nonce, uint32_t counter)
{
    // Initialize the ChaCha20 state
    memcpy(chacha->key, key, 32 * sizeof(uint8_t));
    memcpy(chacha->nonce, nonce, 3 * sizeof(uint32_t));
    chacha->counter = counter;
}

/**
 * @brief Очистка экземпляра структуры `ChaCha20`.
 *
 * @param chacha Указатель на структуру `ChaCha20`.
 */
void chacha_clear(ChaCha20 *chacha)
{
    chacha_clear_buf(chacha->key, 32 * sizeof(uint8_t));
    chacha_clear_buf((uint8_t *)chacha->nonce, 3 * sizeof(uint32_t));
    chacha->counter = 0;
}

/**
 * @brief Выполняет один раунд ChaCha20 --- QUARTERROUND(a, b, c, d).
 */
static inline void chacha_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b;
    *d ^= *a;
    *d = (*d << 16) | (*d >> 16);
    *c += *d;
    *b ^= *c;
    *b = (*b << 12) | (*b >> 20);
    *a += *b;
    *d ^= *a;
    *d = (*d << 8) | (*d >> 24);
    *c += *d;
    *b ^= *c;
    *b = (*b << 7) | (*b >> 25);
}

/**
 * @brief Генерирует следующий блок ChaCha20.
 *
 * @param input Входной массив состояния.
 * @param output Выходной массив ключевого потока (keystream).
 */
static void chacha_next_block(const uint32_t input[16], uint32_t output[16])
{
    memcpy(output, input, 16 * sizeof(uint32_t));

    for (int i = 0; i < 10; ++i)
    {
        // Column rounds
        chacha_quarter_round(output + 0, output + 4, output + 8, output + 12);
        chacha_quarter_round(output + 1, output + 5, output + 9, output + 13);
        chacha_quarter_round(output + 2, output + 6, output + 10, output + 14);
        chacha_quarter_round(output + 3, output + 7, output + 11, output + 15);

        // Diagonal rounds
        chacha_quarter_round(output + 0, output + 5, output + 10, output + 15);
        chacha_quarter_round(output + 1, output + 6, output + 11, output + 12);
        chacha_quarter_round(output + 2, output + 7, output + 8, output + 13);
        chacha_quarter_round(output + 3, output + 4, output + 9, output + 14);
    }

    for (int i = 0; i < 16; ++i)
    {
        output[i] += input[i];
    }
}

/**
 * @brief Устанавливает начальное состояние ChaCha20.
 *
 * @param chacha Указатель на структуру `ChaCha20`.
 * @param state Массив начального состояния.
 */
static void chacha_set_initial_state(ChaCha20 *chacha, uint32_t state[16])
{
    // Set the initial state
    state[0] = chacha_constants[0];
    state[1] = chacha_constants[1];
    state[2] = chacha_constants[2];
    state[3] = chacha_constants[3];

    // Set the key
    memcpy(state + 4, chacha->key, sizeof(uint8_t) * 32);

    // Set the counter
    state[12] = chacha->counter;

    // Set the nonce
    memcpy(state + 13, chacha->nonce, 3 * sizeof(uint32_t));
}

/**
 * @brief Шифрует данные с помощью ChaCha20.
 *
 * @param chacha Указатель на структуру `ChaCha20`.
 * @param plain_text Указатель на открытый текст.
 * @param cipher_text Указатель на шифрованный текст.
 * @param len Длина данных (`len(plain_text) = len(cipher_text)`).
 */
void chacha_encrypt(ChaCha20 *chacha, const uint8_t *plain_text, uint8_t *cipher_text, size_t len)
{
    uint32_t state[16] = {0};
    chacha_set_initial_state(chacha, state);
    uint32_t keystream[16] = {0};

    for (size_t i = 0; i < len; i += 64)
    {
        chacha_next_block(state, keystream);
        state[12] = ++chacha->counter;
        // handle overflow
        if (state[12] == 0)
        {
            state[13]++;
        }

        size_t block_size = (len - i < 64) ? len - i : 64;
        for (size_t j = 0; j < block_size; j++)
        {
            cipher_text[i + j] = plain_text[i + j] ^ *((uint8_t *)keystream + j);
        }
    }

    chacha_clear_buf((uint8_t *)keystream, 16 * sizeof(uint32_t));
    chacha_clear_buf((uint8_t *)state, 16 * sizeof(uint32_t));
}

/**
 * @brief Генерирует случайные байты с помощью ChaCha20
 *
 * @param chacha Указатель на структуру `ChaCha20`
 * @param fp Файловый указатель на массив для хранения случайных байтов
 * @param len Длина генерируемой последовательности байт
 */
void chacha_prng(ChaCha20 *chacha, FILE *fp, size_t len)
{
    uint32_t state[16] = {0};
    chacha_set_initial_state(chacha, state);
    uint32_t keystream[16] = {0};

    for (size_t i = 0; i < len; i += 64)
    {
        chacha_next_block(state, keystream);
        state[12] = ++chacha->counter;
        // handle overflow
        if (state[12] == 0)
        {
            state[13]++;
        }

        size_t block_size = (len - i < 64) ? len - i : 64;
        fwrite(keystream, sizeof(uint8_t), block_size, fp);
    }

    chacha_clear_buf((uint8_t *)keystream, 16 * sizeof(uint32_t));
    chacha_clear_buf((uint8_t *)state, 16 * sizeof(uint32_t));
}