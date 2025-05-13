#include "crisp.h"
#include "magma.h"
#include "streebog.h"
#include "kdf_tree_gostr3411_2012_256.h"

static const uint8_t label[6] = {0x6d, 0x61, 0x63, 0x65, 0x6e, 0x63}; // `macenc`

/**
 * @brief Проверка корректности номера сообщения `seqNum`
 *
 * @param crisp Структура протокола CRISP
 * @param seqNum номер CRISP-сообщения
 */
uint8_t crisp_is_seqnum_valid(Crisp *crisp, uint64_t seqNum)
{
    if (seqNum > crisp->min_seqNum + 64)
    {
        return 1;
    }

    // Сообщение слишком старое
    if (seqNum < crisp->min_seqNum)
    {
        return 0;
    }

    // Сообщение является дубликатом
    if (((crisp->seqNum_bitmask >> (crisp->min_seqNum + 64 - seqNum)) & 1) == 1)
    {
        return 0;
    }

    return 1;
}

/**
 * @brief Обновление окна принятых сообщений
 *
 * @param crisp Структура протокола CRISP
 * @param seqNum номер CRISP-сообщения
 */
void crisp_update_seqnum(Crisp *crisp, uint64_t seqNum)
{
    if (seqNum < crisp->min_seqNum + 64)
    {
        crisp->seqNum_bitmask |= (1 << (crisp->min_seqNum + 64 - seqNum));
    }
    else
    {
        crisp->seqNum_bitmask <<= seqNum - crisp->min_seqNum + 64;
        crisp->seqNum_bitmask |= 1;
        crisp->min_seqNum = (int64_t)seqNum - 64 + 1 > 0 ? seqNum - 64 + 1 : 0;
    }
}

/**
 * @brief Инициализирует экземпляр структуры Crisp
 *
 * @param crisp Указатель на структуру Crsip
 * @param key Массив с ключевой информацией
 * @param seed Массив с дополнительной информацией
 */
void crisp_new(Crisp *crisp, uint8_t key[32], uint8_t seed[8])
{
    crisp->externalKeyIdFlag = 0;
    crisp->version = 0;
    crisp->cs = 0x5;
    crisp->seqNum = 0;
    crisp->min_seqNum = 0;
    crisp->seqNum_bitmask = 0;
    memcpy(crisp->key, key, 32);
    memcpy(crisp->seed, seed, 8);
}

void crisp_clear(Crisp *crisp)
{
    crisp->externalKeyIdFlag = 0;
    crisp->version = 0;
    crisp->cs = 0x0;
    crisp->seqNum = 0;
    crisp->min_seqNum = 0;
    crisp->seqNum_bitmask = 0;
    memset(crisp->key, 0, 32);
    memset(crisp->seed, 0, 8);
}

void crisp_encode(Crisp *crisp, const uint8_t *data, size_t data_size, uint8_t *raw_crisp_message, uint16_t *raw_crisp_message_len)
{
    uint16_t offset = 0;
    memset(raw_crisp_message, 0, 2048);
    // Кодируем ExternalKeyIdFlag и Version
    raw_crisp_message[offset++] = 0x00;
    raw_crisp_message[offset++] = 0x00;

    // Кодируем CS
    raw_crisp_message[offset++] = crisp->cs;

    // Кодируем KeyId
    raw_crisp_message[offset++] = 0x80;

    // Кодируем SeqNum
    raw_crisp_message[offset++] = (crisp->seqNum >> 40) & 0xff;
    raw_crisp_message[offset++] = (crisp->seqNum >> 32) & 0xff;
    raw_crisp_message[offset++] = (crisp->seqNum >> 24) & 0xff;
    raw_crisp_message[offset++] = (crisp->seqNum >> 16) & 0xff;
    raw_crisp_message[offset++] = (crisp->seqNum >> 8) & 0xff;
    raw_crisp_message[offset++] = (crisp->seqNum) & 0xff;

    // Вырабатываем ключи шифрования и имитозащиты
    uint8_t derived_key[64] = {0};
    kdf_tree_gostr3411_2012_256(
        crisp->key, 256,
        label, sizeof(label) / sizeof(label[0]),
        crisp->seed, sizeof(crisp->seed) / sizeof(crisp->seed[0]),
        1,
        derived_key, 512);
    uint8_t K_enc[32] = {0};
    uint8_t K_mac[32] = {0};
    memcpy(K_enc, derived_key, 32);
    memcpy(K_mac, derived_key + 32, 32);

    // Кодируем PayloadData
    uint8_t iv[4] = {
        (crisp->seqNum >> 24) & 0xff,
        (crisp->seqNum >> 16) & 0xff,
        (crisp->seqNum >> 8) & 0xff,
        (crisp->seqNum) & 0xff};
    Magma magma = {0};
    magma_new(&magma, K_enc, iv);
    uint8_t *buf_out = malloc(data_size);
    magma_ctr_encrypt(&magma, data, buf_out, data_size);
    memcpy(raw_crisp_message + offset, buf_out, data_size);
    offset += data_size;

    // Кодируем ICV
    Streebog streebog = {0};
    streebog_new(&streebog);
    uint8_t calc_mac[32] = {0};
    streebog_hmac_256(K_mac, 256, raw_crisp_message, offset, calc_mac);
    memcpy(raw_crisp_message + offset, calc_mac, 32);
    offset += 32;
    *raw_crisp_message_len = offset;

    crisp->seqNum++;

    streebog_clear_buf(buf_out, data_size);
    free(buf_out);
    magma_clear(&magma);
    streebog_clear_buf(iv, 4);
    streebog_clear_buf(calc_mac, 32);
    streebog_clear(&streebog);
    streebog_clear_buf(K_mac, 32);
    streebog_clear_buf(K_enc, 32);
    streebog_clear_buf(derived_key, 64);
}

void crisp_decode(Crisp *crisp, const uint8_t *raw_crisp_message, uint16_t raw_crisp_message_len, CrispMessage *crisp_message)
{
    uint16_t offset = 0;
    // Декодируем ExternalKeyIdFlag и Version
    crisp_message->externalKeyIdFlag = raw_crisp_message[0] & 0x80;
    crisp_message->version = 0;
    crisp_message->version |= (uint16_t)(raw_crisp_message[0] & 0x7f) << 8;
    crisp_message->version |= (uint16_t)raw_crisp_message[1];
    offset += 2;

    if (crisp->version != crisp_message->version)
    {
        fprintf(stderr, "CRISP Version mismatch: client = %d; message = %d\n", crisp->version, crisp_message->version);
        return;
    }

    // Декодируем CS
    crisp_message->cs = raw_crisp_message[2];
    offset += 1;

    if (crisp->cs != crisp_message->cs)
    {
        fprintf(stderr, "CRISP CS mismatch: client = %d; message = %d\n", crisp->cs, crisp_message->cs);
        return;
    }

    // Декодируем KeyId
    memset(crisp_message->keyId, 0, 128);
    if (raw_crisp_message[3] == 0x80) // keyId == 10000000_2
    {
        crisp_message->keyId[0] = 0x80;
        crisp_message->keyIdLen = 1;
    }
    else if ((raw_crisp_message[3] & 0x80) == 0) // keyId == 0???????_2
    {
        crisp_message->keyId[0] = raw_crisp_message[3];
        crisp_message->keyIdLen = 1;
    }
    else //          length          keyId
    {    // keyId = 1??????? ???????? ... ????????_2
        crisp_message->keyIdLen = raw_crisp_message[3] & 0x7f;
        memcpy(crisp_message->keyId, raw_crisp_message + 4, crisp_message->keyIdLen);
    }
    if (crisp_message->keyIdLen == 1)
    {
        offset += 1;
    }
    else
    {
        offset += 1 + crisp_message->keyIdLen;
    }

    // Декодируем SeqNum
    crisp_message->seqNum = (uint64_t)raw_crisp_message[offset] << 40 |
                            (uint64_t)raw_crisp_message[offset + 1] << 32 |
                            (uint64_t)raw_crisp_message[offset + 2] << 24 |
                            (uint64_t)raw_crisp_message[offset + 3] << 16 |
                            (uint64_t)raw_crisp_message[offset + 4] << 8 |
                            (uint64_t)raw_crisp_message[offset + 5];
    offset += 6;

    if (crisp_message->seqNum < crisp->seqNum)
    {
        fprintf(stderr, "Message SeqNum is incorrect: client = %016lx, message = %016lx\n", crisp->seqNum, crisp_message->seqNum);
        return;
    }

    // Декодируем PayloadData
    crisp_message->payloadDataLen = raw_crisp_message_len - offset - cs_to_icv_map[crisp_message->cs];
    // crisp_message->payloadData = malloc(sizeof(uint8_t) * crisp_message->payloadDataLen);
    memcpy(crisp_message->payloadData, raw_crisp_message + offset, crisp_message->payloadDataLen);
    offset += crisp_message->payloadDataLen;

    // Декодируем ICV
    crisp_message->icvLen = cs_to_icv_map[crisp_message->cs];
    // crisp_message->icv = malloc(sizeof(uint8_t) * crisp_message->icvLen);
    memcpy(crisp_message->icv, raw_crisp_message + offset, crisp_message->icvLen);
    offset += crisp_message->icvLen;
    assert(offset == raw_crisp_message_len);

    uint8_t derived_key[64] = {0};

    kdf_tree_gostr3411_2012_256(
        crisp->key, 256,
        label, sizeof(label) / sizeof(label[0]),
        crisp->seed, sizeof(crisp->seed) / sizeof(crisp->seed[0]),
        1,
        derived_key, 512);

    uint8_t K_enc[32] = {0};
    uint8_t K_mac[32] = {0};
    memcpy(K_enc, derived_key, 32);
    memcpy(K_mac, derived_key + 32, 32);

    // Проверяем совпадает ли ICV
    Streebog streebog = {0};
    streebog_new(&streebog);
    uint8_t calc_mac[32] = {0};
    streebog_hmac_256(K_mac, 256, raw_crisp_message, raw_crisp_message_len - crisp_message->icvLen, calc_mac);
    for (size_t i = 0; i < 32; i++)
    {
        if (calc_mac[i] != crisp_message->icv[i])
        {
            fprintf(stderr, "CRISP ICV mismatch (at index i=%ld): calculated = %02x, message = %02x\n", i, calc_mac[i], crisp_message->icv[i]);
            return;
        }
    }

    // crisp_update_seqnum(crisp, crisp_message->seqNum);
    crisp->seqNum++;

    // Расшифровываем PayloadData
    uint8_t iv[4] = {
        (crisp_message->seqNum >> 24) & 0xff,
        (crisp_message->seqNum >> 16) & 0xff,
        (crisp_message->seqNum >> 8) & 0xff,
        (crisp_message->seqNum) & 0xff};
    Magma magma = {0};
    magma_new(&magma, K_enc, iv);
    uint8_t *buf_out = malloc(crisp_message->payloadDataLen);
    magma_ctr_encrypt(&magma, crisp_message->payloadData, buf_out, crisp_message->payloadDataLen);
    memcpy(crisp_message->payloadData, buf_out, crisp_message->payloadDataLen);

    streebog_clear_buf(buf_out, crisp_message->payloadDataLen);
    free(buf_out);
    magma_clear(&magma);
    streebog_clear_buf(iv, 4);
    streebog_clear_buf(calc_mac, 32);
    streebog_clear(&streebog);
    streebog_clear_buf(K_mac, 32);
    streebog_clear_buf(K_enc, 32);
    streebog_clear_buf(derived_key, 64);
}