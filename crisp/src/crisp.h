#ifndef CRISP_H
#define CRISP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include <assert.h>

    typedef struct CrispMessage
    {
        uint8_t externalKeyIdFlag;
        uint16_t version;
        uint8_t cs;

        uint16_t keyIdLen; // длина поля KeyId
        uint8_t keyId[128];

        uint64_t seqNum;

        uint16_t payloadDataLen; // длина поля PayloadData
        uint8_t payloadData[2048];

        uint8_t icvLen; // длина поля ICV
        uint8_t icv[32];
    } CrispMessage;

    typedef struct Crisp
    {
        uint8_t externalKeyIdFlag;
        uint8_t cs;
        uint16_t version;
        uint64_t seqNum;
        uint64_t min_seqNum;
        uint64_t seqNum_bitmask;
        uint8_t key[32];
        uint8_t seed[8];
    } Crisp;

    /**
     * @brief Отображение значений поля CS на размеры имитовставок (в батайх).
     */
    static const uint8_t cs_to_icv_map[6] = {
        0x0,  // Игонорируем
        0x4,  // Секция 8.1.3.               CS = 1: s = 32
        0x4,  // Секция 8.2.2.               CS = 2: s = 32
        0x8,  // Секция 8.3.3.               CS = 3: s = 64
        0x8,  // Секция 8.4.2.               CS = 4: s = 64
        0x20, // Мой кастомный крипто набор. CS = 5: s = 256
        //      1. EncryptionAlg: Магма CTR
        //      2. MACAlg:        HMAC_GOSTR3411_2012_256
        //      3. MACLength:     256 бит
        //      4. DeriveIV:      IV = LSB_{32}(byte(SeqNum, 6))
        //      5. DeriveKey:     K_enc = K1 || K2 || K3 || K4
        //                        K_mac = K5 || K6 || K7 || K8
        //                        K1 || ... || K8 = KDF_TREE_GOSTR3411_2012_256(
        //                                            key,
        //                                            Label,
        //                                            seed,
        //                                            1,
        //                                            byte_count), где
        //                        Label = binary(`macenc`, 6)
        //                        seed = выбирается за рамками протокола
        //                        byte_count = 64 байта
    };

    void crisp_new(Crisp *crisp, uint8_t key[32], uint8_t seed[8]);
    void crisp_clear(Crisp *crisp);

    uint8_t crisp_is_seqnum_valid(Crisp *crisp, uint64_t seqNum);
    void crisp_update_seqnum(Crisp *crisp, uint64_t seqNum);

    void crisp_encode(Crisp *crisp, const uint8_t *data, size_t data_size, uint8_t *raw_crisp_message, uint16_t *raw_crisp_message_len);
    void crisp_decode(Crisp *crisp, const uint8_t *raw_crisp_message, uint16_t raw_crisp_message_len, CrispMessage *crisp_message);

#ifdef __cplusplus
}
#endif

#endif // CRISP_H
