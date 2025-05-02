extern "C" {
#include "kuznyechik.h"
}

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstdint>

// Utility function to convert hex string to byte array
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// А.2.1 Преобразование S
// S(ffeeddccbbaa99881122334455667700) = b66cd8887d38e8d77765aeea0c9a7efc,
// S(b66cd8887d38e8d77765aeea0c9a7efc) = 559d8dd7bd06cbfe7e7b262523280d39,
// S(559d8dd7bd06cbfe7e7b262523280d39) = 0c3322fed531e4630d80ef5c5a81c50b,
// S(0c3322fed531e4630d80ef5c5a81c50b) = 23ae65633f842d29c5df529c13f5acda.
TEST(KuznyechikTest, Sbox) {
    std::vector<std::vector<uint8_t>> blocks_in = {
        hex_to_bytes("ffeeddccbbaa99881122334455667700"), 
        hex_to_bytes("b66cd8887d38e8d77765aeea0c9a7efc"), 
        hex_to_bytes("559d8dd7bd06cbfe7e7b262523280d39"), 
        hex_to_bytes("0c3322fed531e4630d80ef5c5a81c50b")
    };
    std::vector<std::vector<uint8_t>> blocks_out = {
        hex_to_bytes("b66cd8887d38e8d77765aeea0c9a7efc"), 
        hex_to_bytes("559d8dd7bd06cbfe7e7b262523280d39"), 
        hex_to_bytes("0c3322fed531e4630d80ef5c5a81c50b"), 
        hex_to_bytes("23ae65633f842d29c5df529c13f5acda")
    };

    for (int i = 0; i < 4; i++) {
        kuz_block_t block_in = {0};
        kuz_block_t block_out = {0};
        std::copy(blocks_in[i].begin(), blocks_in[i].end(), block_in);
        std::copy(blocks_out[i].begin(), blocks_out[i].end(), block_out);

        kuz_S(block_in);
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(block_in[j], block_out[j]);
        }
    }
}

TEST(KuznyechikTest, SboxInverse) {
    std::vector<std::vector<uint8_t>> blocks_in = {
        hex_to_bytes("b66cd8887d38e8d77765aeea0c9a7efc"),
        hex_to_bytes("559d8dd7bd06cbfe7e7b262523280d39"),
        hex_to_bytes("0c3322fed531e4630d80ef5c5a81c50b"),
        hex_to_bytes("23ae65633f842d29c5df529c13f5acda")
    };
    std::vector<std::vector<uint8_t>> blocks_out = {
        hex_to_bytes("ffeeddccbbaa99881122334455667700"),
        hex_to_bytes("b66cd8887d38e8d77765aeea0c9a7efc"),
        hex_to_bytes("559d8dd7bd06cbfe7e7b262523280d39"),
        hex_to_bytes("0c3322fed531e4630d80ef5c5a81c50b"),
    };

    for (int i = 0; i < 4; i++) {
        kuz_block_t block_in = {0};
        kuz_block_t block_out = {0};
        std::copy(blocks_in[i].begin(), blocks_in[i].end(), block_in);
        std::copy(blocks_out[i].begin(), blocks_out[i].end(), block_out);

        kuz_inv_S(block_in);
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(block_in[j], block_out[j]);
        }
    }
    
}

// A.2.2 Преобразование R
// R{00000000000000000000000000000100) = 94000000000000000000000000000001,
// R(94000000000000000000000000000001) = a5940000000000000000000000000000,
// R(05940000000000000000000000000000) = 64059400000000000000000000000000,
// R(64a59400000000000000000000000000) = 0d64a594000000000000000000000000.
TEST(KuznyechikTest, Rtransformation) {
    std::vector<std::vector<uint8_t>> blocks_in = {
        hex_to_bytes("00000000000000000000000000000100"),
        hex_to_bytes("94000000000000000000000000000001"),
        hex_to_bytes("a5940000000000000000000000000000"),
        hex_to_bytes("64a59400000000000000000000000000"),
    };
    std::vector<std::vector<uint8_t>> blocks_out = {
        hex_to_bytes("94000000000000000000000000000001"),
        hex_to_bytes("a5940000000000000000000000000000"),
        hex_to_bytes("64a59400000000000000000000000000"),
        hex_to_bytes("0d64a594000000000000000000000000"),
    };

    for (int i = 0; i < 4; i++) {
        kuz_block_t block_in = {0};
        kuz_block_t block_out = {0};
        std::copy(blocks_in[i].begin(), blocks_in[i].end(), block_in);
        std::copy(blocks_out[i].begin(), blocks_out[i].end(), block_out);

        kuz_R(block_in);
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(block_in[j], block_out[j]);
        }
    }
}

TEST(KuznyechikTest, RtransformationInverse) {
    std::vector<std::vector<uint8_t>> blocks_in = {
        hex_to_bytes("94000000000000000000000000000001"),
        hex_to_bytes("a5940000000000000000000000000000"),
        hex_to_bytes("64a59400000000000000000000000000"),
        hex_to_bytes("0d64a594000000000000000000000000"),
    };
    std::vector<std::vector<uint8_t>> blocks_out = {
        hex_to_bytes("00000000000000000000000000000100"),
        hex_to_bytes("94000000000000000000000000000001"),
        hex_to_bytes("a5940000000000000000000000000000"),
        hex_to_bytes("64a59400000000000000000000000000"),
    };

    for (int i = 0; i < 4; i++) {
        kuz_block_t block_in = {0};
        kuz_block_t block_out = {0};
        std::copy(blocks_in[i].begin(), blocks_in[i].end(), block_in);
        std::copy(blocks_out[i].begin(), blocks_out[i].end(), block_out);

        kuz_inv_R(block_in);
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(block_in[j], block_out[j]);
        }
    }
}

// A.2.3 Преобразование L
// L(64a59400000000000000000000000000) = d456584dd0e3e84cc3166e4b7fa2890d,
// L(d456584dd0e3e84cc3166e4b7fa2890d) = 79d26221b87b584cd42fbc4ffea5de9a,
// L(79d26221b87b584cd42fbc4ffea5de9a) = 0e93691a0cfc60408b7b68f66b513c13,
// L(0e93691a0cfc60408b7b68f66b513c13) = e6a8094fee0aa204fd97bcb0b44b8580.
TEST(KuznyechikTest, Ltransformation) {
    std::vector<std::vector<uint8_t>> blocks_in = {
        hex_to_bytes("64a59400000000000000000000000000"),
        hex_to_bytes("d456584dd0e3e84cc3166e4b7fa2890d"),
        hex_to_bytes("79d26221b87b584cd42fbc4ffea5de9a"),
        hex_to_bytes("0e93691a0cfc60408b7b68f66b513c13"),
    };
    std::vector<std::vector<uint8_t>> blocks_out = {
        hex_to_bytes("d456584dd0e3e84cc3166e4b7fa2890d"),
        hex_to_bytes("79d26221b87b584cd42fbc4ffea5de9a"),
        hex_to_bytes("0e93691a0cfc60408b7b68f66b513c13"),
        hex_to_bytes("e6a8094fee0aa204fd97bcb0b44b8580"),
    };
    for (int i = 0; i < 4; i++) {
        kuz_block_t block_in = {0};
        kuz_block_t block_out = {0};
        std::copy(blocks_in[i].begin(), blocks_in[i].end(), block_in);
        std::copy(blocks_out[i].begin(), blocks_out[i].end(), block_out);

        kuz_L(block_in);
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(block_in[j], block_out[j]);
        }
    }
}

TEST(KuznyechikTest, LtransformationInverse) {
    std::vector<std::vector<uint8_t>> blocks_in = {
        hex_to_bytes("d456584dd0e3e84cc3166e4b7fa2890d"),
        hex_to_bytes("79d26221b87b584cd42fbc4ffea5de9a"),
        hex_to_bytes("0e93691a0cfc60408b7b68f66b513c13"),
        hex_to_bytes("e6a8094fee0aa204fd97bcb0b44b8580"),
    };
    std::vector<std::vector<uint8_t>> blocks_out = {
        hex_to_bytes("64a59400000000000000000000000000"),
        hex_to_bytes("d456584dd0e3e84cc3166e4b7fa2890d"),
        hex_to_bytes("79d26221b87b584cd42fbc4ffea5de9a"),
        hex_to_bytes("0e93691a0cfc60408b7b68f66b513c13"),
    };
    for (int i = 0; i < 4; i++) {
        kuz_block_t block_in = {0};
        kuz_block_t block_out = {0};
        std::copy(blocks_in[i].begin(), blocks_in[i].end(), block_in);
        std::copy(blocks_out[i].begin(), blocks_out[i].end(), block_out);

        kuz_inv_L(block_in);
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(block_in[j], block_out[j]);
        }
    }
}

// A.2.4 Алгоритм развертывания ключа
TEST(KuznyechikTest, ExpandKey) {
    std::string key_str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    std::vector<uint8_t> key_bytes = hex_to_bytes(key_str);
    std::vector<std::vector<uint8_t>> expected_keys = {
        hex_to_bytes("8899aabbccddeeff0011223344556677"),
        hex_to_bytes("fedcba98765432100123456789abcdef"),
        hex_to_bytes("db31485315694343228d6aef8cc78c44"),
        hex_to_bytes("3d4553d8e9cfec6815ebadc40a9ffd04"),
        hex_to_bytes("57646468c44a5e28d3e59246f429f1ac"),
        hex_to_bytes("bd079435165c6432b532e82834da581b"),
        hex_to_bytes("51e640757e8745de705727265a0098b1"),
        hex_to_bytes("5a7925017b9fdd3ed72a91a22286f984"),
        hex_to_bytes("bb44e25378c73123a5f32f73cdb6e517"),
        hex_to_bytes("72e9dd7416bcf45b755dbaa88e4a4043"),
    };

    kuz_key_t key = {0};
    std::copy(key_bytes.begin(), key_bytes.end(), key);
    kuz_iter_keys iter_keys = {0};

    kuz_expand_key(&iter_keys, key);
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < KUZ_BLOCK_SIZE; j++) {
            EXPECT_EQ(iter_keys.enc_keys[i][j], expected_keys[i][j]);
        }
    }
}

// A.2.5 Алгоритм зашифрования
TEST(KuznyechikTest, Encrypt) {
    std::string key_str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    std::vector<uint8_t> key_bytes = hex_to_bytes(key_str);

    kuz_key_t key = {0};
    std::copy(key_bytes.begin(), key_bytes.end(), key);
    kuz_iter_keys iter_keys = {0};
    kuz_expand_key(&iter_keys, key);

    std::string plaintext_str = "1122334455667700ffeeddccbbaa9988";
    std::vector<uint8_t> plaintext_bytes = hex_to_bytes(plaintext_str);

    kuz_block_t plaintext = {0};
    std::copy(plaintext_bytes.begin(), plaintext_bytes.end(), plaintext);

    kuz_block_t ciphertext = {0};
    kuz_encrypt(plaintext, ciphertext, &iter_keys);

    std::string expected_ciphertext_str = "7f679d90bebc24305a468d42b9d4edcd";
    std::vector<uint8_t> expected_ciphertext_bytes = hex_to_bytes(expected_ciphertext_str);

    for (int i = 0; i < KUZ_BLOCK_SIZE; i++) {
        EXPECT_EQ(ciphertext[i], expected_ciphertext_bytes[i]);
    }
}

// A.2.6 Алгоритм расшифрования
TEST(KuznyechikTest, Decrypt) {
    std::string key_str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    std::vector<uint8_t> key_bytes = hex_to_bytes(key_str);

    kuz_key_t key = {0};
    std::copy(key_bytes.begin(), key_bytes.end(), key);
    kuz_iter_keys iter_keys = {0};
    kuz_expand_key(&iter_keys, key);

    std::string ciphertext_str = "7f679d90bebc24305a468d42b9d4edcd";
    std::vector<uint8_t> ciphertext_bytes = hex_to_bytes(ciphertext_str);

    kuz_block_t ciphertext = {0};
    std::copy(ciphertext_bytes.begin(), ciphertext_bytes.end(), ciphertext);

    kuz_block_t plaintext = {0};
    kuz_decrypt(ciphertext, plaintext, &iter_keys);

    std::string expected_plaintext_str = "1122334455667700ffeeddccbbaa9988";
    std::vector<uint8_t> expected_plaintext_bytes = hex_to_bytes(expected_plaintext_str);

    for (int i = 0; i < KUZ_BLOCK_SIZE; i++) {
        EXPECT_EQ(plaintext[i], expected_plaintext_bytes[i]);
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}