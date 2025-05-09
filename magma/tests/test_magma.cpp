extern "C"
{
#include "magma.h"
}

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstdint>

// Utility function to convert hex string to byte array
std::vector<uint8_t> hex_to_bytes(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// t(fdb97531) = 2a196f34,
// t(2a196f34) = ebd9f03a,
// t(ebd9f03a) = b039bb3d,
// t(b039bb3d) = 68695433
TEST(MagmaTest, t_transform)
{
    std::vector<uint32_t> in = {0xfdb97531, 0x2a196f34, 0xebd9f03a, 0xb039bb3d};
    std::vector<uint32_t> out = {0x2a196f34, 0xebd9f03a, 0xb039bb3d, 0x68695433};
    for (size_t i = 0; i < 4; i++)
    {
        uint32_t tmp_out = 0;
        magma_t(&in[i], &tmp_out);
        EXPECT_EQ(tmp_out, out[i]) << "Got:      0x" << std::hex << tmp_out << std::endl
                                   << "Expected: 0x" << std::hex << out[i];
    }
}

TEST(MagmaTest, add_mod_32)
{
    std::vector<uint32_t> in = {0x1};
    std::vector<uint32_t> out = {0x3};
    for (size_t i = 0; i < in.capacity(); i++)
    {
        uint32_t tmp_out = 0;
        uint32_t b = 0x2;
        magma_add_mod32(&in[i], &b, &tmp_out);
        EXPECT_EQ(tmp_out, out[i]) << "Got:      0x" << std::hex << tmp_out << std::endl
                                   << "Expected: 0x" << std::hex << out[i];
    }
}

// g[87654321](fedcba98) = fdcbc20c,
// g[fdcbc20c](87654321) = 7e791a4b,
// g[7e791a4b](fdcbc20c) = c76549ec,
// g[c76549ec](7e791a4b) = 9791c849.
TEST(MagmaTest, g_transform)
{
    std::vector<uint32_t> in = {0xfedcba98, 0x87654321, 0xfdcbc20c, 0x7e791a4b};
    std::vector<uint32_t> out = {0xfdcbc20c, 0x7e791a4b, 0xc76549ec, 0x9791c849};
    std::vector<uint32_t> k = {0x87654321, 0xfdcbc20c, 0x7e791a4b, 0xc76549ec};
    for (size_t i = 0; i < 4; i++)
    {
        uint32_t tmp_out = 0;
        magma_g(&in[i], &k[i], &tmp_out);
        EXPECT_EQ(tmp_out, out[i]) << "Got:      0x" << std::hex << tmp_out << std::endl
                                   << "Expected: 0x" << std::hex << out[i];
    }
}

TEST(MagmaTest, key_expansion)
{
    std::vector<uint32_t> in = {0xfedcba98, 0x87654321, 0xfdcbc20c, 0x7e791a4b};
    std::vector<uint32_t> out = {0xfdcbc20c, 0x7e791a4b, 0xc76549ec, 0x9791c849};
    std::vector<uint8_t> k_bytes = hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const uint32_t expected_keys[32] = {
        0xffeeddcc, // K_1
        0xbbaa9988, // K_2
        0x77665544, // K_3
        0x33221100, // K_4
        0xf0f1f2f3, // K_5
        0xf4f5f6f7, // K_6
        0xf8f9fafb, // K_7
        0xfcfdfeff, // K_8
        0xffeeddcc, // K_9
        0xbbaa9988, // K_10
        0x77665544, // K_11
        0x33221100, // K_12
        0xf0f1f2f3, // K_13
        0xf4f5f6f7, // K_14
        0xf8f9fafb, // K_15
        0xfcfdfeff, // K_16
        0xffeeddcc, // K_17
        0xbbaa9988, // K_18
        0x77665544, // K_19
        0x33221100, // K_20
        0xf0f1f2f3, // K_21
        0xf4f5f6f7, // K_22
        0xf8f9fafb, // K_23
        0xfcfdfeff, // K_24
        0xfcfdfeff, // K_25
        0xf8f9fafb, // K_26
        0xf4f5f6f7, // K_27
        0xf0f1f2f3, // K_28
        0x33221100, // K_29
        0x77665544, // K_30
        0xbbaa9988, // K_31
        0xffeeddcc  // K_32
    };
    magma_iter_keys iter_keys = {0};
    magma_expand_key(&iter_keys, k_bytes.data());
    for (size_t i = 0; i < 32; i++)
    {
        EXPECT_EQ(iter_keys.enc_keys[i], expected_keys[i]) << "i = " << i << std::endl
                                                           << "Got:      0x" << std::hex << iter_keys.enc_keys[i] << std::endl
                                                           << "Expected: 0x" << std::hex << expected_keys[i];
    }
}

TEST(MagmaTest, cipher)
{
    std::vector<uint8_t> in = hex_to_bytes("fedcba9876543210");
    std::vector<uint8_t> expected_out = hex_to_bytes("4ee901e5c2d8ca3d");
    std::vector<uint8_t> k_bytes = hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    magma_iter_keys iter_keys = {0};
    magma_expand_key(&iter_keys, k_bytes.data());
    uint8_t out[8] = {0};
    magma_encrypt(in.data(), out, &iter_keys);
    for (size_t i = 0; i < in.capacity(); i++)
    {
        EXPECT_EQ(out[i], expected_out[i]) << "Got:      0x" << std::hex << int(out[i]) << std::endl
                                           << "Expected: 0x" << std::hex << int(expected_out[i]);
    }
}

// P1 = 92def06b3c130a59,
// P2 = db54c704f8189d20,
// P3 = 4a98fb2e67a8024c,
// P4 = 8912409b17b57e41
TEST(MagmaTest, cipher_ctr)
{
    std::vector<uint8_t> in = hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
    std::vector<uint8_t> iv = hex_to_bytes("12345678");
    std::vector<uint8_t> k_bytes = hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    std::vector<uint8_t> expected_out = hex_to_bytes("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d");
    uint8_t out[32] = {0};
    Magma magma = {0};
    magma_new(&magma, k_bytes.data());
    memcpy(magma.iv, iv.data(), 4);

    magma_ctr_encrypt(&magma, in.data(), out, in.size());
    for (size_t i = 0; i < expected_out.capacity(); i++)
    {
        EXPECT_EQ(out[i], expected_out[i]) << "Got:      0x" << std::hex << int(out[i]) << std::endl
                                           << "Expected: 0x" << std::hex << int(expected_out[i]);
    }
}

TEST(MagmaTest, cipher_cmac)
{
    std::vector<uint8_t> in = hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
    std::vector<uint8_t> iv = hex_to_bytes("12345678");
    std::vector<uint8_t> k_bytes = hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    uint8_t expected_out[4] = {0x15, 0x4e, 0x72, 0x10};
    uint8_t out[4] = {0};
    Magma magma = {0};
    magma_new(&magma, k_bytes.data());
    memcpy(magma.iv, iv.data(), 4);

    magma_cmac(&magma, in.data(), in.size(), out, 32);
    for (size_t i = 0; i < 4; i++)
    {
        EXPECT_EQ(out[i], expected_out[i]) << "Got:      0x" << std::hex << int(out[i]) << std::endl
                                           << "Expected: 0x" << std::hex << int(expected_out[i]);
    }
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}