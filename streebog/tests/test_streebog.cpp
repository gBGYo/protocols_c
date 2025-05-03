extern "C"
{
#include "streebog.h"
}

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include <iomanip>

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

TEST(StreebogTest, Test1)
{
    std::string input = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
    std::vector<uint8_t> input_bytes = hex_to_bytes(input);
    std::reverse(input_bytes.begin(), input_bytes.end());

    std::string expected_output = "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d";
    std::vector<uint8_t> expected_output_bytes = hex_to_bytes(expected_output);
    std::reverse(expected_output_bytes.begin(), expected_output_bytes.end());

    Streebog sb;
    streebog_new(&sb);
    streebog_stage3(&sb, input_bytes.data(), input_bytes.size());
    for (size_t i = 0; i < 32; i++)
    {
        EXPECT_EQ(sb.h[32 + i], expected_output_bytes[i]) << "at index " << i;
    }
}

TEST(StreebogTest, HMAC)
{
    std::string key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::vector<uint8_t> key_bytes = hex_to_bytes(key);

    std::string T = "0126bdb87800af214341456563780100";
    std::vector<uint8_t> T_bytes = hex_to_bytes(T);

    std::string expected_hmac = "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9";
    std::vector<uint8_t> expected_hmac_bytes = hex_to_bytes(expected_hmac);

    hmac_block_t hmac;
    streebog_hmac_256(key_bytes.data(), key_bytes.size() * 8, T_bytes.data(), T_bytes.size(), hmac);
    for (size_t i = 0; i < 32; i++)
    {
        EXPECT_EQ(hmac[i], expected_hmac_bytes[i]) << "at i = " << i;
    }
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}