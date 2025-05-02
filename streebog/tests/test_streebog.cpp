extern "C" {
#include "streebog.h"
}

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

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

TEST(StreebogTest, Test1) {
    std::string input = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
    std::vector<uint8_t> input_bytes = hex_to_bytes(input);
    std::reverse(input_bytes.begin(), input_bytes.end());

    std::string expected_output = "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b";
    std::vector<uint8_t> expected_output_bytes = hex_to_bytes(expected_output);
    std::reverse(expected_output_bytes.begin(), expected_output_bytes.end());

    Streebog sb;
    streebog_new(&sb);
    streebog_stage3(&sb, input_bytes.data(), input_bytes.size());
    for (size_t i = 0; i < STREEBOG_BLOCK_SIZE; i++) {
        EXPECT_EQ(sb.h[i], expected_output_bytes[i]) << "at index " << i;
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}