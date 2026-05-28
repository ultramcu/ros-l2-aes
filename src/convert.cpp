
#include "../include/convert.h"


std::vector<unsigned char> hexStringToVector(const std::string& hexString) {
    std::vector<unsigned char> result;

    // Iterate over the hex string in pairs
    for (size_t i = 0; i < hexString.length(); i += 2) {
        // Extract two characters and convert them to a byte value
        std::string byteString = hexString.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));

        // Add the byte value to the result vector
        result.push_back(byte);
    }

    return result;
}