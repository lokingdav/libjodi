#include <sodium.h>
#include "libcpex.hpp"

namespace libcpex {
    string Utils::BytesToString(Bytes const &data) {
        return string(data.begin(), data.end());
    }

    Bytes Utils::StringToBytes(string const &data) {
        return Bytes(data.begin(), data.end());
    }

    string Utils::EncodeBase64(Bytes const & data) {
        size_t encodedLength = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
        char *encoded = new char[encodedLength];
        sodium_bin2base64(encoded, encodedLength, data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL);
        string result(encoded);
        delete[] encoded;
        return result;
    }

    Bytes Utils::DecodeBase64(string const & data) {
        size_t decodedLength = data.size();
        Bytes decoded(decodedLength);

        size_t actualDecodedLength;
        if (sodium_base642bin(decoded.data(), decoded.size(),
                              data.c_str(), data.size(),
                              nullptr, 
                              &actualDecodedLength,
                              nullptr,
                              sodium_base64_VARIANT_ORIGINAL) != 0) {
            panic("Invalid Base64 input");
        }

        decoded.resize(actualDecodedLength);

        return decoded;
    }
}