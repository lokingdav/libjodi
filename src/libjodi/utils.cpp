#include <sodium.h>
#include "libjodi.hpp"

namespace libjodi {
    string Utils::BytesToString(Bytes const &data) {
        return string(data.begin(), data.end());
    }

    Bytes Utils::StringToBytes(string const &data) {
        return Bytes(data.begin(), data.end());
    }

    Bytes Utils::Sha160(Bytes const &preimage) {
        Bytes hash(20);

        if (crypto_generichash(hash.data(), hash.size(), preimage.data(), preimage.size(), nullptr, 0) != 0) {
            panic("Failed to compute SHA-1 hash");
        }

        return hash;
    }

    Bytes Utils::Sha256(Bytes const &preimage) {
        Bytes hash(crypto_hash_sha256_BYTES);

        if (crypto_hash_sha256(hash.data(), preimage.data(), preimage.size()) != 0) {
            panic("Failed to compute SHA-256 hash");
        }

        return hash;
    }

    Bytes Utils::Xor(Bytes const & x, Bytes const & y) {
        size_t maxLength = std::max(x.size(), y.size());
        Bytes result(maxLength, 0);

        for (size_t i = 0; i < maxLength; ++i) {
            unsigned char byte1 = (i < x.size()) ? x[i] : 0; 
            unsigned char byte2 = (i < y.size()) ? y[i] : 0;
            result[i] = byte1 ^ byte2;
        }

        return result;
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

    Bytes Utils::RemoveTrailingZeroes(Bytes &data) {
        while (!data.empty() && data.back() == 0) {
            data.pop_back();
        }
        return data;
    }

    Bytes Utils::RandomBytes(size_t size)
    {
        unsigned char buff[size];
        randombytes_buf(buff, sizeof buff);
        return Bytes(buff, buff + sizeof buff);
    }
}