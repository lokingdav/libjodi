#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

SCENARIO("Encryption scheme allows one to encrypt and/or decrypt", "[encryption]") {
    GIVEN("Any secret key and plaintext information") {
        Bytes key = Encryption::Keygen();
        Bytes plaintext = Utils::StringToBytes("David L. Adei");

        WHEN("plaintext is encrypted into ctx") {
            Bytes ctx = Encryption::Encrypt(key, plaintext);

            REQUIRE(ctx != plaintext);

            THEN("it can be decrypted back into the original plaintext") {
                Bytes msg = Encryption::Decrypt(key, ctx);
                REQUIRE(plaintext == msg);
            }
        }
    }
}