#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

SCENARIO("Util helper functions are useful") {
    GIVEN("Any message string") {
        string msg = "Hello World!";

        WHEN("converted into Bytes array") {
            Bytes msgBytes = Utils::StringToBytes(msg);
            REQUIRE(msgBytes.size() == msg.size());

            THEN("converting back to string should give the original message") {
                string msgString = Utils::BytesToString(msgBytes);
                REQUIRE(msg == msgString);
            }
        }

        WHEN("encoded to base64") {
            Bytes mbytes = Utils::StringToBytes(msg);
            string b64e = Utils::EncodeBase64(mbytes);

            THEN("decoding should give the same value") {
                Bytes b64d = Utils::DecodeBase64(b64e);
                
                REQUIRE(mbytes == b64d);
                REQUIRE(msg == Utils::BytesToString(b64d));
            }
        }
    }
}