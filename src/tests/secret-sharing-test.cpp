#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

SCENARIO("Shamire's secret sharing scheme", "[sss]") {
    GIVEN("Any secret information") {
        string secret = "David L. Adei";

        WHEN("splited into shares 2-of-3") {
            Bytes sb = Utils::StringToBytes(secret);
            vector<Bytes> shares = SecretSharing::Split(sb);
            REQUIRE(shares.size() == 5);

            THEN("it can be combined to reconstruct the secret") {
                Bytes reconsecret = SecretSharing::Combine(shares);
                REQUIRE(sb == reconsecret);
            }
        }
    }
}