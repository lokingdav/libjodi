#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

SCENARIO("Shamire's secret sharing scheme", "[sss]") {
    GIVEN("Any secret information") {
        string secret = "David L. Adei";
        auto n = 3, t = 2;

        WHEN("splited into shares 2-of-3") {
            Bytes sb = Utils::StringToBytes(secret);
            vector<Bytes> shares = SecretSharing::Split(sb, n, t);
            REQUIRE(shares.size() == n);

            THEN("it can be combined to reconstruct the secret") {
                Bytes reconsecret = SecretSharing::Combine(shares, t);
                REQUIRE(sb == reconsecret);
            }
        }
    }
}