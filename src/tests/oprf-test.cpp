#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

SCENARIO("OPRF protocol label generation", "[oprf]") {
    auto keypair = libcpex::OPRF::Keygen();

    GIVEN("Any message") {
        string msg = "Hello World!";

        WHEN("blinded to a point on the EC curve by a Party A") {
            auto b1 = libcpex::OPRF::Blind(&msg);
            REQUIRE(b1.mask.size() == 32);
            REQUIRE(b1.sk.size() == 32);

            Bytes label;

            THEN("it should be evaluatable") {
                auto eval = libcpex::OPRF::Evaluate(keypair, b1.mask);
                REQUIRE(eval.fx.size() == 32);
                REQUIRE(eval.pk.size() == 32);

                THEN("it should be unblindable") {
                    label = libcpex::OPRF::Unblind(eval, b1.sk);
                }
            }

            WHEN("blinding is done by another Party B") {
                THEN("blinding should not be deterministic") {
                    auto b2 = libcpex::OPRF::Blind(&msg);
                    REQUIRE(b2.mask.size() == 32);
                    REQUIRE(b2.sk.size() == 32);
                    REQUIRE(b1.mask != b2.mask);
                    REQUIRE(b1.sk != b2.sk);
                }
            }
        }
    }
}