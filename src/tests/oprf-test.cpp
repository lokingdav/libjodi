#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

SCENARIO("OPRF protocol label generation", "[oprf]") {
    GlobalInitSodium();
    
    auto keypair = libcpex::OPRF::Keygen();

    GIVEN("Any message") {
        string msg = "Hello World!";

        WHEN("blinded to a point on the EC curve by a Party A") {
            auto b1 = libcpex::OPRF::Blind(msg);
            REQUIRE(b1.x.size() == 32);
            REQUIRE(b1.r.size() == 32);

            Bytes label;

            THEN("it should be evaluatable") {
                auto eval = libcpex::OPRF::Evaluate(keypair, b1.x);
                REQUIRE(eval.fx.size() == 32);
                REQUIRE(eval.vk.size() == 32);

                THEN("it should be unblindable") {
                    label = libcpex::OPRF::Unblind(eval, b1.r);
                }
            }

            WHEN("blinding is done by another Party B") {
                THEN("blinding should not be deterministic") {
                    auto b2 = libcpex::OPRF::Blind(msg);
                    REQUIRE(b2.x.size() == 32);
                    REQUIRE(b2.r.size() == 32);
                    REQUIRE(b1.x != b2.x);
                    REQUIRE(b1.r != b2.r);
                }
            }
        }
    }

    GIVEN("A KeyRotation instance, tmax in seconds, an interval in seconds, and a key set size") {
        auto tmax = 1; //seconds
        auto size = 10;
        auto interval = tmax * 2; //seconds
        auto instance = KeyRotation::GetInstance();
        
        WHEN("a new instance is created") {
            THEN("it should be a singleton") {
                auto instance2 = KeyRotation::GetInstance();
                REQUIRE(instance == instance2);
            }
        }

        WHEN("rotation is started") {
            instance->StartRotation(size, interval);

            THEN("it should have been initialized") {
                REQUIRE(instance->GetListSize() == size);
                REQUIRE(instance->GetExpiryIndex() == -1);
                // make sure key index 0 is not expired
                REQUIRE(instance->IsExpiredWithin(0, tmax) == false);
            }
        }

        WHEN("rotation is running") {
            THEN("it should stop when requested") {
                instance->StopRotation();
                REQUIRE(instance->GetListSize() == 0);
                REQUIRE(instance->GetExpiryIndex() == -1);
            }
        }
    }
}