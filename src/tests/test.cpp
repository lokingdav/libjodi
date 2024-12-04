#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex.hpp"

using namespace libcpex;

SCENARIO("Scalars are big integers", "[Scalars]") {
    GIVEN("Any valid Scalar object") {
        Scalar scalar = Scalar::Random();
        REQUIRE_NOTHROW(scalar.CheckKeyData());

        WHEN("it's serialized to bytes") {
            libcpex::Bytes data = scalar.Serialize();
            REQUIRE(data.size() == Scalar::SIZE);

            THEN("it should be possible to deserialize back to Scalar instance") {
                REQUIRE(scalar == Scalar::Deserialize(data));
            }
        }

        WHEN("it's inversed, it should be reversible") {
            REQUIRE(scalar == scalar.Inverse().Inverse());
        }
    };
};

SCENARIO("Points are on an elliptic curve") {
    GIVEN("Any message") {
        string msg = "hello World!";

        WHEN("it's hashed to a point on the curve") {
            Point p1 = Point::HashToPoint(msg);
            REQUIRE_NOTHROW(p1.CheckValid());

            THEN("hashing should be deterministic") {
                Point p2 = Point::HashToPoint(msg);
                REQUIRE(p1 == p2);
            }

            THEN("it should be multiplied by a scalar or inverse scalar") {
                Scalar s = Scalar::Random();
                REQUIRE(p1 == s.Inverse() * (s * p1));
            }
        }
    }
};