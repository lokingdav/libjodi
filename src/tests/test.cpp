#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libcpex/libcpex.hpp"

using namespace libcpex;

// SCENARIO("Scalars are big integers", "[Scalars]") {
//     GIVEN("Any valid Scalar object") {
//         Scalar scalar = Scalar::Random();

//         WHEN("it's serialized to bytes") {
//             vector<uint8_t>data = scalar.Serialize();
//             REQUIRE(data.size() == Scalar::SIZE);

//             THEN("it should be possible to deserialize back to Scalar instance") {
//                 REQUIRE(scalar == Scalar::Deserialize(data));
//             }
//         }

//         WHEN("it's inversed, it should be reversible") {
//             REQUIRE(scalar == scalar.Inverse().Inverse());
//         }
//     };
// };

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

            THEN("it should be multiplyable by a scalar") {
                Scalar s = Scalar::Random();
                Point p2 = s * p1;
                REQUIRE_NOTHROW(p2.CheckValid());

                THEN("it should be reverted back by multiplying inverse of scalar") {
                    Point p3 = s.Inverse() * p2;
                    REQUIRE_NOTHROW(p3.CheckValid());
                    print("\nP1 ======");
                    printlist(p1.Serialize());
                    print("\n\nP3 ======");
                    printlist(p3.Serialize());
                    REQUIRE(p1 == p3);
                }
            }
        }
    }
};