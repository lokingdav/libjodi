#include <chrono>

#include <catch2/catch_test_macros.hpp>
#include "../libjodi/libjodi.hpp"

using namespace libjodi;

SCENARIO("VOPRF protocol", "[VOPRF]") {
    InitMCL();

    PrivateKey sk = PrivateKey::Keygen();
    PublicKey pk = sk.GetPublicKey();

    GIVEN("A private key") {
        THEN("it should be serializable") {
            string skStr = sk.ToString();
            REQUIRE(skStr.size() > 0); // 32 bytes + 12 bytes for base64 padding
            PrivateKey sk2 = PrivateKey::FromString(skStr);
            REQUIRE(sk == sk2);
        }
    }

    GIVEN("A public key") {
        THEN("it should be serializable") {
            string pkStr = pk.ToString();
            REQUIRE(pkStr.size() > 0);
            PublicKey pk2 = PublicKey::FromString(pkStr);
            REQUIRE(pk == pk2);
        }
    }

    GIVEN("Any message, m") {
        string m = "hello world";

        THEN("it should be hashable to a point") {
            Point p = Point::HashToPoint(m);

            REQUIRE(p.ToString().size() > 0);

            THEN("the point should be serializable") {
                string pStr = p.ToString();
                REQUIRE(pStr.size() > 0);
                Point p2 = Point::FromString(pStr);
                REQUIRE(p == p2);
            }

            THEN("the point should be deterministic") {
                Point p2 = Point::HashToPoint(m);
                REQUIRE(p == p2);
            }

            THEN("the point should be unique") {
                Point p2 = Point::HashToPoint(m + "!");
                REQUIRE(p != p2);
            }

            THEN("the point should be evaluatable") {
                Point p2 = Point::Mul(p, sk);
                REQUIRE(p2.ToString().size() > 0);

                THEN("the evaluated point should be invertible") {
                    Point p3 = Point::Mul(p2, sk.Inverse());
                    REQUIRE(p == p3);
                }
            }
        }
    }

    GIVEN("A client, server and a message") {
        string m = "hello world";
        Point point = Point::HashToPoint(m);

        THEN("the the client should be able to blind msg") {
            VOPRF_Blinded blinded = VOPRF::Blind(m);
            REQUIRE(blinded.x.ToString().size() > 0);
            REQUIRE(blinded.r.ToString().size() > 0);


            THEN("the server should be able to evaluate the blinded message") {
                Point fx = VOPRF::Evaluate(sk, blinded.x);
                REQUIRE(fx.ToString().size() > 0);

                THEN("the client should be able to unblind the evaluated message") {
                    Point y = VOPRF::Unblind(fx, blinded.r);
                    REQUIRE(y.ToString().size() > 0);

                    THEN("the client should be able to verify the evaluated message") {
                        bool ok = VOPRF::Verify(pk, m, y);
                        REQUIRE(ok);
                    }
                }
            }
        }
    }
}