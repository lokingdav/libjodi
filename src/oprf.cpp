#include "libcpex.hpp"

namespace libcpex {
    Point OPRF::Mask(string& msg, Scalar* out) {
        Point point = Point::HashToPoint(msg); 
        *out = Scalar::Random();
        return *out * point; 
    }

    Bytes Evaluate(Bytes key, Bytes point) {
        Point p = Scalar::Deserialize(key) * Point::Deserialize(point);
        return p.Serialize();
    }

    Bytes Evaluate(Scalar key, Bytes point) {
        return (key * Point::Deserialize(point)).Serialize();
    }
}