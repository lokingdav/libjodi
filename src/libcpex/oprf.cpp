#include "libcpex.hpp"

namespace libcpex {
    Point OPRF::Mask(string& msg, Scalar* out) {
        Point point = Point::HashToPoint(msg); 
        *out = Scalar::Random();
        return *out * point; 
    }

    vector<uint8_t>Evaluate(vector<uint8_t>key, vector<uint8_t>point) {
        Point p = Scalar::Deserialize(key) * Point::Deserialize(point);
        return p.Serialize();
    }

    vector<uint8_t>Evaluate(Scalar key, vector<uint8_t>point) {
        return (key * Point::Deserialize(point)).Serialize();
    }
}