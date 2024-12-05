#ifndef ELEMENTS_HPP
#define ELEMENTS_HPP

namespace libcpex {
    class Scalar {
        public:
            static const size_t SIZE = 32;

            Scalar();
            Scalar(PrivateKey sk): sdata(sk) {};

            static Scalar Random();
            static Scalar Deserialize(vector<uint8_t>scalar);
            vector<uint8_t>Serialize();
            Scalar Inverse();
            PrivateKey GetScalarData() const;

            friend bool operator==(const Scalar &s1, const Scalar &s2);

        private:
            PrivateKey sdata;
    };

    class Point {
        public:
            Point(G1Element g1el): p(g1el) {};
            static Point HashToPoint(string message);
            static Point HashToPoint(vector<uint8_t>message);
            static Point Deserialize(vector<uint8_t>point);
            vector<uint8_t>Serialize();

            G1Element GetElement() const;

            void CheckValid() const;

            friend Point operator*(const Point &p, const Scalar &s);
            friend Point operator*(const Scalar &s, const Point &p);
            friend bool operator==(const Point &p1, const Point &p2);
        private:
            G1Element p;
    };
} // namespace libcpex

#endif // ELEMENTS_HPP
