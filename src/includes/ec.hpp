#ifndef ELEMENTS_HPP
#define ELEMENTS_HPP

namespace libcpex {
    class Scalar {
        public:
            static const size_t SIZE = 32;

            Scalar() = default;
            Scalar(blst_scalar* sd): sdata(sd) {};

            static Scalar Random();
            void CheckKeyData() const;
            static Scalar Deserialize(Bytes scalar);
            Bytes Serialize();
            Scalar Inverse();
            blst_scalar GetScalarData();

            friend bool operator==(const Scalar &s1, const Scalar &s2);

        private:
            blst_scalar* sdata;
    };

    class Point {
        public:
            Point() = default;
            Point(G1Element g1el): p(g1el) {};
            static Point HashToPoint(string message);
            static Point HashToPoint(Bytes message);
            static Point Deserialize(Bytes point);
            Bytes Serialize();

            G1Element GetPointData();

            friend Point operator*(const Point &p, const Scalar &s);
            friend Point operator*(const Scalar &s, const Point &p);
            friend bool operator==(Point &p1, Point &p2);
        private:
            G1Element p;
    };
} // namespace libcpex

#endif // ELEMENTS_HPP
