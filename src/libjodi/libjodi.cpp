#include "libjodi.hpp"

namespace libjodi {
    void print(string message) {
        std::cout << message << std::endl;
    }

    void printlist(Bytes message) {
        for (auto x: message) {
            std::cout << static_cast<int>(x) << std::endl;
        }
    }

    void printBytes(Bytes inp) {
        for (auto x: inp) {
            std::cout << static_cast<int>(x) << ", ";
        }
        print("");
    }

    void panic(string message) {
        throw std::runtime_error(message);
    }
}
