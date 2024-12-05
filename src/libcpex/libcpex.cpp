#include "libcpex.hpp"

namespace libcpex {
    void print(string message) {
        std::cout << message << std::endl;
    }

    void printlist(Bytes message) {
        for (auto x: message) {
            std::cout << static_cast<int>(x) << std::endl;
        }
    }

    void panic(string message) {
        throw std::runtime_error(message);
    }
}
