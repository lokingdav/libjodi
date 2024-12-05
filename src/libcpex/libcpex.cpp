#include "libcpex.hpp"

namespace libcpex {
    void print(string message) {
        std::cout << message << std::endl;
    }

    void printlist(vector<uint8_t> message) {
        for (auto x: message) {
            std::cout << static_cast<int>(x) << ",";
        }
        print("");
    }
}
