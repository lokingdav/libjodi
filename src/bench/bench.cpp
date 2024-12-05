#include <sodium.h>
#include <chrono>

#include "../libcpex/libcpex.hpp"

const int numIters = 1000;

auto startTimer() {
    return std::chrono::high_resolution_clock::now();
}

void endTimer(auto start, auto iters) {
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Time taken: " << duration.count() / iters << " microseconds\n";
}

int main(int argc, char* argv[])
{
    auto keypair = libcpex::OPRF::Keygen();

    string message = "hello";
    
    auto start = startTimer();
    for (auto i = 0; i < numIters; i++) {
        auto blinded = libcpex::OPRF::Blind(&message);
        auto answer = libcpex::OPRF::Evaluate(keypair, blinded.mask);
        Bytes label = libcpex::OPRF::Unblind(answer, blinded.sk);
    }
    endTimer(start, numIters);

    libcpex::print("Done!");

    return 0;
}