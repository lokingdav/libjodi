#include "libcpex.hpp"
#include <chrono>
#include <iostream>
#include <utility>

namespace libcpex {

    CpexDHT::CpexDHT() {}

    CpexDHT::~CpexDHT() { StopDiscovery(); }

    vector<CpexNode> CpexDHT::FindNodes(Bytes key, size_t count) {
        std::lock_guard<std::mutex> lock(nodesMutex);
        vector<CpexNode> result;

        for (size_t i = 0; i < nodes.size() && i < count; i++) {
            result.push_back(nodes[i]);
        }

        return result;
    }

    void CpexDHT::StartDiscovery(string url) {
        std::lock_guard<std::mutex> lock(nodesMutex);

        if (discoveryRunning) {
            std::cerr << "[CpexDHT] Discovery already running.\n";
            return;
        }

        discoveryUrl = std::move(url);
        stopDiscoveryFlag = false;
        discoveryRunning = true;

        auto interval = std::chrono::minutes(1);

        discoveryThread = std::thread([this, interval]() {
            while (!stopDiscoveryFlag) {
                std::this_thread::sleep_for(interval);
                if (stopDiscoveryFlag) break;

                // This is where an actual request would happen
                // Simulate fetched nodes
                vector<CpexNode> fetchedNodes;
                CpexNode nodeA{"nodeIdA", "192.168.1.10", true};
                CpexNode nodeB{"nodeIdB", "192.168.1.11", true};
                fetchedNodes.push_back(nodeA);
                fetchedNodes.push_back(nodeB);

                {
                    std::lock_guard<std::mutex> lk(nodesMutex);
                    nodes = std::move(fetchedNodes);
                }
                
                std::cout << "[CpexDHT] Nodes updated by discovery.\n";
            }

            // Cleanup state when thread finishes
            {
                std::lock_guard<std::mutex> lk(nodesMutex);
                discoveryRunning = false;
            }
        });
    }

    void CpexDHT::StopDiscovery() {
        {
            std::lock_guard<std::mutex> lock(nodesMutex);
            if (!discoveryRunning) {
                return; // Not running
            }
            stopDiscoveryFlag = true;
        }

        if (discoveryThread.joinable()) {
            discoveryThread.join();
        }
    }
}
