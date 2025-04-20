#include "libjodi.hpp"
#include <chrono>
#include <iostream>
#include <utility>

namespace libjodi {

    JodiDHT::JodiDHT() {}

    JodiDHT::~JodiDHT() { StopDiscovery(); }

    vector<JodiNode> JodiDHT::FindNodes(Bytes key, size_t count) {
        std::lock_guard<std::mutex> lock(nodesMutex);
        vector<JodiNode> result;

        for (size_t i = 0; i < nodes.size() && i < count; i++) {
            result.push_back(nodes[i]);
        }

        return result;
    }

    void JodiDHT::StartDiscovery(string url) {
        std::lock_guard<std::mutex> lock(nodesMutex);

        if (discoveryRunning) {
            std::cerr << "[JodiDHT] Discovery already running.\n";
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
                vector<JodiNode> fetchedNodes;
                JodiNode nodeA{"nodeIdA", "192.168.1.10", true};
                JodiNode nodeB{"nodeIdB", "192.168.1.11", true};
                fetchedNodes.push_back(nodeA);
                fetchedNodes.push_back(nodeB);

                {
                    std::lock_guard<std::mutex> lk(nodesMutex);
                    nodes = std::move(fetchedNodes);
                }
                
                std::cout << "[JodiDHT] Nodes updated by discovery.\n";
            }

            // Cleanup state when thread finishes
            {
                std::lock_guard<std::mutex> lk(nodesMutex);
                discoveryRunning = false;
            }
        });
    }

    void JodiDHT::StopDiscovery() {
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
