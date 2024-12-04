#include "libcpex.hpp"

namespace libcpex {
    Http::Http() {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    Http::~Http() {
        curl_global_cleanup();
    }

    size_t Http::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    void Http::performGetRequest(const Request& req, string& response) {
        CURL* curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, req.url.c_str());

            struct curl_slist* headers = NULL;
            for (const auto& header : req.headers) {
                string header_entry = header.first + ": " + header.second;
                headers = curl_slist_append(headers, header_entry.c_str());
            }
            if (headers) {
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            }

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Http::WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "GET request failed: " << curl_easy_strerror(res) << std::endl;
            }

            if (headers) {
                curl_slist_free_all(headers);
            }

            curl_easy_cleanup(curl);
        }
    }

    void Http::performPostRequest(const Request& req, string& response) {
        CURL* curl = curl_easy_init();

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, req.url.c_str());

            curl_easy_setopt(curl, CURLOPT_POST, 1L);

            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.payload.c_str());

            struct curl_slist* headers = NULL;
            for (const auto& header : req.headers) {
                string header_entry = header.first + ": " + header.second;
                headers = curl_slist_append(headers, header_entry.c_str());
            }
            if (headers) {
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            }

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Http::WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "POST request failed: " << curl_easy_strerror(res) << std::endl;
            }

            if (headers) {
                curl_slist_free_all(headers);
            }

            curl_easy_cleanup(curl);
        }
    }
    
    vector<string> Http::get(const vector<Request>& requests) {
        size_t n = requests.size();
        vector<string> responses(n);
        vector<thread> threads;

        for (size_t i = 0; i < n; ++i) {
            threads.emplace_back(&Http::performGetRequest, this, std::cref(requests[i]), std::ref(responses[i]));
        }

        for (auto& t : threads) {
            t.join();
        }

        return responses;
    }

    vector<string> Http::post(const vector<Request>& requests) {
        size_t n = requests.size();
        vector<string> responses(n);
        vector<thread> threads;

        for (size_t i = 0; i < n; ++i) {
            threads.emplace_back(&Http::performPostRequest, this, std::cref(requests[i]), std::ref(responses[i]));
        }

        for (auto& t : threads) {
            t.join();
        }

        return responses;
    }
}
