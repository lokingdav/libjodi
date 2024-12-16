#include <thread>
#include <curl/curl.h>
#include <sstream>

#include <future>        // For std::future and std::async
#include <utility>       // For std::move (if needed)
#include <functional>    // For std::function (optional)
#include <stdexcept>

#include "./includes/http.hpp"

using namespace libcpex;

namespace {
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        std::string* str = (std::string*) userp;
        size_t totalSize = size * nmemb;
        str->append((char*)contents, totalSize);
        return totalSize;
    }

    static size_t HeaderCallback(void* buffer, size_t size, size_t nmemb, void* userdata) {
        size_t totalSize = size * nmemb;
        std::string header((char*)buffer, totalSize);

        auto* hdrMap = static_cast<std::map<std::string, std::string>*>(userdata);

        // Typical header format: "Key: Value\r\n"
        // We skip lines like "HTTP/1.1 200 OK"
        auto colonPos = header.find(':');
        if (colonPos != std::string::npos) {
            auto trim = [](std::string &s) {
                while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
                while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
            };
            std::string key = header.substr(0, colonPos);
            std::string val = header.substr(colonPos + 1);
            // Remove trailing \r\n
            while (!val.empty() && (val.back() == '\r' || val.back() == '\n')) {
                val.pop_back();
            }
            trim(key);
            trim(val);
            if (!key.empty() && !val.empty()) {
                (*hdrMap)[key] = val;
            }
        }

        return totalSize;
    }

    static curl_slist* setRequestHeaders(CURL* curl, const std::map<std::string, std::string>& headers) {
        curl_slist* chunk = nullptr;
        for (auto& h : headers) {
            std::string hdr = h.first + ": " + h.second;
            chunk = curl_slist_append(chunk, hdr.c_str());
        }
        if (chunk) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        }
        return chunk;
    }

    static std::string buildPostFields(CURL* curl, const std::map<std::string, std::string>& body) {
        std::string postFields;
        for (auto it = body.begin(); it != body.end(); ++it) {
            if (it != body.begin()) postFields += "&";
            char* key_escaped = curl_easy_escape(curl, it->first.c_str(), 0);
            char* val_escaped = curl_easy_escape(curl, it->second.c_str(), 0);
            postFields += key_escaped;
            postFields += "=";
            postFields += val_escaped;
            curl_free(key_escaped);
            curl_free(val_escaped);
        }
        return postFields;
    }
    
    static std::map<std::string, std::string> parsePayload(const std::string& body) {
        std::map<std::string, std::string> payload;

        if (body.find('=') != std::string::npos) {
            std::istringstream ss(body);
            std::string kv;
            while (std::getline(ss, kv, '&')) {
                auto eqPos = kv.find('=');
                if (eqPos != std::string::npos) {
                    std::string key = kv.substr(0, eqPos);
                    std::string val = kv.substr(eqPos + 1);
                    payload[key] = val;
                } else {
                    // Not properly formatted, fallback
                    payload.clear();
                    payload["raw_body"] = body;
                    return payload;
                }
            }
            // If we got here, we managed to parse some pairs
            if (payload.empty()) {
                payload["raw_body"] = body;
            }
        } else {
            // Just store raw
            payload["raw_body"] = body;
        }

        return payload;
    }

}

std::vector<Response> Http::gets(const std::vector<Request>& requests) {
    std::vector<std::future<Response>> futures;
    futures.reserve(requests.size());

    // Launch each get request asynchronously.
    for (const auto& req : requests) {
        futures.emplace_back(std::async(std::launch::async, [&req]() {
            return get(req);
        }));
    }

    // Collect the results
    std::vector<Response> results;
    results.reserve(futures.size());
    for (auto& f : futures) {
        results.push_back(f.get());
    }

    return results;
}

std::vector<Response> Http::posts(const std::vector<Request>& requests) {
    std::vector<std::future<Response>> futures;
    futures.reserve(requests.size());

    // Launch each post request asynchronously.
    for (const auto& req : requests) {
        futures.emplace_back(std::async(std::launch::async, [&req]() {
            return post(req);
        }));
    }

    // Collect the results
    std::vector<Response> results;
    results.reserve(futures.size());
    for (auto& f : futures) {
        results.push_back(f.get());
    }

    return results;
}

Response Http::get(const Request& req) {
    return performHttpRequest(req, false);
}

Response Http::post(const Request& req) {
    return performHttpRequest(req, true);
}

Response Http::performHttpRequest(const Request& req, bool isPost) {
    Response resp;
    resp.success = false;
    resp.statusCode = 0;
    resp.errorMessage.clear();
    resp.payload.clear();
    resp.headers.clear();

    CURL* curl = curl_easy_init();
    if (!curl) {
        resp.errorMessage = "Failed to initialize CURL";
        return resp;
    }

    std::string responseBody;
    curl_easy_setopt(curl, CURLOPT_URL, req.endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp.headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    curl_slist *chunk = setRequestHeaders(curl, req.headers);

    if (isPost) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        std::string postFields = buildPostFields(curl, req.body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        resp.errorMessage = curl_easy_strerror(res);
    }

    // Check HTTP status code
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    resp.statusCode = static_cast<int>(httpCode);

    // Determine success based on HTTP status code and curl result
    if (res == CURLE_OK && httpCode >= 200 && httpCode < 300) {
        resp.success = true;
    } else {
        if (resp.errorMessage.empty() && (httpCode < 200 || httpCode >= 300)) {
            resp.errorMessage = "HTTP request failed with status code: " + std::to_string(httpCode);
        }
    }

    // Parse payload
    resp.payload = parsePayload(responseBody);

    if (chunk) curl_slist_free_all(chunk);
    curl_easy_cleanup(curl);

    return resp;
}
