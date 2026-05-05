#include <string>
#include <vector>
#include <sstream>
#include <fstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>
#endif

#include "server.h"
#include "HashTable.h"
#include "Heap.h"
#include "Graph.h"

// Very small HTTP server (bonus web UI).
// Single-threaded, blocking, demo-oriented.

struct WebRuntimeState {
    std::vector<User> users;
    std::vector<LoginLogEntry> logs;
    std::vector<ThreatRecord> threats;
    std::vector<std::pair<std::string, std::string>> edges;
    Graph graph;
    std::string lastGraphOutput;

    // Helper: build analytics on-demand.
    void buildAnalytics(std::vector<std::pair<std::string, int>>& topIps,
                        std::vector<std::pair<std::string, int>>& topUsers) const {
        HashTable<int> ipFails(211);
        HashTable<int> userFails(211);

        for (const auto& e : logs) {
            if (!e.success) {
                int* ipC = ipFails.get(e.ip);
                ipFails.put(e.ip, ipC ? (*ipC + 1) : 1);

                int* uC = userFails.get(e.username);
                userFails.put(e.username, uC ? (*uC + 1) : 1);
            }
        }

        struct PairItem {
            std::string key;
            int value;
            bool operator<(const PairItem& o) const { return value < o.value; }
        };

        MaxHeap<PairItem> ipHeap;
        ipFails.forEach([&](const std::string& k, const int& v) { ipHeap.push({k, v}); });
        for (int i = 0; i < 5; ++i) {
            PairItem it;
            if (!ipHeap.pop(it)) break;
            topIps.push_back({it.key, it.value});
        }

        MaxHeap<PairItem> userHeap;
        userFails.forEach([&](const std::string& k, const int& v) { userHeap.push({k, v}); });
        for (int i = 0; i < 5; ++i) {
            PairItem it;
            if (!userHeap.pop(it)) break;
            topUsers.push_back({it.key, it.value});
        }
    }
};

static std::string readAllText(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return "";
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::string htmlEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        default: out += c; break;
        }
    }
    return out;
}

static std::string usersTableHtml(const std::vector<User>& users) {
    std::ostringstream ss;
    ss << "<table class=\"table\"><thead><tr><th>ID</th><th>Username</th><th>Status</th></tr></thead><tbody>";
    for (const auto& u : users) {
        ss << "<tr><td>" << u.getId() << "</td><td>" << htmlEscape(u.getUsername())
           << "</td><td>" << htmlEscape(u.getStatus()) << "</td></tr>";
    }
    ss << "</tbody></table>";
    return ss.str();
}

static std::string threatsTableHtml(const std::vector<ThreatRecord>& threats) {
    std::ostringstream ss;
    ss << "<table class=\"table\"><thead><tr><th>IP</th><th>Failed</th><th>Severity</th></tr></thead><tbody>";
    int shown = 0;
    for (const auto& t : threats) {
        if (shown++ >= 5) break;
        ss << "<tr><td>" << htmlEscape(t.ip) << "</td><td>" << t.failedCount << "</td><td>" << t.severity << "</td></tr>";
    }
    ss << "</tbody></table>";
    return ss.str();
}

static std::string analyticsBlockHtml(const WebRuntimeState& st) {
    std::vector<std::pair<std::string, int>> topIps;
    std::vector<std::pair<std::string, int>> topUsers;
    st.buildAnalytics(topIps, topUsers);

    std::ostringstream ss;
    ss << "<div class=\"grid\" style=\"grid-template-columns:1fr 1fr; padding:0; gap:10px\">";

    ss << "<div><h3 style=\"margin:0 0 6px; font-size:14px\">Top Attacking IPs</h3>";
    ss << "<table class=\"table\"><thead><tr><th>IP</th><th>Fails</th></tr></thead><tbody>";
    for (const auto& p : topIps) {
        ss << "<tr><td>" << htmlEscape(p.first) << "</td><td>" << p.second << "</td></tr>";
    }
    ss << "</tbody></table></div>";

    ss << "<div><h3 style=\"margin:0 0 6px; font-size:14px\">Users With Most Failed Logins</h3>";
    ss << "<table class=\"table\"><thead><tr><th>User</th><th>Fails</th></tr></thead><tbody>";
    for (const auto& p : topUsers) {
        ss << "<tr><td>" << htmlEscape(p.first) << "</td><td>" << p.second << "</td></tr>";
    }
    ss << "</tbody></table></div>";

    ss << "</div>";
    return ss.str();
}

static std::string replaceAll(std::string s, const std::string& a, const std::string& b) {
    size_t pos = 0;
    while ((pos = s.find(a, pos)) != std::string::npos) {
        s.replace(pos, a.size(), b);
        pos += b.size();
    }
    return s;
}

static std::string urlDecode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') { out.push_back(' '); continue; }
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                return 0;
            };
            int v = (hex(s[i + 1]) << 4) | hex(s[i + 2]);
            out.push_back(static_cast<char>(v));
            i += 2;
            continue;
        }
        out.push_back(s[i]);
    }
    return out;
}

static std::string getQueryParam(const std::string& query, const std::string& key) {
    // query is like: a=1&b=2
    size_t pos = 0;
    while (pos < query.size()) {
        size_t eq = query.find('=', pos);
        if (eq == std::string::npos) break;
        std::string k = query.substr(pos, eq - pos);
        size_t amp = query.find('&', eq + 1);
        std::string v = (amp == std::string::npos) ? query.substr(eq + 1) : query.substr(eq + 1, amp - (eq + 1));
        if (k == key) return urlDecode(v);
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return "";
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(c); break;
        }
    }
    return out;
}

static std::string httpResponse(const std::string& body, const std::string& contentType = "text/html; charset=utf-8", int code = 200, const std::string& extraHeaders = "") {
    std::ostringstream ss;
    const char* reason = "OK";
    if (code == 303) reason = "See Other";
    else if (code == 400) reason = "Bad Request";
    else if (code == 404) reason = "Not Found";
    else if (code >= 500) reason = "Server Error";
    ss << "HTTP/1.1 " << code << ' ' << reason << "\r\n";
    ss << "Content-Type: " << contentType << "\r\n";
    ss << "Content-Length: " << body.size() << "\r\n";
    ss << "Connection: close\r\n";
    if (!extraHeaders.empty()) ss << extraHeaders;
    ss << "\r\n";
    ss << body;
    return ss.str();
}

static std::string httpRedirect(const std::string& location) {
    std::ostringstream ss;
    ss << "HTTP/1.1 303 See Other\r\n";
    ss << "Location: " << location << "\r\n";
    ss << "Content-Length: 0\r\n";
    ss << "Connection: close\r\n\r\n";
    return ss.str();
}

static std::string handleUsersJson(const WebRuntimeState& st) {
    std::ostringstream ss;
    ss << "{\"users\":[";
    for (size_t i = 0; i < st.users.size(); ++i) {
        const auto& u = st.users[i];
        ss << "{\"id\":" << u.getId() << ",\"username\":\"" << jsonEscape(u.getUsername())
           << "\",\"status\":\"" << jsonEscape(u.getStatus()) << "\"}";
        if (i + 1 < st.users.size()) ss << ',';
    }
    ss << "]}";
    return ss.str();
}

static std::string handleAnalyticsJson(const WebRuntimeState& st) {
    std::vector<std::pair<std::string, int>> topIps;
    std::vector<std::pair<std::string, int>> topUsers;
    st.buildAnalytics(topIps, topUsers);

    std::ostringstream ss;
    ss << "{\"top_ips\":[";
    for (size_t i = 0; i < topIps.size(); ++i) {
        ss << "{\"ip\":\"" << jsonEscape(topIps[i].first) << "\",\"fails\":" << topIps[i].second << "}";
        if (i + 1 < topIps.size()) ss << ',';
    }
    ss << "],\"top_users\":[";
    for (size_t i = 0; i < topUsers.size(); ++i) {
        ss << "{\"username\":\"" << jsonEscape(topUsers[i].first) << "\",\"fails\":" << topUsers[i].second << "}";
        if (i + 1 < topUsers.size()) ss << ',';
    }
    ss << "]}";
    return ss.str();
}

static std::string handleGraphJson(WebRuntimeState& st, const std::string& start, const std::string& mode) {
    std::string traversal;
    if (mode == "dfs") traversal = st.graph.dfs(start);
    else traversal = st.graph.bfs(start);
    st.lastGraphOutput = traversal;

    std::ostringstream ss;
    ss << "{\"start\":\"" << jsonEscape(start) << "\",\"mode\":\"" << jsonEscape(mode)
       << "\",\"output\":\"" << jsonEscape(traversal) << "\"}";
    return ss.str();
}

static std::string handleDashboard(WebRuntimeState& st, const std::string& frontendDir) {
    std::string html = readAllText(frontendDir + "\\index.html");
    if (html.empty()) return "<h1>Dashboard not found</h1>";

    html = replaceAll(html, "{{USERS_TABLE}}", usersTableHtml(st.users));
    html = replaceAll(html, "{{THREATS_TABLE}}", threatsTableHtml(st.threats));
    html = replaceAll(html, "{{ANALYTICS_BLOCK}}", analyticsBlockHtml(st));
    html = replaceAll(html, "{{GRAPH_OUTPUT}}", htmlEscape(st.lastGraphOutput));
    return html;
}

static std::string handleStyleCss(const std::string& frontendDir) {
    std::string css = readAllText(frontendDir + "\\style.css");
    if (css.empty()) css = "body{font-family:Arial;}";
    return css;
}

static void parseFormUrlEncoded(const std::string& body, std::string& ip, std::string& username, std::string& password) {
    ip = getQueryParam(body, "ip");
    username = getQueryParam(body, "username");
    password = getQueryParam(body, "password");
}

static void closesocket_cross(int s) {
#ifdef _WIN32
    closesocket((SOCKET)s);
#else
    close(s);
#endif
}

int runHttpServer(int port, const std::string& frontendDir, WebStateSnapshot stateSnapshot) {
#ifdef _WIN32
    using socket_t = SOCKET;
#else
    using socket_t = int;
#endif

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }
#endif

    socket_t serverSock = (socket_t)socket(AF_INET, SOCK_STREAM, 0);
    if ((int)serverSock < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((u_short)port);

    if (bind(serverSock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket_cross((int)serverSock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (listen(serverSock, 8) < 0) {
        closesocket_cross((int)serverSock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    WebRuntimeState st;
    st.users = stateSnapshot.users;
    st.logs = stateSnapshot.logs;
    st.threats = stateSnapshot.threats;
    st.edges = stateSnapshot.edges;
    st.lastGraphOutput = "";
    for (const auto& e : st.edges) {
        st.graph.addEdge(e.first, e.second);
    }

    while (true) {
        socket_t client = accept(serverSock, nullptr, nullptr);
        if ((int)client < 0) break;

        char buf[8192];
        int received = recv(client, buf, sizeof(buf) - 1, 0);
        if (received <= 0) {
            closesocket_cross((int)client);
            continue;
        }
        buf[received] = '\0';
        std::string req(buf);

        // Parse request line
        std::istringstream rs(req);
        std::string method, target, version;
        rs >> method >> target >> version;

        std::string path = target;
        std::string query;
        size_t qpos = target.find('?');
        if (qpos != std::string::npos) {
            path = target.substr(0, qpos);
            query = target.substr(qpos + 1);
        }

        // Very small body extraction
        std::string body;
        size_t headerEnd = req.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            body = req.substr(headerEnd + 4);
        }

        std::string resp;

        if (method == "GET" && path == "/") {
            resp = httpResponse(handleDashboard(st, frontendDir));
        } else if (method == "GET" && path == "/style.css") {
            resp = httpResponse(handleStyleCss(frontendDir), "text/css; charset=utf-8");
        } else if (method == "GET" && path == "/users") {
            resp = httpResponse(handleUsersJson(st), "application/json; charset=utf-8");
        } else if (method == "GET" && path == "/analytics") {
            resp = httpResponse(handleAnalyticsJson(st), "application/json; charset=utf-8");
        } else if (method == "GET" && path == "/graph") {
            std::string start = getQueryParam(query, "start");
            std::string mode = getQueryParam(query, "mode");
            std::string json = getQueryParam(query, "json");
            if (mode.empty()) mode = "bfs";
            if (!start.empty()) {
                std::string payload = handleGraphJson(st, start, mode);
                if (json == "1") {
                    resp = httpResponse(payload, "application/json; charset=utf-8");
                } else {
                    // For dashboard usage, update lastGraphOutput and redirect back to /.
                    resp = httpRedirect("/");
                }
            } else {
                resp = httpResponse("{\"error\":\"missing start\"}", "application/json; charset=utf-8", 400);
            }
        } else if (method == "POST" && path == "/login") {
            // Demo: accept form post, log as queued attempt not processed.
            std::string ip, username, password;
            parseFormUrlEncoded(body, ip, username, password);
            if (!ip.empty() && !username.empty()) {
                LoginLogEntry e;
                e.ts = "WEB";
                e.ip = ip;
                e.username = username;
                e.success = false;
                e.message = "Queued via Web UI (process in CLI)";
                st.logs.push_back(e);
                std::string from = "IP:" + ip;
                std::string to = "U:" + username;
                st.edges.push_back({from, to});
                st.graph.addEdge(from, to);
            }
            // Optional JSON mode: POST /login?json=1
            std::string json = getQueryParam(query, "json");
            if (json == "1") {
                resp = httpResponse("{\"status\":\"queued\"}", "application/json; charset=utf-8");
            } else {
                resp = httpRedirect("/");
            }
        } else {
            resp = httpResponse("Not Found", "text/plain; charset=utf-8", 404);
        }

        send(client, resp.c_str(), (int)resp.size(), 0);
        closesocket_cross((int)client);
    }

    closesocket_cross((int)serverSock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
