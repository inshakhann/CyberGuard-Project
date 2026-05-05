#include "FileManager.h"

std::vector<std::string> FileManager::split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

FileManager::FileManager(const std::string& dataDir) : dataDir(dataDir) {}

std::string FileManager::usersPath() const { return dataDir + "\\users.txt"; }
std::string FileManager::logsPath() const { return dataDir + "\\login_logs.txt"; }
std::string FileManager::threatsPath() const { return dataDir + "\\threats.txt"; }
std::string FileManager::graphPath() const { return dataDir + "\\graph.txt"; }

bool FileManager::loadUsers(std::vector<User>& usersOut) const {
    usersOut.clear();
    std::ifstream in(usersPath());
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto parts = split(line, '|');
        if (parts.size() < 4) continue;
        int id = std::stoi(parts[0]);
        usersOut.emplace_back(id, parts[1], parts[2], parts[3]);
    }
    return true;
}

bool FileManager::saveUsers(const std::vector<User>& users) const {
    std::ofstream out(usersPath(), std::ios::trunc);
    if (!out.is_open()) return false;
    out << "# id|username|password|status\n";
    for (const auto& u : users) {
        out << u.getId() << '|' << u.getUsername() << '|' << u.getPassword() << '|' << u.getStatus() << "\n";
    }
    return true;
}

bool FileManager::loadLogs(std::vector<LoginLogEntry>& logsOut) const {
    logsOut.clear();
    std::ifstream in(logsPath());
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto parts = split(line, '|');
        if (parts.size() < 5) continue;
        LoginLogEntry e;
        e.ts = parts[0];
        e.ip = parts[1];
        e.username = parts[2];
        e.success = (parts[3] == "1");
        e.message = parts[4];
        logsOut.push_back(e);
    }
    return true;
}

bool FileManager::saveLogs(const std::vector<LoginLogEntry>& logs) const {
    std::ofstream out(logsPath(), std::ios::trunc);
    if (!out.is_open()) return false;
    out << "# ts|ip|username|success|message\n";
    for (const auto& e : logs) {
        out << e.ts << '|' << e.ip << '|' << e.username << '|' << (e.success ? "1" : "0") << '|' << e.message << "\n";
    }
    return true;
}

bool FileManager::loadThreats(std::vector<ThreatRecord>& threatsOut) const {
    threatsOut.clear();
    std::ifstream in(threatsPath());
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto parts = split(line, '|');
        if (parts.size() < 3) continue;
        ThreatRecord t;
        t.ip = parts[0];
        t.failedCount = std::stoi(parts[1]);
        t.severity = std::stoi(parts[2]);
        threatsOut.push_back(t);
    }
    return true;
}

bool FileManager::saveThreats(const std::vector<ThreatRecord>& threats) const {
    std::ofstream out(threatsPath(), std::ios::trunc);
    if (!out.is_open()) return false;
    out << "# ip|failedCount|severity\n";
    for (const auto& t : threats) {
        out << t.ip << '|' << t.failedCount << '|' << t.severity << "\n";
    }
    return true;
}

bool FileManager::loadGraphEdges(std::vector<std::pair<std::string, std::string>>& edgesOut) const {
    edgesOut.clear();
    std::ifstream in(graphPath());
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto parts = split(line, '|');
        if (parts.size() < 2) continue;
        edgesOut.push_back({parts[0], parts[1]});
    }
    return true;
}

bool FileManager::saveGraphEdges(const std::vector<std::pair<std::string, std::string>>& edges) const {
    std::ofstream out(graphPath(), std::ios::trunc);
    if (!out.is_open()) return false;
    out << "# src|dst  (src/dst are node ids like IP:1.2.3.4 or U:alice)\n";
    for (const auto& e : edges) {
        out << e.first << '|' << e.second << "\n";
    }
    return true;
}
