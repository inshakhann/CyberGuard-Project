#pragma once

#include <string>
#include <vector>
#include <fstream>

#include "User.h"
#include "Graph.h"

struct LoginLogEntry {
    std::string ts;
    std::string ip;
    std::string username;
    bool success;
    std::string message;
};

struct ThreatRecord {
    std::string ip;
    int failedCount;
    int severity;

    bool operator<(const ThreatRecord& other) const {
        return severity < other.severity;
    }
};

class FileManager {
private:
    std::string dataDir;

    static std::vector<std::string> split(const std::string& s, char delim);

public:
    explicit FileManager(const std::string& dataDir);

    bool loadUsers(std::vector<User>& usersOut) const;
    bool saveUsers(const std::vector<User>& users) const;

    bool loadLogs(std::vector<LoginLogEntry>& logsOut) const;
    bool saveLogs(const std::vector<LoginLogEntry>& logs) const;

    bool loadThreats(std::vector<ThreatRecord>& threatsOut) const;
    bool saveThreats(const std::vector<ThreatRecord>& threats) const;

    bool loadGraphEdges(std::vector<std::pair<std::string, std::string>>& edgesOut) const;
    bool saveGraphEdges(const std::vector<std::pair<std::string, std::string>>& edges) const;

    std::string usersPath() const;
    std::string logsPath() const;
    std::string threatsPath() const;
    std::string graphPath() const;
};
