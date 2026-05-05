#pragma once

#include <string>
#include <vector>

#include "User.h"
#include "FileManager.h"

// Starts a small blocking HTTP server on the given port.
// Uses a snapshot of the current app state for demo.

struct WebStateSnapshot {
	std::vector<User> users;
	std::vector<LoginLogEntry> logs;
	std::vector<ThreatRecord> threats;
	std::vector<std::pair<std::string, std::string>> edges;
};

int runHttpServer(int port, const std::string& frontendDir, WebStateSnapshot stateSnapshot);
