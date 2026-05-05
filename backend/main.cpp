#include <iostream>
#include <string>
#include <vector>

#include "User.h"
#include "HashTable.h"
#include "LinkedList.h"
#include "DoublyLinkedList.h"
#include "Queue.h"
#include "Stack.h"
#include "Heap.h"
#include "Graph.h"
#include "FileManager.h"
#include "server.h"

struct LoginAttempt {
    std::string ip;
    std::string username;
    std::string password;
};

struct AdminAction {
    enum Type { ADD_USER, DELETE_USER } type;
    User userSnapshot;
};

static std::string nowStamp() {
    // Minimal timestamp for logs (academic demo): not using heavy time libs.
    return "CLI";
}

class CyberGuardApp {
private:
    FileManager files;

    // Primary storage: vector for persistence + HashTable for O(1) lookup.
    std::vector<User> users;
    HashTable<int> usernameToIndex; // username -> index in users vector

    Queue<LoginAttempt> attemptQueue;

    // Logs
    std::vector<LoginLogEntry> logsForFile;
    DoublyLinkedList<LoginLogEntry> logList; // traversal demo

    // Undo + recent activity
    Stack<AdminAction> undoStack;
    Stack<std::string> recentActivity;

    // Threats
    HashTable<int> ipFailedCount; // ip -> failed attempts
    std::vector<ThreatRecord> threatsForFile;

    // Graph
    Graph graph;
    std::vector<std::pair<std::string, std::string>> edgesForFile;

    int nextUserId;

    void rebuildUsernameIndex() {
        usernameToIndex = HashTable<int>(211);
        for (int i = 0; i < (int)users.size(); ++i) {
            usernameToIndex.put(users[i].getUsername(), i);
        }
    }

    void logAction(const LoginLogEntry& e) {
        logsForFile.push_back(e);
        logList.pushBack(e);

        recentActivity.push(e.ts + " | " + e.ip + " | " + e.username + " | " + (e.success ? "SUCCESS" : "FAIL") + " | " + e.message);
    }

    bool validateIpBasic(const std::string& ip) const {
        // Basic validation: must contain at least one dot.
        return !ip.empty() && ip.find('.') != std::string::npos;
    }

    int computeSeverity(const std::string& ip, int failedCount) const {
        // Minimal severity rule: severity = failedCount * 10
        // (Easy to explain in viva; ties are fine.)
        (void)ip;
        return failedCount * 10;
    }

    void rebuildThreatsFileSnapshot() {
        threatsForFile.clear();
        ipFailedCount.forEach([&](const std::string& ip, const int& count) {
            ThreatRecord t;
            t.ip = ip;
            t.failedCount = count;
            t.severity = computeSeverity(ip, count);
            threatsForFile.push_back(t);
        });

        // Sort-like output not required; heap will rank when displaying.
    }

    void rebuildEdgesFileSnapshot() {
        edgesForFile.clear();
        // Graph stores adjacency; for file we store edges whenever we add them.
        // We also append to edgesForFile in add edge paths.
    }

    void loadAll() {
        std::vector<User> loadedUsers;
        files.loadUsers(loadedUsers);
        users = loadedUsers;

        nextUserId = 1;
        for (const auto& u : users) {
            if (u.getId() >= nextUserId) nextUserId = u.getId() + 1;
        }
        rebuildUsernameIndex();

        std::vector<LoginLogEntry> loadedLogs;
        files.loadLogs(loadedLogs);
        logsForFile = loadedLogs;
        logList.clear();
        for (const auto& e : logsForFile) {
            logList.pushBack(e);
        }

        // Threats: recompute from logs on load (more reliable than stale file)
        ipFailedCount = HashTable<int>(211);
        for (const auto& e : logsForFile) {
            if (!e.success) {
                int* c = ipFailedCount.get(e.ip);
                ipFailedCount.put(e.ip, c ? (*c + 1) : 1);
            }
        }
        rebuildThreatsFileSnapshot();

        // Graph
        std::vector<std::pair<std::string, std::string>> edges;
        files.loadGraphEdges(edges);
        edgesForFile = edges;
        for (const auto& ed : edgesForFile) {
            graph.addEdge(ed.first, ed.second);
        }
    }

    void saveAll() {
        files.saveUsers(users);
        files.saveLogs(logsForFile);
        rebuildThreatsFileSnapshot();
        files.saveThreats(threatsForFile);
        files.saveGraphEdges(edgesForFile);
    }

    void pause() {
        std::cout << "\nPress Enter to continue...";
        std::string dummy;
        std::getline(std::cin, dummy);
    }

    void printUsers() const {
        std::cout << "\n--- Users (Linked List traversal demo) ---\n";

        // For traversal demo, copy to a linked list and traverse.
        LinkedList<User> list;
        for (const auto& u : users) list.pushFront(u);

        list.forEach([&](const User& u) {
            std::cout << "ID=" << u.getId() << " | " << u.getUsername() << " | " << u.getStatus() << "\n";
        });
    }

    void addUser() {
        std::string username, password;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);

        if (username.empty() || password.empty()) {
            std::cout << "Invalid input.\n";
            return;
        }

        if (usernameToIndex.get(username)) {
            std::cout << "User already exists.\n";
            return;
        }

        User u(nextUserId++, username, password, "ACTIVE");
        users.push_back(u);
        usernameToIndex.put(username, (int)users.size() - 1);

        AdminAction act;
        act.type = AdminAction::ADD_USER;
        act.userSnapshot = u;
        undoStack.push(act);

        recentActivity.push("ADMIN | add user " + username);

        std::cout << "User added.\n";
    }

    void deleteUser() {
        std::string username;
        std::cout << "Username to delete: ";
        std::getline(std::cin, username);

        int* idx = usernameToIndex.get(username);
        if (!idx) {
            std::cout << "User not found.\n";
            return;
        }

        User snapshot = users[*idx];

        // Delete from vector: swap with last for O(1) delete, then rebuild mapping.
        users[*idx] = users.back();
        users.pop_back();
        rebuildUsernameIndex();

        AdminAction act;
        act.type = AdminAction::DELETE_USER;
        act.userSnapshot = snapshot;
        undoStack.push(act);

        recentActivity.push("ADMIN | delete user " + username);

        std::cout << "User deleted.\n";
    }

    void searchUser() const {
        std::string username;
        std::cout << "Username to search: ";
        std::getline(std::cin, username);

        const int* idx = usernameToIndex.get(username);
        if (!idx) {
            std::cout << "User not found.\n";
            return;
        }
        const User& u = users[*idx];
        std::cout << "Found: ID=" << u.getId() << " | " << u.getUsername() << " | " << u.getStatus() << "\n";
    }

    void userManagementMenu() {
        while (true) {
            std::cout << "\n== User Management ==\n";
            std::cout << "1. Add user\n";
            std::cout << "2. Delete user\n";
            std::cout << "3. Search user\n";
            std::cout << "4. Display users\n";
            std::cout << "5. Back\n";
            std::cout << "Choice: ";

            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") addUser();
            else if (choice == "2") deleteUser();
            else if (choice == "3") searchUser();
            else if (choice == "4") printUsers();
            else if (choice == "5") return;
            else std::cout << "Invalid choice.\n";
        }
    }

    void simulateLoginAttempt() {
        LoginAttempt a;
        std::cout << "IP: ";
        std::getline(std::cin, a.ip);
        std::cout << "Username: ";
        std::getline(std::cin, a.username);
        std::cout << "Password: ";
        std::getline(std::cin, a.password);

        if (!validateIpBasic(a.ip) || a.username.empty() || a.password.empty()) {
            std::cout << "Invalid input.\n";
            return;
        }

        attemptQueue.enqueue(a);
        recentActivity.push("QUEUE | login attempt enqueued for " + a.username + " from " + a.ip);
        std::cout << "Attempt enqueued. Queue size=" << attemptQueue.size() << "\n";

        // Graph edge recorded at attempt time
        std::string ipNode = "IP:" + a.ip;
        std::string userNode = "U:" + a.username;
        graph.addEdge(ipNode, userNode);
        edgesForFile.push_back({ipNode, userNode});
    }

    void processLoginQueue() {
        std::cout << "\nProcessing queue...\n";
        int processed = 0;

        while (!attemptQueue.empty()) {
            LoginAttempt a;
            attemptQueue.dequeue(a);
            ++processed;

            LoginLogEntry e;
            e.ts = nowStamp();
            e.ip = a.ip;
            e.username = a.username;

            const int* idx = usernameToIndex.get(a.username);
            if (!idx) {
                e.success = false;
                e.message = "Unknown user";
            } else {
                const User& u = users[*idx];
                if (u.getStatus() != "ACTIVE") {
                    e.success = false;
                    e.message = "User not active";
                } else if (u.getPassword() == a.password) {
                    e.success = true;
                    e.message = "Login success";
                } else {
                    e.success = false;
                    e.message = "Wrong password";
                }
            }

            if (!e.success) {
                int* c = ipFailedCount.get(e.ip);
                ipFailedCount.put(e.ip, c ? (*c + 1) : 1);
            }

            logAction(e);
        }

        rebuildThreatsFileSnapshot();
        std::cout << "Processed " << processed << " attempts.\n";
    }

    void threatAnalysis() const {
        std::cout << "\n== Threat Analysis (Max Heap ranking) ==\n";

        MaxHeap<ThreatRecord> heap;
        ipFailedCount.forEach([&](const std::string& ip, const int& count) {
            ThreatRecord t;
            t.ip = ip;
            t.failedCount = count;
            t.severity = computeSeverity(ip, count);
            heap.push(t);
        });

        if (heap.empty()) {
            std::cout << "No threats yet.\n";
            return;
        }

        for (int i = 0; i < 5; ++i) {
            ThreatRecord t;
            if (!heap.pop(t)) break;
            std::cout << (i + 1) << ". IP=" << t.ip << " | failed=" << t.failedCount << " | severity=" << t.severity << "\n";
        }
    }

    void analyticsReports() const {
        std::cout << "\n== Analytics Reports ==\n";

        HashTable<int> userFails(211);
        for (const auto& e : logsForFile) {
            if (!e.success) {
                int* c = userFails.get(e.username);
                userFails.put(e.username, c ? (*c + 1) : 1);
            }
        }

        struct PairItem {
            std::string key;
            int value;
            bool operator<(const PairItem& o) const { return value < o.value; }
        };

        std::cout << "Top Attacking IPs:\n";
        MaxHeap<PairItem> ipHeap;
        ipFailedCount.forEach([&](const std::string& ip, const int& count) { ipHeap.push({ip, count}); });
        for (int i = 0; i < 5; ++i) {
            PairItem it;
            if (!ipHeap.pop(it)) break;
            std::cout << "- " << it.key << ": " << it.value << " failed\n";
        }

        std::cout << "\nUsers With Most Failed Logins:\n";
        MaxHeap<PairItem> uHeap;
        userFails.forEach([&](const std::string& u, const int& c) { uHeap.push({u, c}); });
        for (int i = 0; i < 5; ++i) {
            PairItem it;
            if (!uHeap.pop(it)) break;
            std::cout << "- " << it.key << ": " << it.value << " failed\n";
        }
    }

    void attackGraphMenu() {
        std::cout << "\n== Attack Graph (Adjacency List) ==\n";
        std::cout << "Enter start node (e.g., IP:192.168.1.10 or U:alice): ";
        std::string start;
        std::getline(std::cin, start);
        if (start.empty()) {
            std::cout << "Invalid start.\n";
            return;
        }

        std::cout << "1. BFS\n2. DFS\nChoice: ";
        std::string c;
        std::getline(std::cin, c);
        if (c == "1") {
            std::cout << "BFS: " << graph.bfs(start) << "\n";
        } else if (c == "2") {
            std::cout << "DFS: " << graph.dfs(start) << "\n";
        } else {
            std::cout << "Invalid choice.\n";
        }
    }

    void logsAndUndoMenu() {
        while (true) {
            std::cout << "\n== Logs & Undo ==\n";
            std::cout << "1. View recent activity (Stack)\n";
            std::cout << "2. View full logs (Doubly Linked List traversal)\n";
            std::cout << "3. Undo last admin action\n";
            std::cout << "4. Back\n";
            std::cout << "Choice: ";

            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") {
                std::cout << "\nRecent activity (top first):\n";
                Stack<std::string> tmp;
                // show up to 10 without destroying original stack
                for (int i = 0; i < 10; ++i) {
                    std::string s;
                    if (!recentActivity.pop(s)) break;
                    std::cout << "- " << s << "\n";
                    tmp.push(s);
                }
                // restore
                while (true) {
                    std::string s;
                    if (!tmp.pop(s)) break;
                    recentActivity.push(s);
                }
            } else if (choice == "2") {
                std::cout << "\nAll logs:\n";
                logList.forEach([&](const LoginLogEntry& e) {
                    std::cout << e.ts << " | " << e.ip << " | " << e.username << " | "
                              << (e.success ? "SUCCESS" : "FAIL") << " | " << e.message << "\n";
                });
            } else if (choice == "3") {
                AdminAction act;
                if (!undoStack.pop(act)) {
                    std::cout << "Nothing to undo.\n";
                    continue;
                }

                if (act.type == AdminAction::ADD_USER) {
                    // Undo add: delete that user
                    const std::string& uname = act.userSnapshot.getUsername();
                    int* idx = usernameToIndex.get(uname);
                    if (idx) {
                        users[*idx] = users.back();
                        users.pop_back();
                        rebuildUsernameIndex();
                        recentActivity.push("UNDO | removed user " + uname);
                        std::cout << "Undo: removed user " << uname << "\n";
                    } else {
                        std::cout << "Undo warning: user already missing.\n";
                    }
                } else if (act.type == AdminAction::DELETE_USER) {
                    // Undo delete: re-add snapshot (new index)
                    users.push_back(act.userSnapshot);
                    rebuildUsernameIndex();
                    recentActivity.push("UNDO | restored user " + act.userSnapshot.getUsername());
                    std::cout << "Undo: restored user " << act.userSnapshot.getUsername() << "\n";
                }
            } else if (choice == "4") {
                return;
            } else {
                std::cout << "Invalid choice.\n";
            }
        }
    }

public:
    explicit CyberGuardApp(const std::string& dataDir)
        : files(dataDir),
          users(),
          usernameToIndex(211),
          attemptQueue(),
          logsForFile(),
          logList(),
          undoStack(),
          recentActivity(),
          ipFailedCount(211),
          threatsForFile(),
          graph(),
          edgesForFile(),
          nextUserId(1) {
        loadAll();
    }

    void run() {
        while (true) {
            std::cout << "\n==== CyberGuard (CLI) ====\n";
            std::cout << "1. User Management\n";
            std::cout << "2. Simulate Login Attempt\n";
            std::cout << "3. Process Login Queue\n";
            std::cout << "4. Threat Analysis\n";
            std::cout << "5. Analytics Reports\n";
            std::cout << "6. Attack Graph (BFS / DFS)\n";
            std::cout << "7. Logs & Undo\n";
            std::cout << "8. Save & Exit\n";
            std::cout << "9. Start Web Server (bonus)\n";
            std::cout << "Choice: ";

            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") userManagementMenu();
            else if (choice == "2") simulateLoginAttempt();
            else if (choice == "3") processLoginQueue();
            else if (choice == "4") threatAnalysis();
            else if (choice == "5") analyticsReports();
            else if (choice == "6") attackGraphMenu();
            else if (choice == "7") logsAndUndoMenu();
            else if (choice == "8") {
                saveAll();
                std::cout << "Saved. Goodbye.\n";
                return;
            } else if (choice == "9") {
                // Snapshot current state into web server.
                WebStateSnapshot st;
                st.users = users;
                st.logs = logsForFile;
                st.threats = threatsForFile;
                st.edges = edgesForFile;

                std::cout << "Starting server on http://127.0.0.1:8080/ (Ctrl+C to stop)\n";
                runHttpServer(8080, "..\\frontend", st);
            } else {
                std::cout << "Invalid choice.\n";
            }
        }
    }
};

int main() {
    CyberGuardApp app("..\\data");
    app.run();
    return 0;
}
