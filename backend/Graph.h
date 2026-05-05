#pragma once

#include <string>
#include <vector>

#include "LinkedList.h"
#include "HashTable.h"
#include "Queue.h"
#include "Stack.h"

// Graph (Adjacency List)
// Nodes are string IDs (e.g., "IP:1.2.3.4", "U:alice")
// Edges represent login attempt relationships.
// BFS/DFS implemented using custom Queue/Stack.

class Graph {
private:
    HashTable<int> nodeToIndex;
    std::vector<std::string> indexToNode;
    std::vector< LinkedList<int> > adj;

    int ensureNode(const std::string& nodeId) {
        int* idx = nodeToIndex.get(nodeId);
        if (idx) return *idx;
        int newIndex = static_cast<int>(indexToNode.size());
        indexToNode.push_back(nodeId);
        nodeToIndex.put(nodeId, newIndex);
        adj.emplace_back();
        return newIndex;
    }

public:
    Graph() : nodeToIndex(211), indexToNode(), adj() {}

    int nodeCount() const { return static_cast<int>(indexToNode.size()); }

    void addEdge(const std::string& from, const std::string& to) {
        int u = ensureNode(from);
        int v = ensureNode(to);
        // For demo simplicity, store directed edge u->v.
        adj[u].pushFront(v);
    }

    bool hasNode(const std::string& nodeId) const {
        return nodeToIndex.get(nodeId) != nullptr;
    }

    // Traversal output as a space-separated string.
    std::string bfs(const std::string& startNode) const {
        const int* sIdxPtr = nodeToIndex.get(startNode);
        if (!sIdxPtr) return "Start node not found.";

        int n = static_cast<int>(indexToNode.size());
        std::vector<bool> visited(n, false);

        Queue<int> q;
        int s = *sIdxPtr;
        visited[s] = true;
        q.enqueue(s);

        std::string out;
        while (!q.empty()) {
            int u;
            q.dequeue(u);
            out += indexToNode[u];
            out += ' ';

            adj[u].forEach([&](const int& v) {
                if (!visited[v]) {
                    visited[v] = true;
                    q.enqueue(v);
                }
            });
        }
        return out;
    }

    std::string dfs(const std::string& startNode) const {
        const int* sIdxPtr = nodeToIndex.get(startNode);
        if (!sIdxPtr) return "Start node not found.";

        int n = static_cast<int>(indexToNode.size());
        std::vector<bool> visited(n, false);

        Stack<int> st;
        st.push(*sIdxPtr);

        std::string out;
        while (!st.empty()) {
            int u;
            st.pop(u);
            if (visited[u]) continue;
            visited[u] = true;

            out += indexToNode[u];
            out += ' ';

            // Push neighbors (traversal order is based on adjacency list insertion)
            adj[u].forEach([&](const int& v) {
                if (!visited[v]) st.push(v);
            });
        }
        return out;
    }

    void forEachEdge(void (*fn)(const std::string&, const std::string&)) const {
        for (int u = 0; u < static_cast<int>(indexToNode.size()); ++u) {
            adj[u].forEach([&](const int& v) { fn(indexToNode[u], indexToNode[v]); });
        }
    }
};
