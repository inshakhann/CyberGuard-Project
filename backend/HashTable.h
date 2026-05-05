#pragma once

#include <string>
#include <vector>
#include "LinkedList.h"

// Hash Table (custom implementation, chaining)
// Used for: User lookup by username, IP/user counters (analytics), node-to-index mapping.
// Average time: insert/search/delete ~ O(1), worst-case O(n) if many collisions.

template <typename V>
class HashTable {
private:
    struct Entry {
        std::string key;
        V value;
        Entry() : key(""), value() {}
        Entry(const std::string& k, const V& v) : key(k), value(v) {}
    };

    std::vector< LinkedList<Entry> > buckets;
    int itemCount;

    unsigned long hashKey(const std::string& key) const {
        // Simple polynomial rolling hash
        unsigned long h = 0;
        for (char c : key) {
            h = (h * 131UL) + static_cast<unsigned long>(static_cast<unsigned char>(c));
        }
        return h;
    }

    int bucketIndex(const std::string& key) const {
        return static_cast<int>(hashKey(key) % buckets.size());
    }

public:
    explicit HashTable(int bucketCount = 101) : buckets(bucketCount), itemCount(0) {}

    int size() const { return itemCount; }

    // Insert or update
    void put(const std::string& key, const V& value) {
        int idx = bucketIndex(key);
        auto* existing = buckets[idx].findIf([&](const Entry& e) { return e.key == key; });
        if (existing) {
            existing->value = value;
            return;
        }
        buckets[idx].pushFront(Entry(key, value));
        ++itemCount;
    }

    // Returns pointer for in-place edits, nullptr if not found
    V* get(const std::string& key) {
        int idx = bucketIndex(key);
        auto* e = buckets[idx].findIf([&](const Entry& entry) { return entry.key == key; });
        if (!e) return nullptr;
        return &e->value;
    }

    const V* get(const std::string& key) const {
        int idx = bucketIndex(key);
        auto* e = buckets[idx].findIf([&](const Entry& entry) { return entry.key == key; });
        if (!e) return nullptr;
        return &e->value;
    }

    bool remove(const std::string& key) {
        int idx = bucketIndex(key);
        bool removed = buckets[idx].removeIf([&](const Entry& entry) { return entry.key == key; });
        if (removed) --itemCount;
        return removed;
    }

    // Traversal over all entries
    template <typename Fn>
    void forEach(Fn fn) const {
        for (const auto& bucket : buckets) {
            bucket.forEach([&](const Entry& e) { fn(e.key, e.value); });
        }
    }
};
