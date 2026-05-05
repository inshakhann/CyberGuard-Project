#pragma once

#include <vector>

// Max Heap (custom implementation)
// Used for: threat severity ranking, top attacking IPs.
// Operations: push/pop are O(log n), peek is O(1).

template <typename T>
class MaxHeap {
private:
    std::vector<T> arr;

    int parent(int i) const { return (i - 1) / 2; }
    int left(int i) const { return (2 * i) + 1; }
    int right(int i) const { return (2 * i) + 2; }

    void siftUp(int i) {
        while (i > 0 && arr[parent(i)] < arr[i]) {
            T tmp = arr[parent(i)];
            arr[parent(i)] = arr[i];
            arr[i] = tmp;
            i = parent(i);
        }
    }

    void siftDown(int i) {
        int n = static_cast<int>(arr.size());
        while (true) {
            int l = left(i);
            int r = right(i);
            int best = i;
            if (l < n && arr[best] < arr[l]) best = l;
            if (r < n && arr[best] < arr[r]) best = r;
            if (best == i) break;
            T tmp = arr[i];
            arr[i] = arr[best];
            arr[best] = tmp;
            i = best;
        }
    }

public:
    MaxHeap() : arr() {}

    int size() const { return static_cast<int>(arr.size()); }
    bool empty() const { return arr.empty(); }

    void push(const T& value) {
        arr.push_back(value);
        siftUp(static_cast<int>(arr.size()) - 1);
    }

    bool peek(T& outValue) const {
        if (arr.empty()) return false;
        outValue = arr[0];
        return true;
    }

    bool pop(T& outValue) {
        if (arr.empty()) return false;
        outValue = arr[0];
        arr[0] = arr.back();
        arr.pop_back();
        if (!arr.empty()) siftDown(0);
        return true;
    }

    void clear() { arr.clear(); }
};
