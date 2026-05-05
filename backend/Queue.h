#pragma once

// Queue (custom implementation)
// Used for: processing login attempts in FIFO order.

template <typename T>
class Queue {
private:
    struct Node {
        T data;
        Node* next;
        Node(const T& d) : data(d), next(nullptr) {}
    };

    Node* frontPtr;
    Node* backPtr;
    int count;

public:
    Queue() : frontPtr(nullptr), backPtr(nullptr), count(0) {}

    ~Queue() { clear(); }

    Queue(const Queue&) = delete;
    Queue& operator=(const Queue&) = delete;

    int size() const { return count; }
    bool empty() const { return frontPtr == nullptr; }

    // O(1) enqueue
    void enqueue(const T& value) {
        Node* n = new Node(value);
        if (!backPtr) {
            frontPtr = backPtr = n;
        } else {
            backPtr->next = n;
            backPtr = n;
        }
        ++count;
    }

    // O(1) dequeue
    bool dequeue(T& outValue) {
        if (!frontPtr) return false;
        Node* n = frontPtr;
        outValue = n->data;
        frontPtr = n->next;
        if (!frontPtr) backPtr = nullptr;
        delete n;
        --count;
        return true;
    }

    void clear() {
        Node* cur = frontPtr;
        while (cur) {
            Node* nxt = cur->next;
            delete cur;
            cur = nxt;
        }
        frontPtr = backPtr = nullptr;
        count = 0;
    }
};
