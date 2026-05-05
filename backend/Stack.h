#pragma once

// Stack (custom implementation)
// Used for: undo last admin action, recent activity viewer.

template <typename T>
class Stack {
private:
    struct Node {
        T data;
        Node* next;
        Node(const T& d) : data(d), next(nullptr) {}
    };

    Node* topPtr;
    int count;

public:
    Stack() : topPtr(nullptr), count(0) {}

    ~Stack() { clear(); }

    Stack(const Stack&) = delete;
    Stack& operator=(const Stack&) = delete;

    int size() const { return count; }
    bool empty() const { return topPtr == nullptr; }

    // O(1) push
    void push(const T& value) {
        Node* n = new Node(value);
        n->next = topPtr;
        topPtr = n;
        ++count;
    }

    // O(1) pop
    bool pop(T& outValue) {
        if (!topPtr) return false;
        Node* n = topPtr;
        outValue = n->data;
        topPtr = n->next;
        delete n;
        --count;
        return true;
    }

    bool peek(T& outValue) const {
        if (!topPtr) return false;
        outValue = topPtr->data;
        return true;
    }

    void clear() {
        Node* cur = topPtr;
        while (cur) {
            Node* nxt = cur->next;
            delete cur;
            cur = nxt;
        }
        topPtr = nullptr;
        count = 0;
    }
};
