#pragma once

// Singly Linked List (custom implementation)
// Used for: user traversal, hash table chaining buckets, general traversal demos.
// Operations: insert, delete, search, traversal.

template <typename T>
class LinkedList {
private:
    struct Node {
        T data;
        Node* next;
        Node(const T& d) : data(d), next(nullptr) {}
    };

    Node* head;
    int count;

public:
    LinkedList() : head(nullptr), count(0) {}

    ~LinkedList() { clear(); }

    LinkedList(const LinkedList&) = delete;
    LinkedList& operator=(const LinkedList&) = delete;

    // Move support (required because we store LinkedList inside std::vector)
    LinkedList(LinkedList&& other) noexcept : head(other.head), count(other.count) {
        other.head = nullptr;
        other.count = 0;
    }

    LinkedList& operator=(LinkedList&& other) noexcept {
        if (this == &other) return *this;
        clear();
        head = other.head;
        count = other.count;
        other.head = nullptr;
        other.count = 0;
        return *this;
    }

    int size() const { return count; }
    bool empty() const { return head == nullptr; }

    // O(1) insert at front
    void pushFront(const T& value) {
        Node* n = new Node(value);
        n->next = head;
        head = n;
        ++count;
    }

    // O(n) search (returns pointer for in-place modification)
    template <typename Pred>
    T* findIf(Pred pred) {
        Node* cur = head;
        while (cur) {
            if (pred(cur->data)) return &cur->data;
            cur = cur->next;
        }
        return nullptr;
    }

    template <typename Pred>
    const T* findIf(Pred pred) const {
        const Node* cur = head;
        while (cur) {
            if (pred(cur->data)) return &cur->data;
            cur = cur->next;
        }
        return nullptr;
    }

    // O(n) delete first matching node
    template <typename Pred>
    bool removeIf(Pred pred) {
        Node* cur = head;
        Node* prev = nullptr;
        while (cur) {
            if (pred(cur->data)) {
                if (prev) prev->next = cur->next;
                else head = cur->next;
                delete cur;
                --count;
                return true;
            }
            prev = cur;
            cur = cur->next;
        }
        return false;
    }

    // O(n) traversal
    template <typename Fn>
    void forEach(Fn fn) const {
        const Node* cur = head;
        while (cur) {
            fn(cur->data);
            cur = cur->next;
        }
    }

    void clear() {
        Node* cur = head;
        while (cur) {
            Node* nxt = cur->next;
            delete cur;
            cur = nxt;
        }
        head = nullptr;
        count = 0;
    }
};
