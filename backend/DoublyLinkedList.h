#pragma once

// Doubly Linked List (custom implementation)
// Used for: activity logs (append + traversal).

template <typename T>
class DoublyLinkedList {
private:
    struct Node {
        T data;
        Node* prev;
        Node* next;
        Node(const T& d) : data(d), prev(nullptr), next(nullptr) {}
    };

    Node* head;
    Node* tail;
    int count;

public:
    DoublyLinkedList() : head(nullptr), tail(nullptr), count(0) {}

    ~DoublyLinkedList() { clear(); }

    DoublyLinkedList(const DoublyLinkedList&) = delete;
    DoublyLinkedList& operator=(const DoublyLinkedList&) = delete;

    int size() const { return count; }
    bool empty() const { return head == nullptr; }

    // O(1) append to tail
    void pushBack(const T& value) {
        Node* n = new Node(value);
        if (!tail) {
            head = tail = n;
        } else {
            tail->next = n;
            n->prev = tail;
            tail = n;
        }
        ++count;
    }

    // O(1) remove from tail
    bool popBack(T& outValue) {
        if (!tail) return false;
        Node* n = tail;
        outValue = n->data;
        tail = n->prev;
        if (tail) tail->next = nullptr;
        else head = nullptr;
        delete n;
        --count;
        return true;
    }

    // O(n) traversal
    template <typename Fn>
    void forEach(Fn fn) const {
        Node* cur = head;
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
        head = tail = nullptr;
        count = 0;
    }
};
