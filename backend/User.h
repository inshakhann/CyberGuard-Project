#pragma once

#include <string>

class User {
private:
    int id;
    std::string username;
    std::string password;
    std::string status; // e.g., "ACTIVE" / "LOCKED"

public:
    User();
    User(int id, const std::string& username, const std::string& password, const std::string& status);

    int getId() const;
    const std::string& getUsername() const;
    const std::string& getPassword() const;
    const std::string& getStatus() const;

    void setPassword(const std::string& newPassword);
    void setStatus(const std::string& newStatus);
};
