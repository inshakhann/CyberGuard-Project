#include "User.h"

User::User() : id(0), username(""), password(""), status("ACTIVE") {}

User::User(int id, const std::string& username, const std::string& password, const std::string& status)
    : id(id), username(username), password(password), status(status) {}

int User::getId() const { return id; }
const std::string& User::getUsername() const { return username; }
const std::string& User::getPassword() const { return password; }
const std::string& User::getStatus() const { return status; }

void User::setPassword(const std::string& newPassword) { password = newPassword; }
void User::setStatus(const std::string& newStatus) { status = newStatus; }
