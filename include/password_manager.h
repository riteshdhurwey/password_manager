#include<iostream>
#include<string>
#include"db_manager.h"
#include"aes.h"
class PasswordManager {
public:
    PasswordManager(DBManager* db);
    ~PasswordManager();

    bool registeruser(const std::string& username, const std::string& masterPassword);
    bool loginUser(const std::string& username, const std::string& masterPassword);

    void addPassword(const std::string& website, const std::string& username, const std::string& password);
    void retrievePasswords(const std::string &website);
    void UpdateInfo(const std::string &site,const std::string &username,const std::string &password);
    void deleteInfo(const std::string& website);
    void viewAllPasswords();

private:
    DBManager* db;
    int currentUserId;
    CryptoPP::SecByteBlock masterKey;
};
