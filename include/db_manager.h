// include/db_manager.h
#pragma once
#include"json.hpp"
#include"aes.h"
#include <string>
#include<memory>

using json = nlohmann::json;

// struct DBConfig {
//     std::string db_name;
//     std::string user;
//     std::string password;
//     std::string host;
//     int port;
// };

struct UserRecord {
    int id;                     // user ID from DB
    std::string username;       // just for reference
    std::string passwordHash;   // stored hash from DB
    std::string salt;           // stored salt (base64 or hex encoded)
    };

struct PasswordRecord {
    int id;
    std::string website;
    std::string username;
    std::string encryptedPassword;
    std::string salt;
    std::string iv;
};



class DBManager {
public:
    
    UserRecord getUser(const std::string &username);
    PasswordRecord getPassword(int userId, const std::string& website);
    DBManager(const std::string& configFile = "db_config.json");
    ~DBManager();
   // DBConfig loadDBConfig(const std::string& filename);

    bool connect();
    bool registerUser(const std::string& username, const std::string& masterPassword_hash, const std::string& salt);
    bool storePassword(int userId, const std::string& site,const std::string &website_hash,const std::string &username,const std::string& encryptedPassword,const std::string& iv, const std::string& salt);
    bool UpdateInfo(int userId, const std::string& site,const std::string &website_hash,const std::string &username,const std::string& encryptedPassword,const std::string& iv, const std::string& salt);
    bool deleteInfo(int userId,const std::string &website_hash); 
    std::vector<PasswordRecord>viewAll (int userId);
    std::vector<PasswordRecord>records;
    //PasswordRecord retrievePassword(int userId, const std::string& site);
    // bool authenticateUser(const std::string& username, const std::string& masterHash);

private:
    sql::Connection* conn;
    std::string host, user, pass, db;
};
