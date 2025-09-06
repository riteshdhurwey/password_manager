#include "db_manager.h"
#include"aes.h"

DBManager::DBManager(const std::string& configFile) : conn(nullptr) {
    std::ifstream file(configFile);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open DB config file: " + configFile);
    }

    json j;
    file >> j;

    db   = j["db_name"].get<std::string>();
    user = j["db_user"].get<std::string>();
    pass = j["db_password"].get<std::string>();
    host = j["db_host"].get<std::string>();
    connect();
}

DBManager::~DBManager(){
    if(conn) delete conn;
}

bool DBManager::connect() {
    try {
        sql::Driver *driver = get_driver_instance();
        
        // host must be in "tcp://ip:port" format
       std::string fullHost = "tcp://" + host + ":3306";  

        conn = driver->connect(fullHost,user,pass);

        if (!conn) {
            return false;
        }

        conn->setSchema(db);
        return true;

    } catch (sql::SQLException &e) {
        std::cerr << "DB Connection failed: " << e.what() 
                  << " (MySQL error code: " << e.getErrorCode()
                  << ", SQLState: " << e.getSQLState() << ")" 
                  << std::endl;
        return false;
    }
}


bool DBManager::registerUser(const std::string& username, const std::string& masterPassword_hash, const std::string& salt){
    if (!conn) {
        std::cerr << "ERROR: Connection is NULL\n";
        return false;
    }

    try{
    sql::PreparedStatement *pstmt = conn->prepareStatement("INSERT INTO users(username,salt,password_hash) VALUES(?,?,?)");
    pstmt->setString(1,username);
    pstmt->setString(2,salt);
    pstmt->setString(3,masterPassword_hash);
    pstmt->executeQuery();
    delete pstmt;
    return true;
    }catch(sql::SQLException &e){
        std::cerr<<"Error in mysql :"<<e.what()<<std::endl;
        return false;
    }
    

}

UserRecord DBManager::getUser(const std::string& username) {
    UserRecord user{};
    try{
    std::string query = "SELECT id, username, password_hash, salt FROM users WHERE username = ?";
    
    sql::PreparedStatement *pstmt = conn->prepareStatement(query);
    pstmt->setString(1, username);
    sql::ResultSet * res=pstmt->executeQuery();

    if (res->next()) {
        user.id = res->getInt("id");
        user.username = res->getString("username");
        user.passwordHash = res->getString("password_hash");
        user.salt = res->getString("salt");
    }
    delete res;
    delete pstmt;
}catch(sql::SQLException &e){
    std::cerr<<"sql error "<<e.what()<<std::endl;
}
    return user;
}

PasswordRecord DBManager::getPassword(int userId, const std::string& website) {
    PasswordRecord record;
    std::string website_hash = sha256(website);
    std::string query = "SELECT id, website, username, password, salt, iv "
                        "FROM passwords WHERE user_id = ? AND website_hash = ?";

    sql::PreparedStatement *pstmt = conn->prepareStatement(query);
    pstmt->setInt(1, userId);
    pstmt->setString(2, website_hash);

    sql::ResultSet *res = pstmt->executeQuery();
    if (res->next()) {
        record.id = res->getInt("id");
        record.website = res->getString("website");
        record.username = res->getString("username");
        record.encryptedPassword = res->getString("password");
        record.salt = res->getString("salt");
        record.iv = res->getString("iv");
    }
    return record; // if not found, fields will be empty
}

bool DBManager::storePassword(int userId, const std::string& site,const std::string &website_hash,const std::string &username, const std::string& encryptedPassword,const std::string& iv, const std::string& salt){
   try{
    sql::PreparedStatement *pstmt = conn->prepareStatement("INSERT INTO passwords(user_id,website,website_hash,username,password,salt,iv) VALUES(?,?,?,?,?,?,?)");
    pstmt->setInt(1,userId);
    pstmt->setString(2,site);
    pstmt->setString(3,website_hash);
    pstmt->setString(4,username);
    pstmt->setString(5,encryptedPassword);
    pstmt->setString(6,salt);
    pstmt->setString(7,iv);
    pstmt->executeQuery();
    delete pstmt;
    return true;
   }catch(sql::SQLException &e){
    std::cerr<<"error in sql "<<e.what()<<std::endl;
    return false;
   }
}

bool DBManager::UpdateInfo(int userId, const std::string& site,const std::string &website_hash,const std::string &username,const std::string& encryptedPassword,const std::string& iv, const std::string& salt){
    try{
        sql::PreparedStatement *pstmt = conn->prepareStatement("UPDATE passwords SET username = ?, SET password = ?, SET salt = ?, SET iv = ? WHERE user_id = ? AND website_hash = ?");
        pstmt->setString(1,username);
        pstmt->setString(2,encryptedPassword);
        pstmt->setString(3,salt);
        pstmt->setString(4,iv);
        pstmt->setInt(5,userId);
        pstmt->setString(6,website_hash);
        int rows = pstmt->executeUpdate();
        delete pstmt;
        if(rows!=0){
            return true;
        }
        std::cerr<<"error in sql"<<std::endl;
            return false;
    }catch(sql::SQLException &e){
        std::cerr<<"sql error"<<e.what()<<std::endl;
        return false;
    }
    
}

bool DBManager::deleteInfo(int userId,const std::string &website_hash){
    try{
        sql::PreparedStatement *pstmt = conn->prepareStatement("DELETE FROM passwords WHERE user_id = ? AND website_hash = ?");
        pstmt->setInt(1,userId);
        pstmt->setString(2,website_hash);
        int QueryAffected =pstmt->executeUpdate();
        delete pstmt;
        if(QueryAffected!=0){
            return true;
        }else{
            return false;
        }
    }catch(sql::SQLException &e){
        std::cerr<<"sql error"<<e.what()<<std::endl;
        return false;
    }
}

std::vector<PasswordRecord> DBManager::viewAll (int userId){
        sql::PreparedStatement *pstmt = conn->prepareStatement("SELECT website,username,password,salt,iv FROM passwords WHERE user_id = ?");
        pstmt->setInt(1,userId);
        sql::ResultSet *res = pstmt->executeQuery();
        while(res->next()){
            PasswordRecord record ;
            record.username = res->getString("username");
            record.website = res->getString("website");
            record.encryptedPassword = res->getString("password");
            record.iv = res->getString("iv");
            record.salt = res->getString("salt");
            records.push_back(record);
        }
        delete pstmt;
        delete res;
        return records;
    
}
