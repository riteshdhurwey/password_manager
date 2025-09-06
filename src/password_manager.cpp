#include"password_manager.h"

PasswordManager::PasswordManager(DBManager* db) {
    this->db = db;
    this->currentUserId = -1;
    this->masterKey ;
}
PasswordManager::~PasswordManager() {
   
}
bool PasswordManager::registeruser(const std::string& username, const std::string& masterPassword){
    
    std::string saltHex = generateRandomHex(16);
    CryptoPP::byte saltBytes[16];

    CryptoPP::StringSource(saltHex,true,
    new CryptoPP::HexDecoder(
    new CryptoPP::ArraySink(saltBytes,16)
    ));

    CryptoPP::SecByteBlock masterKey = deriveKeyFromPassword(masterPassword,saltBytes,16,32);

    // The sha256 function can't accept SecByteBlock Key so need to convert it into string 
    std::string keyStr(reinterpret_cast<const char*>(masterKey.data()),masterKey.size());

    //Now use the string to Generate Hash of Key
    std::string masterPassword_hash = sha256(keyStr);

    //f

    return db->registerUser(username,masterPassword_hash,saltHex);

   }

bool PasswordManager::loginUser(const std::string& username, const std::string& masterPassword){
    UserRecord user = db->getUser(username);
    CryptoPP::byte saltByte[16]; 
    std::string salt =user.salt;  
    CryptoPP::StringSource(salt,true,
    new CryptoPP::HexDecoder(new CryptoPP::ArraySink(saltByte,16)));
    CryptoPP::SecByteBlock key = deriveKeyFromPassword(masterPassword,saltByte,16,32);

    std::string keyStr(reinterpret_cast<const char*>(key.data()),key.size());
    std::string hash = sha256(keyStr);

    if (hash == user.passwordHash) {
        currentUserId = user.id;  
        masterKey = deriveKeyFromPassword (masterPassword, saltByte,16,32); // derive AES key for encryption/decryption
        return true;
    }
    return false;
}

void PasswordManager::addPassword(const std::string& website, const std::string& username, const std::string& password){
    std::string ivHex = generateRandomHex(16);
    std::string saltHex = generateRandomHex(16);

    CryptoPP::SecByteBlock entrykey = deriveEntryKey(masterKey,saltHex);
    std::string websiteEnc = encryptAES(website,entrykey,ivHex);
    std::string usernameEnc = encryptAES(username,entrykey,ivHex);
    std::string passwordEnc = encryptAES(password,entrykey,ivHex);
    std::string websiteHash = sha256(website);

    bool done = db->storePassword(currentUserId,websiteEnc,websiteHash,usernameEnc,passwordEnc,saltHex,ivHex);
    if(!done){
        std::cout<<"Details not saved!"<<std::endl;
    }else{
        std::cout<<"Details Saved!"<<std::endl;
    }

}

void PasswordManager::retrievePasswords(const std::string &website){
   PasswordRecord record = db->getPassword(currentUserId,website);
    if(record.id==0){
        std::cout<<"No record found for "<<website<<std::endl;
        //return;
    }else{
        
        CryptoPP::SecByteBlock entrykey = deriveEntryKey(masterKey,record.salt);
        std::string username = decryptAES(record.username,entrykey,record.iv);
        std::string password = decryptAES(record.encryptedPassword,entrykey,record.iv);
        std::cout<<"Website Name :"<<website<<std::endl;
        std::cout<<"Username :"<<username<<std::endl;
        std::cout<<"Password :"<<password<<std::endl;
    }  
}

void PasswordManager::UpdateInfo(const std::string &site,const std::string &username,const std::string &password){

    std::string ivHex = generateRandomHex(16);
    std::string saltHex = generateRandomHex(16);

    CryptoPP::SecByteBlock entrykey = deriveEntryKey(masterKey,saltHex);

    std::string websiteEnc = encryptAES(site,entrykey,ivHex);
    std::string usernameEnc = encryptAES(username,entrykey,ivHex);
    std::string passwordEnc = encryptAES(password,entrykey,ivHex);
    std::string websiteHash = sha256(site);

    bool done = db->UpdateInfo(currentUserId,websiteEnc,websiteHash,usernameEnc,passwordEnc,ivHex,saltHex);
    if(done==true){
        std::cout<<"Record updated!"<<std::endl;
    }else{
        std::cout<<"Record Not Updated!"<<std::endl;
    }
}

void PasswordManager::deleteInfo(const std::string &website){
    std::string website_hash = sha256(website);
    bool done = db->deleteInfo(currentUserId,website_hash);
    if(done==true){
        std::cout<<"Record Deleted."<<std::endl;
    }else{
        std::cout<<"Error while Deleting Record."<<std::endl;
    }
}

void PasswordManager::viewAllPasswords(){
    std::vector<PasswordRecord>records = db->viewAll(currentUserId);
    for(const auto &rec :records){
        std::string saltHex = rec.salt;
        CryptoPP::SecByteBlock entrykey = deriveEntryKey(masterKey,saltHex);
    
        std::string website = decryptAES(rec.website,entrykey,rec.iv);
        std::string username = decryptAES(rec.username,entrykey,rec.iv);
        std::string password = decryptAES(rec.encryptedPassword,entrykey,rec.iv);
        std::cout<<"Website :"<<website<<std::endl;
        std::cout<<"Username :"<<username<<std::endl;
        std::cout<<"password :"<<password<<std::endl;
        std::cout<<"----------------------------------------------------"<<std::endl;
    }
}