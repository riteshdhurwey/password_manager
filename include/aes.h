#include<iostream>
#include<string>
#include<stdexcept>
#include<jdbc/mysql_connection.h>
#include<jdbc/mysql_driver.h>
#include<jdbc/cppconn/prepared_statement.h>
#include<jdbc/cppconn/resultset.h>
#include<jdbc/cppconn/statement.h>
#include<cryptopp/aes.h>
#include<cryptopp/modes.h>
#include<cryptopp/filters.h>
#include<cryptopp/hex.h>
#include<cryptopp/osrng.h>
#include<cryptopp/sha.h>
#include<cryptopp/cryptlib.h>
#include<cryptopp/pwdbased.h>
#include<cryptopp/base64.h>
#include<fstream>
#include<cryptopp/secblock.h>
#include<openssl/sha.h>
#include<vector>
#include<iomanip>
#include<sstream>
#include<openssl/evp.h>

// CryptoPP::SecByteBlock HexDecode(const std::string& hex);
std::string encryptAES(const std::string& plaintext, const CryptoPP::SecByteBlock& key,const std::string &iv);
std::string decryptAES(const std::string& ciphertext, const CryptoPP::SecByteBlock& key,const std::string &iv);
std::string generateRandomHex(size_t lenght);
CryptoPP::SecByteBlock deriveKeyFromPassword(const std::string &password, const CryptoPP::byte* salt, size_t saltsize,size_t keysize );
std::string sha256(const std::string& input);
CryptoPP::SecByteBlock deriveEntryKey( const CryptoPP::SecByteBlock& masterKey, const std::string& entrySalt);