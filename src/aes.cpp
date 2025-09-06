#include<aes.h>

//Generates random 16 Bytes Iv and Salt
std::string generateRandomHex(size_t length) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock randomBytes(length);
    prng.GenerateBlock(randomBytes, randomBytes.size());

    std::string hex;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex));
    encoder.Put(randomBytes, randomBytes.size());
    encoder.MessageEnd();

    return hex;
}
// CryptoPP::byte HexDecode(const std::string& hex) {
//    CryptoPP::byte saltBytes[16];
//     CryptoPP::StringSource(hex, true,
//         new CryptoPP::HexDecoder(new CryptoPP::ArraySink(saltBytes, sizeof(saltBytes))) );
//     return saltBytes;
//     }

CryptoPP::SecByteBlock deriveKeyFromPassword(const std::string &password, const CryptoPP::byte* salt, size_t saltsize,size_t keysize){
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    CryptoPP::SecByteBlock key(keysize);
    pbkdf2.DeriveKey(key.data(), key.size(), 0, (const CryptoPP::byte*)password.data(), password.size(), salt, saltsize, 10000);
    return key;
}


std::string encryptAES(const std::string& plaintext,const CryptoPP::SecByteBlock &key,const std::string &iv){

    //Decoding the string Iv into Bytes
    CryptoPP::byte ivBytes[16];
    CryptoPP::StringSource(iv,true,
    new CryptoPP::HexDecoder(new CryptoPP::ArraySink(ivBytes,16)));

    std::string CipherText;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption Encryptor;
    Encryptor.SetKeyWithIV(key, key.size(),ivBytes);

    CryptoPP::StringSource(plaintext,true,
    new CryptoPP::StreamTransformationFilter(Encryptor,
    new CryptoPP::StringSink(CipherText)));

    return CipherText;
}

std::string decryptAES(const std::string &cipherText,
                       const CryptoPP::SecByteBlock &key,
                       const std::string &iv) {
                        CryptoPP::byte ivBytes[16];
    CryptoPP::StringSource(iv,true,
    new CryptoPP::HexDecoder(new CryptoPP::ArraySink(ivBytes,16)));
    try {
std::string plaintext;

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key,key.size(),ivBytes);

    CryptoPP::StringSource(cipherText,true,
    new CryptoPP::StreamTransformationFilter(decryptor,
    new CryptoPP::StringSink(plaintext)));

    return plaintext;
    } catch (const CryptoPP::Exception &e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        return "";
    }
}



std::string sha256(const std::string &input) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < length; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return ss.str();
}

CryptoPP::SecByteBlock deriveEntryKey(
    const CryptoPP::SecByteBlock& masterKey,
    const std::string& entrySalt)

{

    CryptoPP::byte saltBytes[16];
    CryptoPP::StringSource(entrySalt,true,
    new CryptoPP::HexDecoder(new CryptoPP::ArraySink(saltBytes,16)));
    CryptoPP::SecByteBlock entryKey(32); // AES-256

    // CryptoPP::SecByteBlock key(32); // 256-bit AES key
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(
        entryKey, entryKey.size(),
        0,
        (CryptoPP::byte*)masterKey.data(), masterKey.size(),
        saltBytes, sizeof(saltBytes),
        100000 // iterations
    );

    return entryKey;
}