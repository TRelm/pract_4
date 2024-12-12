#include <cryptlib.h>
#include <rijndael.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <files.h>
#include <hex.h>
#include <base64.h>
#include <iostream>
#include <fstream>
#include <string>

using namespace CryptoPP;

void saveIV(const std::string& file, const SecByteBlock& iv) {
    std::ofstream ivFile(file, std::ios::binary);
    if (!ivFile) {
        throw std::runtime_error("Не удалось открыть файл для записи IV");
    }
    ivFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    ivFile.close();
}

void loadIV(const std::string& file, SecByteBlock& iv) {
    std::ifstream ivFile(file, std::ios::binary);
    if (!ivFile) {
        throw std::runtime_error("Не удалось открыть файл для чтения IV");
    }
    ivFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
    ivFile.close();
}

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password, const std::string& ivFile) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    SHA256 hash;
    StringSource(password, true, new HashFilter(hash, new ArraySink(key, key.size())));

    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, iv.size());

    saveIV(ivFile, iv);

    CBC_Mode<AES>::Encryption cbcEncryption(key, key.size(), iv);

    // Шифрование и сохранение с кодированием Base64
    std::string cipherText;
    FileSource(inputFile.c_str(), true,
        new StreamTransformationFilter(cbcEncryption,
            new StringSink(cipherText)));

    // Кодирование зашифрованного текста в Base64
    std::string encodedText;
    StringSource(cipherText, true,
        new Base64Encoder(new StringSink(encodedText)));

    // Сохраняем зашифрованный текст в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Не удалось открыть файл для записи зашифрованного текста");
    }
    outFile << encodedText;
    outFile.close();

    std::cout << "Файл зашифрован: " << outputFile << std::endl;
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password, const std::string& ivFile) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    // Генерация ключа на основе пароля
    SHA256 hash;
    StringSource(password, true, new HashFilter(hash, new ArraySink(key, key.size())));

    // Чтение IV из файла
    loadIV(ivFile, iv);

    // Чтение зашифрованных данных из файла и декодирование из Base64
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Не удалось открыть файл для чтения зашифрованного текста");
    }
    std::string encodedText((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    std::string cipherText;
    StringSource(encodedText, true,
        new Base64Decoder(new StringSink(cipherText)));

    // Расшифровка данных и сохранение результата в файл
    CBC_Mode<AES>::Decryption cbcDecryption(key, key.size(), iv);
    StringSource(cipherText, true,
        new StreamTransformationFilter(cbcDecryption,
            new FileSink(outputFile.c_str())));

    std::cout << "Файл расшифрован: " << outputFile << std::endl;
}

int main() {
    std::string password = "test_password";
    std::string inputFile = "input.txt";
    std::string encryptedFile = "encrypted.txt";
    std::string decryptedFile = "decrypted.txt";
    std::string ivFile = "iv.bin";

    try {
        encryptFile(inputFile, encryptedFile, password, ivFile);
        decryptFile(encryptedFile, decryptedFile, password, ivFile);

        std::cout << "Проверка завершена. Исходный и расшифрованный файлы должны совпадать." << std::endl;
    } catch (const Exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }

    return 0;
}

