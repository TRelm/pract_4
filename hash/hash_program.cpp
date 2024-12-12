#include <iostream>
#include <fstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

void hashFile(const std::string& filename) {
    try {
        // Буфер для хэша
        CryptoPP::SHA256 hash;
        std::string digest;

        // Чтение файла и хэширование
        CryptoPP::FileSource(
            filename.c_str(),
            true,
            new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest))
        );

        // Преобразование хэша в строку
        CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
        CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));

        std::cout << std::endl;
    } catch (const CryptoPP::Exception &e) {
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Standard error: " << e.what() << std::endl;
    }
}


int main() {
    std::string filename;
    std::cout << "Введите имя файла: ";
    std::cin >> filename;

    hashFile(filename);
    return 0;
}

