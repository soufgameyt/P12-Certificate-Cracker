#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace P12Cracker {
    const std::string Letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string Digits  = "0123456789";
    const std::string Specials= "!@#$%^&*()_+-=[]{}|;:,.<>/?";

    std::vector<unsigned char> P12Buffer;
    std::string Charset;
    bool Found = false;
    int MaxLength = 10;

    bool FileExists(const std::string &path) {
        struct stat st;
        return stat(path.c_str(), &st) == 0;
    }

    bool LoadP12File(const std::string &path) {
        struct stat st;
        if (stat(path.c_str(), &st) != 0) return false;
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        P12Buffer.resize(st.st_size);
        f.read(reinterpret_cast<char*>(P12Buffer.data()), st.st_size);
        return f.good();
    }

    bool TryPassword(const std::string &password) {
        const unsigned char *p = P12Buffer.data();
        PKCS12 *p12 = d2i_PKCS12(NULL, &p, static_cast<long>(P12Buffer.size()));
        if (!p12) return false;
        EVP_PKEY *pkey = nullptr;
        X509 *cert = nullptr;
        STACK_OF(X509) *ca = nullptr;
        int ok = PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca);
        if (ok == 1) {
            if (pkey) EVP_PKEY_free(pkey);
            if (cert) X509_free(cert);
            if (ca) sk_X509_pop_free(ca, X509_free);
            PKCS12_free(p12);
            return true;
        }
        PKCS12_free(p12);
        return false;
    }

    void GenerateRecursive(std::string &buf, int pos, int maxPos) {
        if (Found) return;
        if (pos == maxPos) {
            std::cout << buf << '\n' << std::flush;
            if (TryPassword(buf)) {
                std::cout << "\nPasswordFound: " << buf << '\n';
                Found = true;
            }
            return;
        }
        for (size_t i = 0; i < Charset.size() && !Found; ++i) {
            buf[pos] = Charset[i];
            GenerateRecursive(buf, pos + 1, maxPos);
        }
    }

    void Start() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        Charset = Letters + Digits + Specials;

        std::string path;
        std::cout << "Enter path to .p12: ";
        std::getline(std::cin, path);
        while (!FileExists(path)) {
            std::cout << "Invalid path. Enter path to .p12: ";
            std::getline(std::cin, path);
        }

        std::cout << "Max password length (1-25, default " << MaxLength << "): ";
        std::string line;
        std::getline(std::cin, line);
        if (!line.empty()) {
            int v = std::stoi(line);
            if (v >= 1 && v <= 25) MaxLength = v;
        }

        if (!LoadP12File(path)) {
            std::cerr << "Failed to load file\n";
            return;
        }

        for (int len = 1; len <= MaxLength && !Found; ++len) {
            std::string buf(len, '\0');
            GenerateRecursive(buf, 0, len);
        }

        EVP_cleanup();
        ERR_free_strings();
    }
}

int main() {
    P12Cracker::Start();
    return 0;
}
