#include <unistd.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <iostream>
#include <errno.h>
#include <time.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <iomanip>
#include <fstream>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#include <memory>
#include <cstring>
#include <ctime>

using namespace std;

// Returns vector of "SubjectName;;;###ValidUntil" entries.
vector<string> read_cert_infos(const vector<string>& certlist_array, bool ssl_check)
{
    string zeichenvorrat = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    OpenSSL_add_all_algorithms();
    OPENSSL_no_config();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    vector<string> certlist_subj_valid_until;

    for (size_t i = 0; i < certlist_array.size(); ++i) {
        int finde_semikolon = certlist_array[i].find(";;;");
        string cert_hex     = certlist_array[i].substr(0, finde_semikolon);

        int bytes   = cert_hex.size() / 3;
        int padding = cert_hex.size() % 3;
        int count   = bytes * 3;
        unsigned long long dezimal_nummer_long = 0;
        string cert_base64 = "";
        int j = 0;

        for (j = 0; j < count; j += 3) {
            char e1[2] = {cert_hex[j],   0};
            char e2[2] = {cert_hex[j+1], 0};
            char e3[2] = {cert_hex[j+2], 0};
            dezimal_nummer_long  = strtoull(e1, nullptr, 16) << 8;
            dezimal_nummer_long |= strtoull(e2, nullptr, 16) << 4;
            dezimal_nummer_long |= strtoull(e3, nullptr, 16);
            cert_base64 += zeichenvorrat[0x3F & (dezimal_nummer_long >> 6)];
            cert_base64 += zeichenvorrat[0x3F & dezimal_nummer_long];
        }

        if (padding == 1) {
            char e1[2] = {cert_hex[j], 0};
            dezimal_nummer_long = strtoull(e1, nullptr, 16) << 8;
            cert_base64 += zeichenvorrat[0x3F & (dezimal_nummer_long >> 6)];
            cert_base64 += '=';
        }
        if (padding > 1) {
            char e1[2] = {cert_hex[j],   0};
            char e2[2] = {cert_hex[j+1], 0};
            char e3[2] = {cert_hex[j+2], 0};
            dezimal_nummer_long  = strtoull(e1, nullptr, 16) << 8;
            dezimal_nummer_long |= strtoull(e2, nullptr, 16) << 4;
            dezimal_nummer_long |= strtoull(e3, nullptr, 16);
            cert_base64 += zeichenvorrat[0x3F & (dezimal_nummer_long >> 6)];
            cert_base64 += zeichenvorrat[0x3F & dezimal_nummer_long];
            cert_base64 += '=';
            cert_base64 += '=';
        }

        // Insert line breaks every 64 chars
        string wrapped;
        wrapped.reserve(cert_base64.size() + cert_base64.size() / 64 + 64);
        for (size_t k = 0; k < cert_base64.size(); k += 64) {
            wrapped += cert_base64.substr(k, 64);
            wrapped += '\n';
        }
        cert_base64 = "-----BEGIN CERTIFICATE-----\n" + wrapped + "-----END CERTIFICATE-----";

        const char* pem = cert_base64.c_str();

        BIO* bio_mem = BIO_new(BIO_s_mem());
        ERR_print_errors_fp(stderr);
        BIO_puts(bio_mem, pem);
        ERR_print_errors_fp(stderr);

        X509* x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        BIO_free(bio_mem);
        if (!x509) {
            cerr << "read_cert_infos: PEM_read_bio_X509 failed for entry " << i << endl;
            ERR_print_errors_fp(stderr);
            continue;
        }

        // Extract subject name using a memory BIO — vector<char> avoids manual new/delete
        BIO* subj_bio = BIO_new(BIO_s_mem());
        X509_NAME* subject = X509_get_subject_name(x509);
        if (!subject) {
            cerr << "read_cert_infos: X509_get_subject_name failed for entry " << i << endl;
            BIO_free(subj_bio);
            X509_free(x509);
            continue;
        }
        X509_NAME_print(subj_bio, subject, 0);

        char* dataStart = NULL;
        long nameLength = BIO_get_mem_data(subj_bio, &dataStart);
        vector<char> subjectBuf(dataStart, dataStart + nameLength);
        string subj_string(subjectBuf.begin(), subjectBuf.end());
        BIO_free(subj_bio);

        if (!ssl_check)
            cout << "\n Subject Name: " << subj_string << " ";

        // Extract expiry date
        BIO* validBio = BIO_new(BIO_s_mem());
        ASN1_TIME* valid_until = X509_get_notAfter(x509);
        if (!valid_until) {
            cerr << "read_cert_infos: X509_get_notAfter failed for entry " << i << endl;
            BIO_free(validBio);
            X509_free(x509);
            continue;
        }
        ASN1_TIME_print(validBio, valid_until);

        char* start_punkt = NULL;
        long laenge = BIO_get_mem_data(validBio, &start_punkt);
        vector<char> validBuf(start_punkt, start_punkt + laenge);
        string valid_until_string(validBuf.begin(), validBuf.end());
        BIO_free(validBio);

        if (!ssl_check)
            cout << " Gültig bis: " << valid_until_string << endl;

        certlist_subj_valid_until.push_back(subj_string + ";;;###" + valid_until_string);

        X509_free(x509);

        zeichenvorrat = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        cert_base64 = "";
    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return certlist_subj_valid_until;
}
