#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <cstdlib>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

using namespace std;

// Returns vector of "SubjectName;;;###ValidUntil" entries.
// certlist_array entries are "hex_DER;;;CONTEXT;;;APPLIC" where hex_DER is the
// raw DER certificate encoded as uppercase hex (2 chars per byte).
vector<string> read_cert_infos(const vector<string>& certlist_array, bool ssl_check)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    vector<string> certlist_subj_valid_until;

    for (size_t i = 0; i < certlist_array.size(); ++i) {
        size_t sep = certlist_array[i].find(";;;");
        string cert_hex = certlist_array[i].substr(0, sep);

        if (cert_hex.empty() || cert_hex.size() % 2 != 0)
            continue;

        // Decode hex string to raw DER bytes
        vector<unsigned char> der;
        der.reserve(cert_hex.size() / 2);
        for (size_t k = 0; k + 1 < cert_hex.size(); k += 2) {
            char buf[3] = { cert_hex[k], cert_hex[k+1], '\0' };
            der.push_back(static_cast<unsigned char>(strtoul(buf, nullptr, 16)));
        }

        // Parse DER directly — no PEM conversion needed
        const unsigned char* p = der.data();
        X509* x509 = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
        if (!x509)
            continue;

        // Extract subject name
        BIO* subj_bio = BIO_new(BIO_s_mem());
        X509_NAME* subject = X509_get_subject_name(x509);
        if (!subject) {
            BIO_free(subj_bio);
            X509_free(x509);
            continue;
        }
        X509_NAME_print(subj_bio, subject, 0);

        char* data = nullptr;
        long  len  = BIO_get_mem_data(subj_bio, &data);
        string subj_string(data, len);
        BIO_free(subj_bio);

        if (!ssl_check)
            cout << "\n Subject: " << subj_string << " ";

        // Extract expiry date
        BIO* exp_bio = BIO_new(BIO_s_mem());
        const ASN1_TIME* not_after = X509_get0_notAfter(x509);
        if (!not_after) {
            BIO_free(exp_bio);
            X509_free(x509);
            continue;
        }
        ASN1_TIME_print(exp_bio, not_after);

        char* exp_data = nullptr;
        long  exp_len  = BIO_get_mem_data(exp_bio, &exp_data);
        string expiry(exp_data, exp_len);
        BIO_free(exp_bio);

        if (!ssl_check)
            cout << " Expires: " << expiry << "\n";

        certlist_subj_valid_until.push_back(subj_string + ";;;###" + expiry);

        X509_free(x509);
    }

    EVP_cleanup();
    ERR_free_strings();

    return certlist_subj_valid_until;
}
