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
#include <curl/curl.h>
#include "sap_utils.h"

using namespace std;

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userdata)
{
    ((string*)userdata)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Returns the raw HTTP response body.
string web_srv(const CliParams& p, const string& soap_xml)
{
    string http_response;
    string sysnr2 = p.sysnr.size() < 2 ? "0" + p.sysnr : p.sysnr;

    if (p.http_proto != "http" && p.http_proto != "https") {
        cerr << "web_srv: unknown protocol '" << p.http_proto << "'" << endl;
        return {};
    }

    CURL *curl = curl_easy_init();
    struct curl_slist *header = NULL;
    header = curl_slist_append(header, "Content-Type: text/xml;charset=UTF-8");

    char curl_errbuf[CURL_ERROR_SIZE];

    if (p.http_proto == "http") {
        string url = "http://" + p.hostname + ":5" + sysnr2 + "13/?wdsl";
        curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER,   curl_errbuf);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);
        curl_easy_setopt(curl, CURLOPT_USERNAME,      p.username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD,      p.password.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    soap_xml.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    header);
        curl_easy_setopt(curl, CURLOPT_POST,          1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &http_response);

        CURLcode rc = curl_easy_perform(curl);
        if (rc != CURLE_OK) {
            cout << "Error: " << curl_easy_strerror(rc) << endl;
            curl_easy_cleanup(curl);
            curl_slist_free_all(header);
            exit(1);
        }
    }

    if (p.http_proto == "https") {
        string url = "https://" + p.hostname + ":5" + sysnr2 + "14/?wdsl";
        curl_easy_setopt(curl, CURLOPT_URL,             url.c_str());
        // SSL verification disabled only when -insecure is explicitly passed
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  p.insecure ? 0L : 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  p.insecure ? 0L : 2L);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER,     curl_errbuf);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,         10L);
        curl_easy_setopt(curl, CURLOPT_USERNAME,        p.username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD,        p.password.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,      soap_xml.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      header);
        curl_easy_setopt(curl, CURLOPT_POST,            1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &http_response);

        CURLcode rc = curl_easy_perform(curl);
        if (rc != CURLE_OK) {
            cout << "Error: " << curl_easy_strerror(rc) << endl;
            curl_easy_cleanup(curl);
            curl_slist_free_all(header);
            exit(1);
        }
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(header);
    return http_response;
}
