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
#include <regex>

using namespace std;

// Returns days until the certificate expires given a "NotAfter" date string.
long time_converter(const string& cert_valud_until)
{
    string date = cert_valud_until.substr(0, cert_valud_until.length() - 16);

    struct tm zeit{};
    strptime(date.c_str(), "%a %b  %d %H:%M:%S %Y", &zeit);

    time_t aktuelle_zeit = std::time(nullptr);
    long diff = static_cast<long>(mktime(&zeit)) - static_cast<long>(aktuelle_zeit);

    return diff / 60 / 60 / 24;
}
