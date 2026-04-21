#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include "nwrfcsdk/include/sapnwrfc.h"
#include "nwrfcsdk/include/sapucrfc.h"

using std::string;
using std::vector;

static const unsigned NUM_LOGIN_PARAMS = 9;

// Typed container for all CLI parameters.
struct CliParams {
    std::string mode;
    std::string username;
    std::string password;
    std::string hostname;
    std::string sid;
    std::string sysnr;
    std::string client;
    std::string monitor;
    std::string warn;
    std::string critical;
    std::string http_proto;
    std::string subject;
    std::string rfc_dest;
    std::string sapcontrol;
    std::string type;
    std::string psefile;
    std::string sapgenpse;
    bool        insecure = false;  // -insecure: skip SSL peer/host verification (HTTPS only)
    bool        verbose  = false;  // -verbose/-v: print operation details to stderr
};

// RAII owner for SAP_UC* buffers allocated via mallocU.
class SapUcString {
public:
    SapUcString() = default;
    explicit SapUcString(SAP_UC* ptr) : ptr_(ptr) {}

    SapUcString(const SapUcString&)            = delete;
    SapUcString& operator=(const SapUcString&) = delete;

    SapUcString(SapUcString&& o) noexcept : ptr_(o.ptr_) { o.ptr_ = nullptr; }
    SapUcString& operator=(SapUcString&& o) noexcept {
        if (this != &o) { free(ptr_); ptr_ = o.ptr_; o.ptr_ = nullptr; }
        return *this;
    }

    ~SapUcString() { free(ptr_); }

    SAP_UC* get()   const noexcept { return ptr_; }
    bool    valid() const noexcept { return ptr_ != nullptr; }

private:
    SAP_UC* ptr_ = nullptr;
};

// Two-pass UTF-8 → SAP_UC* conversion (SDK 7.50 idiom).
// Allocates len*2+1 upfront; falls back to exact size on RFC_BUFFER_TOO_SMALL.
inline SapUcString utf8ToSapUc(const string& src, RFC_ERROR_INFO& errInfo) {
    unsigned bufSize   = static_cast<unsigned>(src.size()) * 2 + 1;
    SAP_UC*  buf       = static_cast<SAP_UC*>(mallocU(bufSize));
    if (!buf) throw std::runtime_error("utf8ToSapUc: mallocU failed");

    unsigned resultLen = 0;
    RFC_RC rc = RfcUTF8ToSAPUC(
        reinterpret_cast<RFC_BYTE*>(const_cast<char*>(src.c_str())),
        static_cast<unsigned>(src.size()),
        buf, &bufSize, &resultLen, &errInfo
    );

    if (rc == RFC_BUFFER_TOO_SMALL) {
        free(buf);
        bufSize = resultLen + 1;
        buf = static_cast<SAP_UC*>(mallocU(bufSize));
        if (!buf) throw std::runtime_error("utf8ToSapUc: mallocU realloc failed");
        resultLen = 0;
        rc = RfcUTF8ToSAPUC(
            reinterpret_cast<RFC_BYTE*>(const_cast<char*>(src.c_str())),
            static_cast<unsigned>(src.size()),
            buf, &bufSize, &resultLen, &errInfo
        );
    }

    if (rc != RFC_OK) {
        free(buf);
        throw std::runtime_error(
            string("utf8ToSapUc: conversion failed for '") + src + "'"
        );
    }

    buf[resultLen] = static_cast<SAP_UC>(0);
    return SapUcString(buf);
}

// Two-pass SAP_UC* → UTF-8 std::string conversion.
inline string sapUcToUtf8(const SAP_UC* src, RFC_ERROR_INFO& errInfo) {
    if (!src || strlenU(src) == 0) return {};

    unsigned bufSize   = 0;
    unsigned resultLen = 0;

    // Pass 1: probe required buffer size
    RfcSAPUCToUTF8(
        const_cast<SAP_UC*>(src), strlenU(src),
        nullptr, &bufSize, &resultLen, &errInfo
    );

    vector<char> buf(bufSize + 1, '\0');
    bufSize   = static_cast<unsigned>(buf.size());
    resultLen = 0;

    RFC_RC rc = RfcSAPUCToUTF8(
        const_cast<SAP_UC*>(src), strlenU(src),
        reinterpret_cast<RFC_BYTE*>(buf.data()), &bufSize, &resultLen, &errInfo
    );

    if (rc != RFC_OK) return {};
    return string(buf.data(), resultLen);
}

// Opens an RFC connection from CliParams.
// `storage` keeps the SapUcString buffers alive for the lifetime of the connection.
inline RFC_CONNECTION_HANDLE openRfcConnection(
    const CliParams& p,
    vector<SapUcString>& storage,
    RFC_ERROR_INFO& errInfo)
{
    storage.clear();
    storage.reserve(6);
    storage.push_back(utf8ToSapUc(p.username, errInfo));
    storage.push_back(utf8ToSapUc(p.password, errInfo));
    storage.push_back(utf8ToSapUc(p.hostname, errInfo));
    storage.push_back(utf8ToSapUc(p.sid,      errInfo));
    storage.push_back(utf8ToSapUc(p.sysnr,    errInfo));
    storage.push_back(utf8ToSapUc(p.client,   errInfo));

    RFC_CONNECTION_PARAMETER loginParams[NUM_LOGIN_PARAMS];
    loginParams[0].name = cU("dest");    loginParams[0].value = cU("DEV");
    loginParams[1].name = cU("user");    loginParams[1].value = storage[0].get();
    loginParams[2].name = cU("passwd");  loginParams[2].value = storage[1].get();
    loginParams[3].name = cU("ASHOST"); loginParams[3].value = storage[2].get();
    loginParams[4].name = cU("SYSID");  loginParams[4].value = storage[3].get();
    loginParams[5].name = cU("SYSNR");  loginParams[5].value = storage[4].get();
    loginParams[6].name = cU("CLIENT"); loginParams[6].value = storage[5].get();
    loginParams[7].name = cU("lang");   loginParams[7].value = cU("EN");
    loginParams[8].name = cU("TRACE");  loginParams[8].value = cU("0");

    return RfcOpenConnection(loginParams, NUM_LOGIN_PARAMS, &errInfo);
}
