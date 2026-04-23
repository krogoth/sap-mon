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
#include "sap_utils.h"

using namespace std;

static string bytesToHex(const RFC_BYTE* buf, unsigned len)
{
    static const char hc[] = "0123456789ABCDEF";
    string out;
    out.reserve(len * 2);
    for (unsigned k = 0; k < len; ++k) {
        out += hc[(buf[k] >> 4) & 0xF];
        out += hc[ buf[k]       & 0xF];
    }
    return out;
}

vector<string> ssfp_get_pseinfo(const CliParams& p)
{
    RFC_ERROR_INFO errorInfo;
    vector<SapUcString> storage;
    RFC_CONNECTION_HANDLE conn = openRfcConnection(p, storage, errorInfo);

    if (errorInfo.code != RFC_OK) {
        cerr << "ssfp_get_pseinfo: login failed (code " << errorInfo.code << ")" << endl;
        return {};
    }

    RFC_FUNCTION_DESC_HANDLE ccms_bapi_handle = RfcGetFunctionDesc(conn, cU("SSFP_GET_PSEINFO"), &errorInfo);
    if (!ccms_bapi_handle) {
        cerr << "ssfp_get_pseinfo: RfcGetFunctionDesc SSFP_GET_PSEINFO failed" << endl;
        RfcCloseConnection(conn, &errorInfo);
        return {};
    }
    RFC_FUNCTION_HANDLE rfc_handle = RfcCreateFunction(ccms_bapi_handle, &errorInfo);

    vector<string> context_list = {
        "PROG", "PROG", "SMIM", "SFA",  "SSFA", "SSFA",
        "SSLC", "SSLC", "WSSE", "WSSE", "WSSE", "SSLS"
    };
    vector<string> applic_list = {
        "<SYST>", "<SNCS>", "DFAULT", "CLBOAU", "ELEARN", "SSO2",
        "ANONYM", "DFAULT", "DFAULT", "WSSCRT", "WSSKEY", "DFAULT"
    };

    vector<string> certlist;

    for (size_t i = 0; i < context_list.size(); ++i) {
        auto uc_ctx    = utf8ToSapUc(context_list[i], errorInfo);
        auto uc_applic = utf8ToSapUc(applic_list[i],  errorInfo);

        RfcSetChars(rfc_handle, cU("CONTEXT"), uc_ctx.get(),    strlenU(uc_ctx.get()),    &errorInfo);
        RfcSetChars(rfc_handle, cU("APPLIC"),  uc_applic.get(), strlenU(uc_applic.get()), &errorInfo);

        RfcInvoke(conn, rfc_handle, &errorInfo);

        const string tag = ";;;" + context_list[i] + ";;;" + applic_list[i];

        // EXPORTING CERTIFICATE: the PSE own certificate (XSTRING)
        {
            RFC_BYTE cert_buf[65536] = {};
            unsigned cert_len = 0;
            if (RfcGetXString(rfc_handle, cU("CERTIFICATE"),
                              cert_buf, sizeof(cert_buf), &cert_len, &errorInfo) == RFC_OK
                && cert_len > 0)
                certlist.push_back(bytesToHex(cert_buf, cert_len) + tag);
        }

        // EXPORTING CERTIFICATELIST: SSFBINTAB = TYPE TABLE OF XSTRING
        // Each row is a single XSTRING blob (CA trust-list certificate).
        // Access via RfcGetXStringByIndex(row, 0) — flat table, index 0 is the only field.
        unsigned rowCount = 0;
        RFC_TABLE_HANDLE table;
        RfcGetTable(rfc_handle, cU("CERTIFICATELIST"), &table, &errorInfo);
        RfcGetRowCount(table, &rowCount, &errorInfo);

        for (unsigned j = 0; j < rowCount; ++j) {
            RfcMoveTo(table, j, &errorInfo);
            RFC_STRUCTURE_HANDLE row = RfcGetCurrentRow(table, &errorInfo);
            if (!row) continue;

            RFC_BYTE cert_buf[65536] = {};
            unsigned cert_len = 0;
            if (RfcGetXStringByIndex(row, 0,
                                     cert_buf, sizeof(cert_buf), &cert_len, &errorInfo) == RFC_OK
                && cert_len > 0)
                certlist.push_back(bytesToHex(cert_buf, cert_len) + tag);
        }
    }

    RfcDestroyFunction(rfc_handle, &errorInfo);
    RfcCloseConnection(conn, &errorInfo);
    return certlist;
}
