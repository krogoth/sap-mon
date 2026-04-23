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

        // EXPORTING CERTIFICATE: the PSE own certificate (XSTRING)
        {
            RFC_BYTE cert_buf[65536] = {};
            unsigned cert_len = 0;
            RFC_RC rc = RfcGetXString(rfc_handle, cU("CERTIFICATE"),
                                      cert_buf, sizeof(cert_buf), &cert_len, &errorInfo);
            cerr << "[ssl] context=" << context_list[i] << " applic=" << applic_list[i]
                 << " own-cert rc=" << rc << " cert_len=" << cert_len << "\n";
            if (rc == RFC_OK && cert_len > 0) {
                static const char hc[] = "0123456789ABCDEF";
                string cert_hex;
                cert_hex.reserve(cert_len * 2);
                for (unsigned k = 0; k < cert_len; ++k) {
                    cert_hex += hc[(cert_buf[k] >> 4) & 0xF];
                    cert_hex += hc[ cert_buf[k]       & 0xF];
                }
                certlist.push_back(cert_hex + ";;;" + context_list[i] + ";;;" + applic_list[i]);
            }
        }

        // EXPORTING CERTIFICATELIST: table of RAWSTRING blobs (SSFBINTAB)
        // Each row IS the certificate — accessed via implicit field TABLE_LINE
        unsigned rowCount = 0;
        RFC_TABLE_HANDLE table;
        RfcGetTable(rfc_handle, cU("CERTIFICATELIST"), &table, &errorInfo);
        RfcGetRowCount(table, &rowCount, &errorInfo);

        cerr << "[ssl] context=" << context_list[i] << " applic=" << applic_list[i]
             << " rowCount=" << rowCount << " rc=" << errorInfo.code << "\n";

        for (unsigned j = 0; j < rowCount; ++j) {
            RfcMoveTo(table, j, &errorInfo);

            string cert_hex;

            // Attempt 1: XSTRING getter — raw bytes, we hex-encode them
            RFC_BYTE cert_buf[65536] = {};
            unsigned cert_len = 0;
            RFC_RC rc_get = RfcGetXString(table, cU("TABLE_LINE"),
                                          cert_buf, sizeof(cert_buf),
                                          &cert_len, &errorInfo);
            if (rc_get == RFC_OK && cert_len > 0) {
                static const char hc[] = "0123456789ABCDEF";
                cert_hex.reserve(cert_len * 2);
                for (unsigned k = 0; k < cert_len; ++k) {
                    cert_hex += hc[(cert_buf[k] >> 4) & 0xF];
                    cert_hex += hc[ cert_buf[k]       & 0xF];
                }
                cerr << "[ssl]   row " << j << " XString cert_len=" << cert_len
                     << " first='" << cert_hex.substr(0, 16) << "'\n";
            } else {
                // Attempt 2: String getter — SDK may return RAWSTRING as uppercase hex
                SAP_UC str_buf[32768] = iU("");
                unsigned str_len = 0;
                RFC_RC rc_str = RfcGetString(table, cU("TABLE_LINE"),
                                             str_buf, sizeofU(str_buf), &str_len, &errorInfo);
                if (rc_str == RFC_OK && str_len > 0) {
                    cert_hex = sapUcToUtf8(str_buf, errorInfo);
                    cerr << "[ssl]   row " << j << " GetString str_len=" << str_len
                         << " hex.size()=" << cert_hex.size()
                         << " first='" << cert_hex.substr(0, 16) << "'\n";
                } else {
                    cerr << "[ssl]   row " << j
                         << " XString rc=" << rc_get << " String rc=" << rc_str << "\n";
                }
            }

            if (!cert_hex.empty())
                certlist.push_back(cert_hex + ";;;" + context_list[i] + ";;;" + applic_list[i]);
        }
    }

    RfcDestroyFunction(rfc_handle, &errorInfo);
    RfcCloseConnection(conn, &errorInfo);
    return certlist;
}
