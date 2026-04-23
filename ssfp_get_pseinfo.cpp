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

    // Inspect CERTIFICATE field type once, so we know which getter to use
    unsigned cert_field_bytes = 0;
    {
        RFC_PARAMETER_DESC paramDesc;
        memset(&paramDesc, 0, sizeof(paramDesc));
        RFC_RC rc_pd = RfcGetParameterDescByName(ccms_bapi_handle, cU("CERTIFICATELIST"), &paramDesc, &errorInfo);
        if (rc_pd == RFC_OK && paramDesc.typeDescHandle) {
            RFC_FIELD_DESC fieldDesc;
            memset(&fieldDesc, 0, sizeof(fieldDesc));
            RFC_RC rc_fd = RfcGetFieldDescByName(paramDesc.typeDescHandle, cU("CERTIFICATE"), &fieldDesc, &errorInfo);
            if (rc_fd == RFC_OK) {
                cert_field_bytes = fieldDesc.nucLength;
                cerr << "[ssl] CERTIFICATE field type=" << fieldDesc.type
                     << " nucLength=" << fieldDesc.nucLength
                     << " ucLength="  << fieldDesc.ucLength  << "\n";
            } else {
                cerr << "[ssl] RfcGetFieldDescByName CERTIFICATE rc=" << rc_fd
                     << " msg='" << sapUcToUtf8(errorInfo.message, errorInfo) << "'\n";
            }
        } else {
            cerr << "[ssl] RfcGetParameterDescByName CERTIFICATELIST rc=" << rc_pd
                 << " msg='" << sapUcToUtf8(errorInfo.message, errorInfo) << "'\n";
        }
    }

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

        unsigned rowCount = 0;
        RFC_TABLE_HANDLE table;
        RfcGetTable(rfc_handle, cU("CERTIFICATELIST"), &table, &errorInfo);
        RfcGetRowCount(table, &rowCount, &errorInfo);

        cerr << "[ssl] context=" << context_list[i] << " applic=" << applic_list[i]
             << " rowCount=" << rowCount << " rc=" << errorInfo.code << "\n";

        for (unsigned j = 0; j < rowCount; ++j) {
            RfcMoveTo(table, j, NULL);

            RFC_BYTE cert_buf[65536] = {};
            unsigned cert_len = 0;

            // Try XSTRING (variable-length raw) first
            RFC_RC rc_get = RfcGetXString(table, cU("CERTIFICATE"),
                                          cert_buf, sizeof(cert_buf),
                                          &cert_len, &errorInfo);

            if (rc_get != RFC_OK) {
                cerr << "[ssl]   row " << j << " RfcGetXString rc=" << rc_get
                     << " msg='" << sapUcToUtf8(errorInfo.message, errorInfo) << "'\n";
                // Field may be type X (fixed-length raw bytes) — try RfcGetBytes
                unsigned use_len = (cert_field_bytes > 0 && cert_field_bytes <= sizeof(cert_buf))
                                   ? cert_field_bytes : sizeof(cert_buf);
                rc_get = RfcGetBytes(table, cU("CERTIFICATE"), cert_buf, use_len, &errorInfo);
                if (rc_get == RFC_OK) {
                    cert_len = use_len;
                    cerr << "[ssl]   row " << j << " RfcGetBytes rc=OK cert_len=" << cert_len << "\n";
                } else {
                    cerr << "[ssl]   row " << j << " RfcGetBytes rc=" << rc_get
                         << " msg='" << sapUcToUtf8(errorInfo.message, errorInfo) << "'\n";
                }
            }

            // Hex-encode raw DER bytes to uppercase ASCII (2 chars per byte)
            static const char hex_chars[] = "0123456789ABCDEF";
            string cert_hex;
            cert_hex.reserve(cert_len * 2);
            for (unsigned k = 0; k < cert_len; ++k) {
                cert_hex += hex_chars[(cert_buf[k] >> 4) & 0xF];
                cert_hex += hex_chars[ cert_buf[k]       & 0xF];
            }

            cerr << "[ssl]   row " << j
                 << " cert_len=" << cert_len
                 << " cert_hex.size()=" << cert_hex.size()
                 << " first='" << cert_hex.substr(0, 16) << "'\n";

            certlist.push_back(cert_hex + ";;;" + context_list[i] + ";;;" + applic_list[i]);
        }
    }

    RfcDestroyFunction(rfc_handle, &errorInfo);
    RfcCloseConnection(conn, &errorInfo);
    return certlist;
}
