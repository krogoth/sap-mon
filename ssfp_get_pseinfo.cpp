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
    RFC_FUNCTION_HANDLE rfc_handle            = RfcCreateFunction(ccms_bapi_handle, &errorInfo);

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

        SAP_UC certificate_in_hex[32768] = iU("");

        for (unsigned j = 0; j < rowCount; ++j) {
            RfcMoveTo(table, j, NULL);
            // Field name is "CERTIFICATE" in RFC SSFP_GET_PSEINFO — verify against your SAP release if extraction fails
            RfcGetString(table, cU("CERTIFICATE"), certificate_in_hex, sizeofU(certificate_in_hex), NULL, &errorInfo);

            string cert_hex = sapUcToUtf8(certificate_in_hex, errorInfo);
            certlist.push_back(cert_hex + ";;;" + context_list[i] + ";;;" + applic_list[i]);
        }
    }

    RfcDestroyFunction(rfc_handle, &errorInfo);
    RfcCloseConnection(conn, NULL);
    return certlist;
}
