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

// Returns Icinga exit code; out_message carries the diagnostic string.
int rfc_ping(const CliParams& p, string& out_message)
{
    RFC_ERROR_INFO errorInfo;
    vector<SapUcString> storage;
    RFC_CONNECTION_HANDLE conn = openRfcConnection(p, storage, errorInfo);

    if (errorInfo.code != RFC_OK) {
        out_message = "Login PROBLEM";
        return 2;
    }

    RFC_FUNCTION_DESC_HANDLE ccms_bapi_handle;
    RFC_FUNCTION_HANDLE rfc_handle;

    ccms_bapi_handle = RfcGetFunctionDesc(conn, cU("/BDL/RFC_CHECK"), &errorInfo);
    rfc_handle       = RfcCreateFunction(ccms_bapi_handle, &errorInfo);

    auto uc_dest = utf8ToSapUc(p.rfc_dest, errorInfo);
    RfcSetChars(rfc_handle, cU("DESTINATION"), uc_dest.get(), strlenU(uc_dest.get()), &errorInfo);

    RfcInvoke(conn, rfc_handle, &errorInfo);

    SAP_UC mess_sap_uc[4096]     = iU("");
    SAP_UC check_ok_sap_uc[4096] = iU("");
    unsigned resultLen = 0;

    RfcGetString(rfc_handle, cU("MESS"),     mess_sap_uc,     sizeofU(mess_sap_uc),     &resultLen, &errorInfo);
    RfcGetString(rfc_handle, cU("CHECK_OK"), check_ok_sap_uc, sizeofU(check_ok_sap_uc), &resultLen, &errorInfo);

    int retcode = -1;

    if (strlenU(mess_sap_uc) != 0) {
        string error_msg = sapUcToUtf8(mess_sap_uc, errorInfo);

        if (error_msg.find("Illegal destination type 'G'.") != string::npos) {
            ccms_bapi_handle = RfcGetFunctionDesc(conn, cU("/SDF/HTTP_CHECK"), &errorInfo);
            rfc_handle       = RfcCreateFunction(ccms_bapi_handle, &errorInfo);

            RfcSetChars(rfc_handle, cU("IV_DESTINATION"), uc_dest.get(), strlenU(uc_dest.get()), &errorInfo);
            RfcSetChars(rfc_handle, cU("IV_PING"), cU("X"), 1, &errorInfo);
            RfcInvoke(conn, rfc_handle, &errorInfo);

            SAP_UC ping_sap_uc[4096] = iU("");
            RfcGetString(rfc_handle, cU("EV_PING_MESSAGE"), ping_sap_uc, sizeofU(ping_sap_uc), &resultLen, &errorInfo);

            string ping_msg = sapUcToUtf8(ping_sap_uc, errorInfo);
            out_message = ping_msg;

            if (ping_msg.find("HTTP Ping successful.") != string::npos)
                retcode = 0;
            else
                retcode = 2;
        } else {
            out_message = error_msg;
            retcode = 2;
        }
    }

    if (strlenU(check_ok_sap_uc) != 0)
        retcode = 0;

    RfcDestroyFunction(rfc_handle, &errorInfo);
    RfcCloseConnection(conn, NULL);
    return retcode;
}
