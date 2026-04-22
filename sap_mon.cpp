// =============================================================================
// sap_mon_refactored.cpp
// Refactoring of Rocket-Search/sap-mon — structural rewrite, logic unchanged.
// Compiler: gcc 11.4.0, -std=c++17
// =============================================================================

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <string>
#include <string_view>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <algorithm>
#include <iterator>
#include <iomanip>
#include <fstream>
#include <regex>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <optional>

#include <curl/curl.h>
#include "sap_utils.h"

using namespace std;

// =============================================================================
// SECTION 1 — Forward declarations
// =============================================================================
int            rfc_ping(const CliParams& p, string& out_message);
vector<string> ssfp_get_pseinfo(const CliParams& p);
vector<string> read_cert_infos(const vector<string>& certlist, bool ssl_check);
string         sapcontrol_commands(const CliParams& p);
string         web_srv(const CliParams& p, const string& soap_xml);
int            xml_extract(const string& web_response, const CliParams& p, vector<string>& certlist);

// =============================================================================
// SECTION 2 — Process-wide RFC state (not function I/O)
// =============================================================================
RFC_ERROR_INFO  g_errorInfo;
RFC_RC          g_rc = RFC_OK;

// parseArgs(char**) supprimé — remplacé par parseArgsU(SAP_UC**) dans mainU.

// =============================================================================
// SECTION 5 — Connexion RFC centralisée
// =============================================================================

static inline void vlog(bool verbose, const string& msg) {
    if (verbose) cerr << "[v] " << msg << "\n";
}

/**
 * checkConnection — affiche l'erreur et exit si la connexion a échoué.
 */
void checkConnection(RFC_CONNECTION_HANDLE conn, const RFC_ERROR_INFO& errInfo) {
    if (errInfo.code != RFC_OK) {
        cout << "Login PROBLEM" << endl;
        // Correction bug original : format string cohérent
        printfU(cU("key#     %s\n"), errInfo.key);
        printfU(cU("message# %s\n"), errInfo.message);
        printfU(cU("code#    %d\n"), errInfo.code);
        exit(-1);
    }
}

/**
 * xmiLogon — invoque BAPI_XMI_LOGON, commun à plusieurs modes.
 * @param iface "XAL" ou "XBP"
 */
void xmiLogon(RFC_CONNECTION_HANDLE conn, const char* iface, RFC_ERROR_INFO& errInfo, bool verbose = false) {
    vlog(verbose, string("XMI logon interface=") + iface);
    auto bapi = RfcGetFunctionDesc(conn, cU("BAPI_XMI_LOGON"), &errInfo);
    if (!bapi) throw std::runtime_error("RfcGetFunctionDesc BAPI_XMI_LOGON failed");
    auto handle = RfcCreateFunction(bapi, &errInfo);
    RfcSetChars(handle, cU("EXTCOMPANY"), cU("TESTCOMPANY"), 11, &errInfo);
    RfcSetChars(handle, cU("EXTPRODUCT"), cU("TESTPRODUKT"), 11, &errInfo);

    unsigned iface_len = static_cast<unsigned>(strlen(iface));
    if (strcmp(iface, "XAL") == 0)
        RfcSetChars(handle, cU("INTERFACE"), cU("XAL"), iface_len, &errInfo);
    else
        RfcSetChars(handle, cU("INTERFACE"), cU("XBP"), iface_len, &errInfo);

    RfcSetChars(handle, cU("VERSION"), cU("1.0"), 3, &errInfo);
    RfcInvoke(conn, handle, &errInfo);

    RFC_STRUCTURE_HANDLE returnStruct;
    SAP_UC ret_type[4]     = iU("");
    SAP_UC ret_msg[8192]   = iU("");
    unsigned resultLen     = 0;
    RfcGetStructure(handle, cU("RETURN"), &returnStruct, &errInfo);
    RfcGetString(returnStruct, cU("TYPE"),    ret_type, sizeofU(ret_type),   &resultLen, &errInfo);
    RfcGetString(returnStruct, cU("MESSAGE"), ret_msg,  sizeofU(ret_msg),    &resultLen, &errInfo);

    string type_utf8 = sapUcToUtf8(ret_type, errInfo);
    string msg_utf8  = sapUcToUtf8(ret_msg,  errInfo);

    RfcDestroyFunction(handle, &errInfo);

    if (type_utf8 == "E" || type_utf8 == "A") {
        throw std::runtime_error(string("BAPI_XMI_LOGON (") + iface + ") failed: " + msg_utf8);
    }

    vlog(verbose, string("XMI logon ") + iface + " OK");
}

// =============================================================================
// SECTION 6 — Handlers (un par mode)
// =============================================================================

// Signature uniforme : connexion déjà ouverte + params CLI
using HandlerFn = function<int(RFC_CONNECTION_HANDLE, const CliParams&, RFC_ERROR_INFO&)>;

// ----------------------------------------------------------------------------
int handle_show(RFC_CONNECTION_HANDLE conn, const CliParams& p, RFC_ERROR_INFO& errInfo) {
    cout << "Alle verfügbaren CCMS Monitore" << endl;

    xmiLogon(conn, "XAL", errInfo, p.verbose);

    vlog(p.verbose, "BAPI_SYSTEM_MON_GETLIST: fetching monitor list");
    auto bapi = RfcGetFunctionDesc(conn, cU("BAPI_SYSTEM_MON_GETLIST"), &errInfo);
    if (!bapi) throw std::runtime_error("RfcGetFunctionDesc BAPI_SYSTEM_MON_GETLIST failed");
    auto handle = RfcCreateFunction(bapi, &errInfo);
    RfcSetChars(handle, cU("EXTERNAL_USER_NAME"), cU("RFC_TEST"), 8, &errInfo);
    RfcInvoke(conn, handle, &errInfo);

    unsigned rowCount = 0;
    RFC_TABLE_HANDLE table;
    RfcGetTable(handle, cU("MONITOR_NAMES"), &table, &errInfo);
    RfcGetRowCount(table, &rowCount, &errInfo);
    vlog(p.verbose, "Monitor sets found: " + to_string(rowCount));

    SAP_UC ms_name[4096]      = iU("");
    SAP_UC moni_name[4096]    = iU("");
    SAP_UC ctx_name[4096]     = iU("");
    SAP_UC obj_name[4096]     = iU("");
    SAP_UC mte_name[4096]     = iU("");
    SAP_UC mtclass_buf[16]    = iU("");

    RFC_STRUCTURE_HANDLE returnStructure;

    for (unsigned i = 0; i < rowCount; ++i) {
        RfcMoveTo(table, i, &errInfo);
        RfcGetString(table, cU("MS_NAME"),   ms_name,   sizeofU(ms_name),   nullptr, &errInfo);
        printfU(cU("%s\n"), ms_name);
        RfcGetString(table, cU("MONI_NAME"), moni_name, sizeofU(moni_name), nullptr, &errInfo);
        printfU(cU(" |\n  -> %s\n"), moni_name);

        auto bapi2 = RfcGetFunctionDesc(conn, cU("BAPI_SYSTEM_MON_GETTREE"), &errInfo);
        if (!bapi2) throw std::runtime_error("RfcGetFunctionDesc BAPI_SYSTEM_MON_GETTREE failed");
        auto handle2 = RfcCreateFunction(bapi2, &errInfo);

        RfcSetInt(handle2,  cU("MAX_TREE_DEPTH"),     0, &errInfo);
        RfcSetInt(handle2,  cU("VIS_ON_USR_LEVEL"),   3, &errInfo);
        RfcSetChars(handle2,cU("EXTERNAL_USER_NAME"), cU("RFC_TEST"), 8, &errInfo);

        RfcGetStructure(handle2, cU("MONITOR_NAME"), &returnStructure, &errInfo);
        RfcSetStructure(handle2, cU("MONITOR_NAME"),  returnStructure, &errInfo);
        RfcSetChars(returnStructure, cU("MS_NAME"),   ms_name,   strlenU(ms_name),   &errInfo);
        RfcSetChars(returnStructure, cU("MONI_NAME"), moni_name, strlenU(moni_name), &errInfo);

        RfcInvoke(conn, handle2, &errInfo);

        unsigned rowCount2 = 0;
        RFC_TABLE_HANDLE table2;
        RfcGetTable(handle2, cU("TREE_NODES"), &table2, &errInfo);
        RfcGetRowCount(table2, &rowCount2, &errInfo);
        vlog(p.verbose, "TREE_NODES rows: " + to_string(rowCount2));

        string last_ctx, last_obj;
        for (unsigned j = 0; j < rowCount2; ++j) {
            RfcMoveTo(table2, j, &errInfo);
            RfcGetString(table2, cU("CONTEXT_NAME"), ctx_name,    sizeofU(ctx_name),    nullptr, &errInfo);
            RfcGetString(table2, cU("OBJECT_NAME"),  obj_name,    sizeofU(obj_name),    nullptr, &errInfo);
            RfcGetString(table2, cU("MTE_NAME"),     mte_name,    sizeofU(mte_name),    nullptr, &errInfo);
            RfcGetString(table2, cU("MTCLASS"),      mtclass_buf, sizeofU(mtclass_buf), nullptr, &errInfo);

            if (p.verbose) {
                string c = sapUcToUtf8(ctx_name, errInfo);
                string o = sapUcToUtf8(obj_name, errInfo);
                string m = sapUcToUtf8(mte_name, errInfo);
                string t = sapUcToUtf8(mtclass_buf, errInfo);
                cerr << "[v] row[" << j << "] CONTEXT_NAME='" << c << "' OBJECT_NAME='" << o
                     << "' MTE_NAME='" << m << "' MTCLASS='" << t << "'\n";
            }

            string ctx     = sapUcToUtf8(ctx_name,    errInfo);
            string obj     = sapUcToUtf8(obj_name,    errInfo);
            string mte     = sapUcToUtf8(mte_name,    errInfo);
            string mtclass = sapUcToUtf8(mtclass_buf, errInfo);
            if (mtclass.size() > 3) mtclass = mtclass.substr(0, 3);

            if (ctx != last_ctx) {
                cout << "  |  [" << ctx << "]\n";
                last_ctx = ctx;
                last_obj.clear();
            }
            if (!obj.empty() && obj != last_obj) {
                cout << "  |    \\ " << obj << "\n";
                last_obj = obj;
            }
            if (!mte.empty()) {
                cout << "  |       -> " << mte;
                if (!mtclass.empty()) cout << "  (class=" << mtclass << ")";
                cout << "\n";
                cout << "  |          -monitor='" << p.sid << "\\" << ctx << "\\" << obj << "\\" << mte << "'\n";
            }
        }
        cout << "\n";
        RfcDestroyFunction(handle2, &errInfo);
    }
    RfcDestroyFunction(handle, &errInfo);
    return 0;
}

// ----------------------------------------------------------------------------
/**
 * Helper commun à -check et -checkall : résout le TID d'un MTE et retourne
 * sa classe MTCLASS sous forme de string UTF-8 (ex: "100", "101", "102", "111").
 */
static string resolveMtClass(
    RFC_CONNECTION_HANDLE conn,
    const SAP_UC* context_name,
    const SAP_UC* mte_name,
    const SAP_UC* object_name,
    const SAP_UC* system_id,
    RFC_STRUCTURE_HANDLE& outTid,
    RFC_ERROR_INFO& errInfo,
    bool verbose = false)
{
    vlog(verbose, "BAPI_SYSTEM_MTE_GETTIDBYNAME: resolving TID");
    auto bapi = RfcGetFunctionDesc(conn, cU("BAPI_SYSTEM_MTE_GETTIDBYNAME"), &errInfo);
    if (!bapi) throw std::runtime_error("RfcGetFunctionDesc BAPI_SYSTEM_MTE_GETTIDBYNAME failed");
    auto handle = RfcCreateFunction(bapi, &errInfo);

    RfcSetChars(handle, cU("CONTEXT_NAME"),       context_name, strlenU(context_name), &errInfo);
    RfcSetChars(handle, cU("EXTERNAL_USER_NAME"),  cU("External_User_Name_nonsens"), 26, &errInfo);
    RfcSetChars(handle, cU("MTE_NAME"),            mte_name,    strlenU(mte_name),    &errInfo);
    RfcSetChars(handle, cU("OBJECT_NAME"),         object_name, strlenU(object_name), &errInfo);
    RfcSetChars(handle, cU("SYSTEM_ID"),           system_id,   strlenU(system_id),   &errInfo);

    RfcInvoke(conn, handle, &errInfo);

    SAP_UC message_mtclass[9999] = iU("");
    RfcGetStructure(handle, cU("TID"), &outTid, &errInfo);
    RfcGetString(outTid, cU("MTCLASS"), message_mtclass, sizeofU(message_mtclass), nullptr, &errInfo);

    string mtclass = sapUcToUtf8(message_mtclass, errInfo);
    if (mtclass.size() > 3) mtclass = mtclass.substr(0, 3);

    vlog(verbose, "TID resolved, MTCLASS=" + mtclass);
    RfcDestroyFunction(handle, &errInfo);
    return mtclass;
}

/**
 * Helper : lit la valeur courante d'un MTE selon sa classe et l'affiche.
 * Retourne la valeur sous forme string pour les comparaisons warn/critical.
 */
static string readMteValue(
    RFC_CONNECTION_HANDLE conn,
    const string& mtclass,
    RFC_STRUCTURE_HANDLE tid,
    SAP_UC* message_buf,
    unsigned msg_buf_size,
    RFC_ERROR_INFO& errInfo,
    bool verbose = false)
{
    struct MteConfig {
        const SAP_UC* bapi_name;
        const SAP_UC* result_struct;
        const SAP_UC* result_field;
    };

    // Dispatch MTCLASS → BAPI + chemin de résultat
    static const map<string, MteConfig> dispatch = {
        {"100", {cU("BAPI_SYSTEM_MTE_GETPERFCURVAL"), cU("CURRENT_VALUE"), cU("ALRELEVVAL")}},
        {"101", {cU("BAPI_SYSTEM_MTE_GETMLCURVAL"),   cU("XMI_MSG_EXT"),   cU("MSG")}},
        {"102", {cU("BAPI_SYSTEM_MTE_GETSMVALUE"),    cU("VALUE"),         cU("MSG")}},
        {"111", {cU("BAPI_SYSTEM_MTE_GETTXTPROP"),    cU("PROPERTIES"),    cU("TEXT")}},
    };

    auto it = dispatch.find(mtclass);
    if (it == dispatch.end()) return {};

    const auto& cfg = it->second;
    vlog(verbose, string("readMteValue: calling ") + sapUcToUtf8(cfg.bapi_name, errInfo));
    auto bapi = RfcGetFunctionDesc(conn, cfg.bapi_name, &errInfo);
    if (!bapi) return {};
    auto handle = RfcCreateFunction(bapi, &errInfo);

    RfcSetChars(handle, cU("EXTERNAL_USER_NAME"), cU("External_User_Name_nonsens"), 26, &errInfo);
    RfcSetStructure(handle, cU("TID"), tid, &errInfo);
    RfcInvoke(conn, handle, &errInfo);

    // Vérification message d'erreur retour
    RFC_STRUCTURE_HANDLE returnStruct;
    SAP_UC return_msg[8192] = iU("");
    unsigned resultLen = 0;
    RfcGetStructure(handle, cU("RETURN"), &returnStruct, &errInfo);
    RfcGetString(returnStruct, cU("MESSAGE"), return_msg, sizeofU(return_msg), &resultLen, &errInfo);
    string err_utf8 = sapUcToUtf8(return_msg, errInfo);
    if (!err_utf8.empty()) {
        cout << "Fehler: Monitor nicht definiert" << endl;
        RfcDestroyFunction(handle, &errInfo);
        return {};
    }

    RFC_STRUCTURE_HANDLE valueStruct;
    RfcGetStructure(handle, cfg.result_struct, &valueStruct, &errInfo);
    RfcGetString(valueStruct, cfg.result_field, message_buf, msg_buf_size, &resultLen, &errInfo);

    string result = sapUcToUtf8(message_buf, errInfo);
    vlog(verbose, "MTE value=" + result);
    RfcDestroyFunction(handle, &errInfo);
    return result;
}

// ----------------------------------------------------------------------------
int handle_check(RFC_CONNECTION_HANDLE conn, const CliParams& p, RFC_ERROR_INFO& errInfo) {
    xmiLogon(conn, "XAL", errInfo, p.verbose);

    // Parsing du monitor path : SID\ContextName\...\ObjectName\MteName
    const string& monitor_name = p.monitor;

    size_t bs1  = monitor_name.find('\\');
    size_t bs2  = (bs1  != string::npos) ? monitor_name.find('\\', bs1  + 1) : string::npos;
    size_t bsL  = monitor_name.rfind('\\');
    size_t bsL1 = (bsL  != string::npos && bsL > 0) ? monitor_name.rfind('\\', bsL - 1) : string::npos;

    if (bs1 == string::npos || bs2 == string::npos || bsL == string::npos || bsL1 == string::npos) {
        cerr << "handle_check: -monitor= value must contain at least 3 backslashes: " << monitor_name << endl;
        return 3;
    }

    string sap_sid      = monitor_name.substr(0, bs1);
    string context_name = monitor_name.substr(bs1 + 1, bs2 - bs1 - 1);
    string mte_name     = monitor_name.substr(bsL + 1);
    string object_name  = monitor_name.substr(bsL1 + 1, bsL - bsL1 - 1);

    auto uc_sid     = utf8ToSapUc(sap_sid,      errInfo);
    auto uc_ctx     = utf8ToSapUc(context_name, errInfo);
    auto uc_mte     = utf8ToSapUc(mte_name,     errInfo);
    auto uc_obj     = utf8ToSapUc(object_name,  errInfo);

    vlog(p.verbose, "monitor=" + monitor_name);
    vlog(p.verbose, "sid=" + sap_sid + " context=" + context_name + " object=" + object_name + " mte=" + mte_name);

    RFC_STRUCTURE_HANDLE tid;
    string mtclass = resolveMtClass(conn,
        uc_ctx.get(), uc_mte.get(), uc_obj.get(), uc_sid.get(),
        tid, errInfo, p.verbose);

    SAP_UC message[8192] = iU("");
    string value = readMteValue(conn, mtclass, tid, message, sizeofU(message), errInfo, p.verbose);

    if (value.empty()) {
        RfcCloseConnection(conn, &errInfo);
        exit(-1);
    }

    printfU(cU("%s\n"), message);

    // Comparaison warn/critical (mode -check uniquement, optionnel)
    if (!p.warn.empty() && !p.critical.empty()) {
        try {
            int val_int      = stoi(value);
            int warn_int     = stoi(p.warn);
            int critical_int = stoi(p.critical);

            if (val_int >= warn_int)     { cout << "WARNUNG"   << endl; return 1; }
            if (val_int >= critical_int) { cout << "CRITICAL"  << endl; return 2; }
        } catch (const std::exception& e) {
            cerr << "handle_check: non-integer warn/critical value: " << e.what() << endl;
            return 3;
        }
    }
    return 0;
}

// ----------------------------------------------------------------------------
int handle_checkall(RFC_CONNECTION_HANDLE conn, const CliParams& p, RFC_ERROR_INFO& errInfo) {
    xmiLogon(conn, "XAL", errInfo, p.verbose);

    const string& monitor_name = p.monitor;
    size_t bs1 = monitor_name.find('\\');
    size_t bs2 = (bs1 != string::npos) ? monitor_name.find('\\', bs1 + 1) : string::npos;

    if (bs1 == string::npos || bs2 == string::npos) {
        cerr << "handle_checkall: -monitor= value must contain at least 2 backslashes: " << monitor_name << endl;
        return 3;
    }

    string ms_name_s  = monitor_name.substr(0, bs1);
    string moni_name_s = monitor_name.substr(bs1 + 1, bs2 - bs1 - 1);

    auto uc_ms   = utf8ToSapUc(ms_name_s,  errInfo);
    auto uc_moni = utf8ToSapUc(moni_name_s, errInfo);

    vlog(p.verbose, "BAPI_SYSTEM_MON_GETTREE: ms=" + ms_name_s + " moni=" + moni_name_s);
    auto bapi = RfcGetFunctionDesc(conn, cU("BAPI_SYSTEM_MON_GETTREE"), &errInfo);
    if (!bapi) throw std::runtime_error("RfcGetFunctionDesc BAPI_SYSTEM_MON_GETTREE failed");
    auto handle = RfcCreateFunction(bapi, &errInfo);

    RfcSetChars(handle, cU("EXTERNAL_USER_NAME"), cU("RFC_TEST"), 8, &errInfo);
    RfcSetInt(handle,   cU("MAX_TREE_DEPTH"),      0, &errInfo);
    RfcSetInt(handle,   cU("VIS_ON_USR_LEVEL"),    6, &errInfo);

    RFC_STRUCTURE_HANDLE monitorName;
    RfcGetStructure(handle, cU("MONITOR_NAME"), &monitorName, &errInfo);
    RfcSetChars(monitorName, cU("MONI_NAME"), uc_moni.get(), strlenU(uc_moni.get()), &errInfo);
    RfcSetChars(monitorName, cU("MS_NAME"),   uc_ms.get(),   strlenU(uc_ms.get()),   &errInfo);

    RfcInvoke(conn, handle, &errInfo);

    unsigned rowCount = 0;
    RFC_TABLE_HANDLE table;
    RfcGetTable(handle, cU("TREE_NODES"), &table, &errInfo);
    RfcGetRowCount(table, &rowCount, &errInfo);
    vlog(p.verbose, "Tree nodes found: " + to_string(rowCount));

    SAP_UC context_name[4096] = iU("");
    SAP_UC mte_name[4096]     = iU("");
    SAP_UC object_name[4096]  = iU("");
    SAP_UC system_id[4096]    = iU("");
    SAP_UC message[8192]      = iU("");

    for (unsigned i = 0; i < rowCount; ++i) {
        RfcMoveTo(table, i, &errInfo);
        RfcGetString(table, cU("MTSYSID"),   system_id,   sizeofU(system_id),   nullptr, &errInfo);
        RfcGetString(table, cU("MTMCNAME"),  context_name,sizeofU(context_name),nullptr, &errInfo);
        RfcGetString(table, cU("OBJECTNAME"),object_name, sizeofU(object_name), nullptr, &errInfo);
        RfcGetString(table, cU("MTNAMESHRT"),mte_name,    sizeofU(mte_name),    nullptr, &errInfo);

        printfU(cU("%s\\%s\\%s\\%s "), system_id, context_name, object_name, mte_name);

        RFC_STRUCTURE_HANDLE tid;
        string mtclass = resolveMtClass(conn,
            context_name, mte_name, object_name, system_id,
            tid, errInfo, p.verbose);

        if (mtclass == "050") { cout << "###" << endl; continue; }

        string value = readMteValue(conn, mtclass, tid, message, sizeofU(message), errInfo, p.verbose);
        if (!value.empty()) printfU(cU(" %s\n"), message);
    }

    RfcDestroyFunction(handle, &errInfo);
    return 0;
}

// ----------------------------------------------------------------------------
int handle_aborted_job(RFC_CONNECTION_HANDLE conn, const CliParams& p, RFC_ERROR_INFO& errInfo) {
    xmiLogon(conn, "XBP", errInfo, p.verbose);

    vlog(p.verbose, "BAPI_XBP_JOB_SELECT: fetching all jobs");
    auto bapi = RfcGetFunctionDesc(conn, cU("BAPI_XBP_JOB_SELECT"), &errInfo);
    if (!bapi) throw std::runtime_error("RfcGetFunctionDesc BAPI_XBP_JOB_SELECT failed");
    auto handle = RfcCreateFunction(bapi, &errInfo);
    RfcSetChars(handle, cU("EXTERNAL_USER_NAME"), cU("RFC_TEST"), 8, &errInfo);

    auto uc_sid = utf8ToSapUc(p.sid, errInfo);

    RFC_STRUCTURE_HANDLE jobSelectParam;
    RfcGetStructure(handle, cU("JOB_SELECT_PARAM"), &jobSelectParam, &errInfo);
    RfcSetStructure(handle, cU("JOB_SELECT_PARAM"), jobSelectParam, &errInfo);
    RfcSetChars(jobSelectParam, cU("JOBNAME"),   cU("*"), 1, &errInfo);
    RfcSetChars(jobSelectParam, cU("JOBCOUNT"),  cU("*"), 1, &errInfo);
    RfcSetChars(jobSelectParam, cU("JOBGROUP"),  cU("*"), 1, &errInfo);
    RfcSetChars(jobSelectParam, cU("USERNAME"),  cU("*"), 1, &errInfo);
    RfcSetChars(jobSelectParam, cU("FROM_DATE"), cU("1900-01-01"), 10, &errInfo);
    RfcSetChars(jobSelectParam, cU("FROM_TIME"), cU("00:00:00"),   8,  &errInfo);
    RfcSetChars(jobSelectParam, cU("TO_DATE"),   cU("2999-12-31"), 10, &errInfo);
    RfcSetChars(jobSelectParam, cU("TO_TIME"),   cU("00:00:00"),   8,  &errInfo);
    RfcSetChars(handle, cU("SYSTEMID"), uc_sid.get(), 3, &errInfo);

    RfcInvoke(conn, handle, &errInfo);

    unsigned rowCount = 0;
    RFC_TABLE_HANDLE table;
    RfcGetTable(handle, cU("JOB_HEAD"), &table, &errInfo);
    RfcGetRowCount(table, &rowCount, &errInfo);
    vlog(p.verbose, "Jobs selected: " + to_string(rowCount));

    SAP_UC job_name[4096]       = iU("");
    SAP_UC job_count[4096]      = iU("");
    SAP_UC job_status[4096]     = iU("");
    SAP_UC job_end_datum[4096]  = iU("");
    SAP_UC job_end_time[4096]   = iU("");

    vector<string> job_name_und_job_count_array;

    for (unsigned i = 0; i < rowCount; ++i) {
        RfcMoveTo(table, i, &errInfo);
        RfcGetString(table, cU("JOBNAME"),  job_name,      sizeofU(job_name),      nullptr, &errInfo);
        RfcGetString(table, cU("JOBCOUNT"), job_count,     sizeofU(job_count),     nullptr, &errInfo);
        RfcGetString(table, cU("STATUS"),   job_status,    sizeofU(job_status),    nullptr, &errInfo);
        RfcGetString(table, cU("ENDDATE"),  job_end_datum, sizeofU(job_end_datum), nullptr, &errInfo);
        RfcGetString(table, cU("ENDTIME"),  job_end_time,  sizeofU(job_end_time),  nullptr, &errInfo);

        string status = sapUcToUtf8(job_status, errInfo);
        if (status.find('A') == string::npos) continue;

        string name   = sapUcToUtf8(job_name,      errInfo);
        string count  = sapUcToUtf8(job_count,     errInfo);
        string datum  = sapUcToUtf8(job_end_datum, errInfo);
        string uhrzeit= sapUcToUtf8(job_end_time,  errInfo);

        job_name_und_job_count_array.push_back(
            name + ";;" + count + "##" + datum + ";#;" + uhrzeit
        );
    }
    RfcDestroyFunction(handle, &errInfo);
    RfcCloseConnection(conn, &errInfo);
    vlog(p.verbose, "Aborted jobs (raw): " + to_string(job_name_und_job_count_array.size()));

    // --- Logique de déduplication (inchangée) ---
    vector<string> job_name_array_3;
    string job_name_temp_2;

    for (size_t j = 0; j < job_name_und_job_count_array.size(); ++j) {
        size_t wo = job_name_und_job_count_array[j].find(";;");
        string job_name_temp = job_name_und_job_count_array[j].substr(0, wo);
        if (job_name_temp == job_name_temp_2) continue;
        job_name_array_3.push_back(job_name_temp);
        job_name_temp_2 = job_name_temp;
    }

    vector<string> aborted_jobs;
    for (const auto& jobname : job_name_array_3) {
        int datum_int_temp  = -1;
        int uhrzeit_int_temp= -1;

        for (const auto& entry : job_name_und_job_count_array) {
            if (entry.find(jobname + ";;") == string::npos) continue;
            size_t wg = entry.find("##");
            int d = stoi(entry.substr(wg + 2, 8));
            if (d > datum_int_temp) datum_int_temp = d;
        }

        for (const auto& entry : job_name_und_job_count_array) {
            if (entry.find(jobname) == string::npos) continue;
            string dtmp = to_string(datum_int_temp);
            if (entry.find(dtmp) == string::npos) continue;
            size_t wsg = entry.find(";#;");
            int u = stoi(entry.substr(wsg + 3, 6));
            if (u > uhrzeit_int_temp) uhrzeit_int_temp = u;
        }

        string uhrzeit_str = to_string(uhrzeit_int_temp);
        uhrzeit_str.insert(0, 6 - uhrzeit_str.size(), '0');
        string datum_str = to_string(datum_int_temp);

        for (const auto& entry : job_name_und_job_count_array) {
            if (entry.find(jobname)   == string::npos) continue;
            if (entry.find(datum_str) == string::npos) continue;
            if (entry.find(uhrzeit_str) == string::npos) continue;
            aborted_jobs.push_back(entry);
        }
    }

    sort(aborted_jobs.begin(), aborted_jobs.end());
    aborted_jobs.erase(unique(aborted_jobs.begin(), aborted_jobs.end()), aborted_jobs.end());

    if (aborted_jobs.empty()) return 0;

    cout << "CRITICAL -\t";
    for (const auto& job : aborted_jobs) {
        string out = job;
        replace(out.begin(), out.end(), ';', '#');
        cout << out << "\t";
    }
    cout << endl;
    return 2;
}

// ----------------------------------------------------------------------------
int handle_abap_dump(RFC_CONNECTION_HANDLE conn, const CliParams& p, RFC_ERROR_INFO& errInfo) {
    xmiLogon(conn, "XBP", errInfo, p.verbose);

    vlog(p.verbose, "/SDF/GET_DUMP_LOG: fetching ABAP dump log");
    auto bapi = RfcGetFunctionDesc(conn, cU("/SDF/GET_DUMP_LOG"), &errInfo);
    if (!bapi) throw std::runtime_error("RfcGetFunctionDesc /SDF/GET_DUMP_LOG failed");
    auto handle = RfcCreateFunction(bapi, &errInfo);

    RfcSetChars(handle, cU("DATE_FROM"), cU("1900-01-01"), 10, &errInfo);
    RfcSetChars(handle, cU("DATE_TO"),   cU("2999-12-31"), 10, &errInfo);
    RfcSetChars(handle, cU("TIME_FROM"), cU("00:00:00"),   8,  &errInfo);
    RfcSetChars(handle, cU("TIME_TO"),   cU("00:00:00"),   8,  &errInfo);
    RfcInvoke(conn, handle, &errInfo);

    unsigned rowCount = 0;
    RFC_TABLE_HANDLE table;
    RfcGetTable(handle, cU("ET_E2E_LOG"), &table, &errInfo);
    RfcGetRowCount(table, &rowCount, &errInfo);
    vlog(p.verbose, "Dump entries found: " + to_string(rowCount) + " (checking last 3)");

    // Champs à extraire
    struct DumpEntry { string date, time, user, severity, host, field1, field4, field9; };
    auto readField = [&](RFC_TABLE_HANDLE t, const SAP_UC* field) -> string {
        SAP_UC buf[4096] = iU("");
        RfcGetString(t, field, buf, sizeofU(buf), nullptr, &errInfo);
        return sapUcToUtf8(buf, errInfo);
    };

    vector<string> abap_dumps;
    unsigned limit = min(rowCount, 3u);

    for (unsigned i = 0; i < limit; ++i) {
        RfcMoveTo(table, i, &errInfo);
        DumpEntry e;
        e.date     = readField(table, cU("E2E_DATE"));
        e.time     = readField(table, cU("E2E_TIME"));
        e.user     = readField(table, cU("E2E_USER"));
        e.severity = readField(table, cU("E2E_SEVERITY"));
        e.host     = readField(table, cU("E2E_HOST"));
        e.field1   = readField(table, cU("FIELD1"));
        e.field4   = readField(table, cU("FIELD4"));
        e.field9   = readField(table, cU("FIELD9"));

        abap_dumps.push_back(
            e.date + "###" + e.time + ";;;" + e.severity + "#;#" +
            e.host + ";#;" + e.field1 + "##;" + e.field4 + ";;#" +
            e.field9 + "+++" + e.user
        );
    }

    RfcDestroyFunction(handle, &errInfo);
    RfcCloseConnection(conn, &errInfo);

    // Load previous snapshot into a set for O(n) diff
    set<string> prev_snapshot;
    {
        ifstream prev("/tmp/sap_mon_abap_dump.log");
        if (prev.is_open()) {
            string line;
            while (getline(prev, line))
                prev_snapshot.insert(line);
        }
    }

    // Persist current snapshot
    {
        ofstream f("/tmp/sap_mon_abap_dump.log");
        for (const auto& line : abap_dumps) f << line << "\n";
    }

    // New entries = lines in abap_dumps not in previous snapshot
    vector<string> diff_lines;
    for (const auto& line : abap_dumps) {
        if (prev_snapshot.find(line) == prev_snapshot.end())
            diff_lines.push_back(line);
    }

    for (const auto& line : diff_lines) {
        auto w_datum    = line.find("###");
        auto w_uhrzeit  = line.find(";;;");
        auto w_severity = line.find("#;#");
        auto w_host     = line.find(";#;");
        auto w_field1   = line.find("##;");
        auto w_field4   = line.find(";;#");
        auto w_user     = line.find("+++");

        string datum    = line.substr(0, w_datum);
        string uhrzeit  = line.substr(w_datum + 3, 6);
        string severity = line.substr(w_uhrzeit + 3, w_severity - w_uhrzeit - 3);
        string host     = line.substr(w_severity + 3, w_host - w_severity - 3);
        string runtime  = line.substr(w_host + 3, w_field1 - w_host - 3);
        string abap_prg = line.substr(w_field1 + 3, w_field4 - w_field1 - 3);
        string exception= line.substr(w_field4 + 3, w_user - w_field4 - 3);
        string username = line.substr(w_user + 3);
        username.erase(remove(username.begin(), username.end(), '\n'), username.end());

        cout << "CRITICAL - ABAP Programm: " << abap_prg
             << " ### Runtime error: " << runtime
             << " ### Exception: "    << exception
             << " ### Schweregrad: "  << severity
             << " ### Hostname: "     << host
             << " ### Username: "     << username
             << " ### Datum: "        << datum
             << " ### Uhrzeit: "      << uhrzeit << endl;
        return 2;
    }
    return 0;
}

// ----------------------------------------------------------------------------
int handle_sslview(RFC_CONNECTION_HANDLE /*conn*/, const CliParams& p, RFC_ERROR_INFO& /*errInfo*/) {
    cout << "Folgende Zertifikate mit dazugehörigem Ablaufdatum sind in der Zertifikatsliste aktiv" << endl << endl;
    auto certlist = ssfp_get_pseinfo(p);
    read_cert_infos(certlist, false);
    return 0;
}

// ----------------------------------------------------------------------------
int handle_sslcheck(RFC_CONNECTION_HANDLE /*conn*/, const CliParams& p, RFC_ERROR_INFO& /*errInfo*/) {
    vlog(p.verbose, "sslcheck: subject=" + p.subject + " warn=" + p.warn + " critical=" + p.critical);
    auto certlist            = ssfp_get_pseinfo(p);
    vlog(p.verbose, "Certificates retrieved: " + to_string(certlist.size()));
    auto certlist_subj_valid = read_cert_infos(certlist, true);

    string subject_suchen = p.subject;

    for (const auto& entry : certlist_subj_valid) {
        if (entry.find(subject_suchen) == string::npos) continue;

        size_t wt = entry.find(";;;###");
        string valid_until = entry.substr(wt + 6);

        struct tm zeit{};
        strptime(valid_until.c_str(), "%b %d %H:%M:%S %Y %Z", &zeit);

        time_t now         = std::time(nullptr);
        long diff_sec      = static_cast<long>(mktime(&zeit)) - static_cast<long>(now);
        long tage          = diff_sec / 60 / 60 / 24;

        vlog(p.verbose, "Certificate expires in " + to_string(tage) + " days");
        if (p.warn.empty()) { cout << tage << endl; return 0; }

        long tage_warn     = stol(p.warn);
        long tage_critical = stol(p.critical);

        if (tage >= tage_warn)     { cout << "OK - "       << tage << endl; return 0; }
        if (tage >= tage_critical) { cout << "WARNING - "  << tage << endl; return 1; }
                                   { cout << "CRITICAL - " << tage << endl; return 2; }
    }
    return 0;
}

// ----------------------------------------------------------------------------
int handle_rfc(RFC_CONNECTION_HANDLE /*conn*/, const CliParams& p, RFC_ERROR_INFO& /*errInfo*/) {
    vlog(p.verbose, "RFC ping: destination=" + p.rfc_dest);
    string message;
    int rc = rfc_ping(p, message);
    if (rc == 0) { cout << "OK - RFC destination " << p.rfc_dest << endl; return 0; }
    if (rc == 2) { cout << "critical - " << message << endl; return 2; }
    return rc;
}

// ----------------------------------------------------------------------------
int handle_java(RFC_CONNECTION_HANDLE /*conn*/, const CliParams& p, RFC_ERROR_INFO& /*errInfo*/) {
    string soap_xml    = sapcontrol_commands(p);
    string web_resp    = web_srv(p, soap_xml);
    vector<string> cl;
    return xml_extract(web_resp, p, cl);
}

// ----------------------------------------------------------------------------
int handle_javashow(RFC_CONNECTION_HANDLE /*conn*/, const CliParams& p, RFC_ERROR_INFO& /*errInfo*/) {
    CliParams pshow   = p;
    pshow.sapcontrol  = "-javashow";
    string soap_xml   = sapcontrol_commands(pshow);
    string web_resp   = web_srv(pshow, soap_xml);
    vector<string> cl;
    xml_extract(web_resp, pshow, cl);
    return 0;
}

// =============================================================================
// SECTION 7 — Signal handler
// =============================================================================
void signalHandler(int signum) {
    cout << "PROBLEM SAP MON mail to software.moore@gmail.com" << endl;
    cout << "Interrupt signal (" << signum << ") received." << endl;
    exit(EXIT_FAILURE);
}

// =============================================================================
// SECTION 8 — Dispatch table + main
// =============================================================================

/**
 * Modes qui nécessitent une connexion RFC ouverte avant dispatch.
 * Les autres (ssl*, rfc, java*) gèrent leur propre connexion en interne.
 */
static const set<string> RFC_CONNECTED_MODES = {
    "-show", "-check", "-checkall", "-aborted-job", "-abap-dump"
};

// sapUcArgToString supprimé — remplacé par conversion directe char-par-char dans parseArgsU

/**
 * parseArgsU — version SAP_UC** de parseArgs.
 * argv arrive déjà converti par le runtime SAP (via mainU).
 * Aucune conversion RfcUTF8ToSAPUC nécessaire sur les arguments CLI.
 */
static CliParams parseArgsU(int argc, SAP_UC** argv) {
    if (argc < 2) throw std::runtime_error("Usage: sap_mon2 -<mode> [options]");

    CliParams p;
    map<string, string> kv;

    // argv[1] = mode — conversion directe caractère par caractère (ASCII pur)
    // sapUcToUtf8 nécessite g_errorInfo initialisé, pas garanti ici
    {
        const SAP_UC* m = argv[1];
        string s;
        while (m && *m) { s += static_cast<char>(*m); ++m; }
        p.mode = s;
    }

    for (int i = 2; i < argc; ++i) {
        // Même conversion légère pour le parsing key=value
        const SAP_UC* arg = argv[i];
        string arg_str;
        while (arg && *arg) { arg_str += static_cast<char>(*arg); ++arg; }

        // strip leading '-' ou '--'
        size_t start = arg_str.find_first_not_of('-');
        if (start == string::npos) continue;

        auto eq = arg_str.find('=', start);
        if (eq == string::npos) {
            kv[arg_str.substr(start)] = "";
            continue;
        }
        kv[arg_str.substr(start, eq - start)] = arg_str.substr(eq + 1);
    }

    auto get = [&](const string& k) -> string {
        auto it = kv.find(k);
        return (it != kv.end()) ? it->second : string{};
    };

    p.username   = get("username");
    p.password   = get("password");
    p.hostname   = get("hostname");
    p.sid        = get("sid");
    p.sysnr      = get("sysnum");
    p.client     = get("client");
    p.monitor    = get("monitor").empty() ? get("monitorname") : get("monitor");
    p.warn       = get("warn");
    p.critical   = get("critical");
    p.http_proto = get("proto").empty() ? get("http") : get("proto");
    p.rfc_dest   = get("rfcdestination").empty() ? get("rfcdest") : get("rfcdestination");
    p.subject    = get("subjectname").empty() ? (get("checkcertificate").empty() ? get("subject") : get("checkcertificate")) : get("subjectname");
    p.sapcontrol = get("sapcontrol");
    p.type       = get("type");
    p.psefile    = get("psefile");
    p.sapgenpse  = get("sapgenpse");
    p.insecure   = kv.count("insecure") > 0;
    p.verbose    = kv.count("verbose") > 0 || kv.count("v") > 0;

    // Validate credentials for RFC-based modes
    static const set<string> rfc_modes = {
        "-check", "-checkall", "-abortjob", "-abapdump",
        "-sslview", "-sslcheck", "-rfc", "-javacheck", "-javashow"
    };
    if (rfc_modes.count(p.mode)) {
        if (p.username.empty()) throw std::runtime_error("Missing required option: -username=");
        if (p.password.empty()) throw std::runtime_error("Missing required option: -password=");
        if (p.hostname.empty()) throw std::runtime_error("Missing required option: -hostname=");
        if (p.sysnr.empty())    throw std::runtime_error("Missing required option: -sysnum=");
        if (p.client.empty())   throw std::runtime_error("Missing required option: -client=");
    }

    return p;
}

/**
 * openRfcConnectionU — version directe SAP_UC** : les valeurs argv sont
 * déjà en SAP_UC*, on les passe directement sans conversion.
 * On garde openRfcConnection(CliParams) pour les handlers internes.
 */
RFC_CONNECTION_HANDLE openRfcConnectionDirect(
    SAP_UC* username, SAP_UC* password, SAP_UC* hostname,
    SAP_UC* sid,      SAP_UC* sysnr,   SAP_UC* client,
    RFC_ERROR_INFO& errInfo)
{
    const RFC_CONNECTION_PARAMETER loginParams[] = {
        {cU("dest"),   cU("DEV")  },
        {cU("user"),   username   },
        {cU("passwd"), password   },
        {cU("ASHOST"), hostname   },
        {cU("SYSID"),  sid        },
        {cU("SYSNR"),  sysnr      },
        {cU("CLIENT"), client     },
        {cU("lang"),   cU("EN")   },
        {cU("TRACE"),  cU("0")    },
    };
    return RfcOpenConnection(loginParams, 9, &errInfo);
}

// argv[i] → valeur après '=' en SAP_UC* (pointeur dans argv[i], pas de copie)
static const SAP_UC* sapUcValue(const SAP_UC* arg) {
    if (!arg) return cU("");
    const SAP_UC eq = static_cast<SAP_UC>('=');
    const SAP_UC* p = arg;
    while (*p && *p != eq) ++p;
    return *p ? p + 1 : arg;
}

// =============================================================================
// SECTION 9 — Help
// =============================================================================
static void print_help() {
    cout <<
"Usage: sap_mon -<mode> [options]\n"
"\n"
"Connection options (required for RFC modes):\n"
"  -username=<user>       SAP logon user\n"
"  -password=<pass>       SAP logon password\n"
"  -hostname=<host>       SAP application server host (or SAP router string)\n"
"  -sid=<SID>             SAP system ID\n"
"  -sysnum=<NN>           SAP system number (two digits)\n"
"  -client=<NNN>          SAP client number\n"
"\n"
"Modes:\n"
"  -show                  List all available CCMS monitor sets\n"
"  -check                 Check a single CCMS monitor value\n"
"    -monitor=<path>        Monitor path (e.g. SID\\host\\Buffers\\...\\value)\n"
"    -warn=<n>              Warning threshold (optional)\n"
"    -critical=<n>          Critical threshold (optional)\n"
"  -checkall              Check all monitors under a monitor set\n"
"    -monitor=<path>        Monitor set path (e.g. SID\\host\\Buffers)\n"
"  -aborted-job           Check for aborted background jobs\n"
"  -abap-dump             Check for ABAP short dumps\n"
"  -sslview               List all X.509 certificates with expiry dates\n"
"  -sslcheck              Check expiry of a specific certificate\n"
"    -subjectname=<subj>    Certificate subject to check\n"
"    -warn=<days>           Warning threshold in days\n"
"    -critical=<days>       Critical threshold in days\n"
"  -rfc                   Test an RFC destination\n"
"    -rfcdestination=<dst>  RFC destination name\n"
"  -java                  Query a SAP Java/ABAP system via sapcontrol SOAP\n"
"    -proto=<http|https>    Protocol\n"
"    -sapcontrol=<cmd>      sapcontrol command (GetProcessList, GetAlerts,\n"
"                           J2EEGetProcessList, J2EEGetComponentList,\n"
"                           J2EEGetVMHeapInfo, certificate-show)\n"
"    -monitorname=<name>    Process/component/monitor name to filter\n"
"    -type=<type>           Heap type for J2EEGetVMHeapInfo\n"
"    -warn=<n>              Warning threshold\n"
"    -critical=<n>          Critical threshold\n"
"  -javashow              List available sapcontrol web methods\n"
"    -proto=<http|https>    Protocol\n"
"\n"
"General options:\n"
"  -verbose / -v          Print operation details to stderr\n"
"  -insecure              Skip SSL peer/host verification (HTTPS only)\n"
"\n"
"Exit codes follow Nagios/Icinga convention: 0=OK, 1=WARNING, 2=CRITICAL.\n"
"\n"
"Examples:\n"
"  sap_mon -show -username=RFC_TEST -password=Test123 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100\n"
"  sap_mon -check -username=RFC_TEST -password=Test123 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100\\\n"
"          -monitor='AL1\\saplnx_AL1_01\\OperatingSystem\\Filesystems\\/tmp\\Freespace' -warn=4000 -critical=2999\n"
"  sap_mon -aborted-job -username=RFC_TEST -password=Test123 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100\n"
"  sap_mon -rfc -username=RFC_TEST -password=Test123 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100\\\n"
"          -rfcdestination=AL1\n"
"  sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sysnum=01 -proto=http\\\n"
"          -sapcontrol=GetProcessList -monitorname=disp+work\n"
    << endl;
}

// =============================================================================
// mainU — signature SAP_UC** requise par le runtime SDK (-DSAPwithUNICODE)
// argv est déjà converti char*→SAP_UC* par sapucum avant l'appel.
// =============================================================================
int mainU(int argc, SAP_UC** argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    for (int sig : {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGTERM, SIGINT})
        signal(sig, signalHandler);

    // --- Parsing CLI (conversion SAP_UC→string pour la logique interne) ---
    CliParams p;
    try {
        p = parseArgsU(argc, argv);
    } catch (const exception& e) {
        cerr << "Argument error: " << e.what() << endl;
        return -1;
    }

    // --- Dispatch table ---
    static const map<string, HandlerFn> handlers = {
        {"-show",         handle_show        },
        {"-check",        handle_check       },
        {"-checkall",     handle_checkall    },
        {"-aborted-job",  handle_aborted_job },
        {"-abap-dump",    handle_abap_dump   },
        {"-sslview",      handle_sslview     },
        {"-sslcheck",     handle_sslcheck    },
        {"-rfc",          handle_rfc         },
        {"-java",         handle_java        },
        {"-javashow",     handle_javashow    },
    };

    if (p.mode == "-help" || p.mode == "--help" || p.mode == "-h") {
        print_help();
        return 0;
    }

    auto it = handlers.find(p.mode);
    if (it == handlers.end()) {
        cerr << "Unknown mode: " << p.mode << "\n\nRun sap_mon -help for usage." << endl;
        return -1;
    }

    vlog(p.verbose, "mode=" + p.mode);

    // --- Connexion RFC directe SAP_UC** pour les modes RFC ---
    RFC_CONNECTION_HANDLE conn = nullptr;
    vector<SapUcString> ucStorage;

    if (RFC_CONNECTED_MODES.count(p.mode)) {
        vlog(p.verbose, "Opening RFC connection: host=" + p.hostname + " user=" + p.username + " sysnr=" + p.sysnr + " client=" + p.client);
        SAP_UC *uc_user=nullptr, *uc_pass=nullptr, *uc_host=nullptr;
        SAP_UC *uc_sid=nullptr,  *uc_sys=nullptr,  *uc_cli=nullptr;

        // Conversion directe SAP_UC→char ASCII (même logique que parseArgsU)
        auto toStr = [](const SAP_UC* p) -> string {
            string s; while (p && *p) { s += static_cast<char>(*p); ++p; } return s;
        };

        for (int i = 2; i < argc; ++i) {
            string key = toStr(argv[i]);
            if      (key.find("-username=") != string::npos) uc_user = const_cast<SAP_UC*>(sapUcValue(argv[i]));
            else if (key.find("-password=") != string::npos) uc_pass = const_cast<SAP_UC*>(sapUcValue(argv[i]));
            else if (key.find("-hostname=") != string::npos) uc_host = const_cast<SAP_UC*>(sapUcValue(argv[i]));
            else if (key.find("-sid=")      != string::npos) uc_sid  = const_cast<SAP_UC*>(sapUcValue(argv[i]));
            else if (key.find("-sysnum=")   != string::npos) uc_sys  = const_cast<SAP_UC*>(sapUcValue(argv[i]));
            else if (key.find("-client=")   != string::npos) uc_cli  = const_cast<SAP_UC*>(sapUcValue(argv[i]));
        }

        conn = openRfcConnectionDirect(
            uc_user, uc_pass, uc_host, uc_sid, uc_sys, uc_cli,
            g_errorInfo);
        checkConnection(conn, g_errorInfo);
        vlog(p.verbose, "RFC connection established");
    }

    // --- Invocation ---
    int ret = 0;
    try {
        ret = it->second(conn, p, g_errorInfo);
    } catch (const exception& e) {
        cerr << "Handler error: " << e.what() << endl;
        if (conn) RfcCloseConnection(conn, &g_errorInfo);
        return -1;
    }

    if (conn) RfcCloseConnection(conn, &g_errorInfo);
    curl_global_cleanup();
    return ret;
}
