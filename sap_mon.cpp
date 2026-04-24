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

// Convert a SAP_UC buffer of known length to std::string.
// Uses the resultLen output of RfcGetString and low-byte extraction,
// which is correct for all ASCII/Latin-1 ABAP field values.
// (strlenU is NOT used here because we already have the length from RfcGetString.)
static string ucToStr(const SAP_UC* buf, unsigned len) {
    string s;
    s.reserve(len);
    for (unsigned i = 0; i < len; ++i)
        s += static_cast<char>(buf[i] & 0xFF);
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

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
    unsigned typeLen = 0, msgLen = 0;
    RfcGetStructure(handle, cU("RETURN"), &returnStruct, &errInfo);
    RfcGetString(returnStruct, cU("TYPE"),    ret_type, sizeofU(ret_type),  &typeLen, &errInfo);
    RfcGetString(returnStruct, cU("MESSAGE"), ret_msg,  sizeofU(ret_msg),   &msgLen,  &errInfo);

    string type_str = ucToStr(ret_type, typeLen);
    string msg_str  = ucToStr(ret_msg,  msgLen);

    RfcDestroyFunction(handle, &errInfo);

    if (type_str == "E" || type_str == "A") {
        throw std::runtime_error(string("BAPI_XMI_LOGON (") + iface + ") failed: " + msg_str);
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

    SAP_UC ms_name[4096]   = iU("");
    SAP_UC moni_name[4096] = iU("");

    RFC_STRUCTURE_HANDLE returnStructure;

    // Leaf MTE classes that carry a readable value
    static const set<string> LEAF_CLASSES = {"100", "101", "102", "111"};

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

        // Helper: read a string field from the current row, trim trailing spaces
        auto readField = [&](const SAP_UC* fld) -> string {
            SAP_UC buf[4096] = iU("");
            RFC_ERROR_INFO e = {};
            unsigned len = 0;
            RfcGetString(table2, fld, buf, sizeofU(buf), &len, &e);
            if (e.code != RFC_OK || len == 0) return "";
            return ucToStr(buf, len);
        };

        // Load all rows, then use level-based path stack (nodes are in depth-first order)
        struct TNode { string name, cls, sysid, mtmcname, objname; int level; };
        vector<TNode> nodes;
        nodes.reserve(rowCount2);
        string sysid = p.sid;

        for (unsigned j = 0; j < rowCount2; ++j) {
            RfcMoveTo(table2, j, &errInfo);
            TNode n;
            n.name    = readField(cU("MTNAMESHRT"));
            n.cls     = readField(cU("MTCLASS"));
            if (n.cls.size() > 3) n.cls = n.cls.substr(0, 3);
            n.sysid   = readField(cU("ALSYSID"));
            // MTMCNAME is the monitoring-concept name — the exact value that
            // BAPI_SYSTEM_MTE_GETTIDBYNAME expects as CONTEXT_NAME.
            // CUSGRPNAME is a display group label and is NOT accepted by the BAPI.
            n.mtmcname = readField(cU("MTMCNAME"));
            n.objname  = readField(cU("OBJECTNAME"));
            string lvl = readField(cU("ALLEVINTRE"));
            n.level = lvl.empty() ? 1 : [](const string& s) {
                try { return stoi(s); } catch (...) { return 1; }
            }(lvl);
            if (!n.sysid.empty()) sysid = n.sysid;
            nodes.push_back(n);
        }

        // Display tree using a path stack — no parent-ID lookup needed because
        // BAPI_SYSTEM_MON_GETTREE returns nodes in depth-first traversal order.
        // For leaf nodes: use MTMCNAME/OBJECTNAME (exact BAPI_SYSTEM_MTE_GETTIDBYNAME
        // params) when available; fall back to the visual stack path otherwise.
        vector<string> pathStack;
        for (const TNode& n : nodes) {
            string indent((n.level > 0 ? n.level - 1 : 0) * 2, ' ');

            // Pop stack back to the parent level
            while ((int)pathStack.size() >= n.level)
                pathStack.pop_back();

            if (LEAF_CLASSES.count(n.cls)) {
                string monitor_path;
                if (!n.mtmcname.empty() && !n.objname.empty()) {
                    monitor_path = sysid + "\\" + n.mtmcname + "\\" + n.objname + "\\" + n.name;
                } else {
                    // Fallback: full stack path
                    monitor_path = sysid;
                    for (const auto& seg : pathStack) monitor_path += "\\" + seg;
                    monitor_path += "\\" + n.name;
                }
                if (p.verbose)
                    cerr << "[v]   mtmcname='" << n.mtmcname << "' objname='" << n.objname << "'\n";
                cout << "  |  " << indent << "-> " << n.name << "  (class=" << n.cls << ")\n";
                cout << "  |  " << indent << "   -monitor='" << monitor_path << "'\n";
            } else {
                cout << "  |  " << indent << n.name << "\n";
                if (!n.name.empty()) pathStack.push_back(n.name);
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
 * Helper commun à -check et -checkall : résout le TID d'un MTE.
 * Retourne le RFC_FUNCTION_HANDLE de l'invocation GETTIDBYNAME — l'appelant
 * DOIT appeler RfcDestroyFunction(returned_handle) APRÈS avoir fini avec outTid,
 * car outTid est un pointeur dans la mémoire du handle (use-after-free sinon).
 * outMtclass reçoit la classe MTCLASS ("100", "101", "102", "111" …).
 */
static RFC_FUNCTION_HANDLE resolveMtClass(
    RFC_CONNECTION_HANDLE conn,
    const SAP_UC* context_name,
    const SAP_UC* mte_name,
    const SAP_UC* object_name,
    const SAP_UC* system_id,
    RFC_STRUCTURE_HANDLE& outTid,
    string& outMtclass,
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

    // Always check RETURN first — if SAP can't find the MTE the TID fields are empty.
    {
        RFC_STRUCTURE_HANDLE ret;
        SAP_UC ret_type[4] = iU(""), ret_msg[4096] = iU("");
        unsigned tlen = 0, mlen = 0;
        if (RfcGetStructure(handle, cU("RETURN"), &ret, &errInfo) == RFC_OK) {
            RfcGetString(ret, cU("TYPE"),    ret_type, sizeofU(ret_type),  &tlen, &errInfo);
            RfcGetString(ret, cU("MESSAGE"), ret_msg,  sizeofU(ret_msg),   &mlen, &errInfo);
            string rtype = ucToStr(ret_type, tlen);
            string rmsg  = ucToStr(ret_msg,  mlen);
            if (!rmsg.empty())
                vlog(verbose, "GETTIDBYNAME RETURN type=" + rtype + " msg=" + rmsg);
        }
    }

    SAP_UC message_mtclass[9999] = iU("");
    unsigned mtclass_len = 0;
    RfcGetStructure(handle, cU("TID"), &outTid, &errInfo);
    RfcGetString(outTid, cU("MTCLASS"), message_mtclass, sizeofU(message_mtclass), &mtclass_len, &errInfo);

    outMtclass = ucToStr(message_mtclass, min(mtclass_len, 3u));
    vlog(verbose, "TID resolved, MTCLASS=" + outMtclass);

    // Caller must RfcDestroyFunction(handle) AFTER readMteValue — outTid lives in handle.
    return handle;
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
    bool verbose = false,
    int* outColor = nullptr)
{
    struct MteConfig {
        const SAP_UC* bapi_name;
        const SAP_UC* result_struct;  // struct containing the text/value
        const SAP_UC* result_field;
        const SAP_UC* color_struct;   // struct containing the alert color (may equal result_struct)
        const SAP_UC* color_field;    // INT4: 1=green 2=yellow 3=red; nullptr if unavailable
    };

    static const map<string, MteConfig> dispatch = {
        {"100", {cU("BAPI_SYSTEM_MTE_GETPERFCURVAL"), cU("CURRENT_VALUE"), cU("ALRELEVVAL"),  cU("CURRENT_VALUE"), cU("LASTALSTAT")}},
        {"101", {cU("BAPI_SYSTEM_MTE_GETMLCURVAL"),   cU("XMI_MSG_EXT"),   cU("MSG"),         cU("CURRENT_VALUE"), cU("VALUEFLTRD")}},
        {"102", {cU("BAPI_SYSTEM_MTE_GETSMVALUE"),    cU("VALUE"),         cU("MSG"),         cU("VALUE"),         cU("SMSGVALUE")}},
        {"111", {cU("BAPI_SYSTEM_MTE_GETTXTPROP"),    cU("PROPERTIES"),    cU("TEXT"),        nullptr,             nullptr}},
    };

    auto it = dispatch.find(mtclass);
    if (it == dispatch.end()) return {};

    const auto& cfg = it->second;
    auto bapi = RfcGetFunctionDesc(conn, cfg.bapi_name, &errInfo);
    if (!bapi) return {};
    auto handle = RfcCreateFunction(bapi, &errInfo);

    RfcSetChars(handle, cU("EXTERNAL_USER_NAME"), cU("External_User_Name_nonsens"), 26, &errInfo);
    RfcSetStructure(handle, cU("TID"), tid, &errInfo);
    RfcInvoke(conn, handle, &errInfo);

    RFC_STRUCTURE_HANDLE returnStruct;
    SAP_UC return_msg[8192] = iU("");
    unsigned resultLen = 0;
    RfcGetStructure(handle, cU("RETURN"), &returnStruct, &errInfo);
    RfcGetString(returnStruct, cU("MESSAGE"), return_msg, sizeofU(return_msg), &resultLen, &errInfo);
    string err_utf8 = ucToStr(return_msg, resultLen);
    if (!err_utf8.empty()) {
        cout << "Fehler: Monitor nicht definiert" << endl;
        RfcDestroyFunction(handle, &errInfo);
        return {};
    }

    RFC_STRUCTURE_HANDLE valueStruct;
    RfcGetStructure(handle, cfg.result_struct, &valueStruct, &errInfo);
    RfcGetString(valueStruct, cfg.result_field, message_buf, msg_buf_size, &resultLen, &errInfo);
    string result = ucToStr(message_buf, resultLen);
    vlog(verbose, "MTE value=" + result);

    if (outColor && cfg.color_field) {
        RFC_STRUCTURE_HANDLE colorStruct = valueStruct;
        // For MTCLASS 101, color lives in CURRENT_VALUE, not XMI_MSG_EXT.
        if (ucToStr(cfg.color_struct, strlenU(cfg.color_struct)) !=
            ucToStr(cfg.result_struct, strlenU(cfg.result_struct)))
            RfcGetStructure(handle, cfg.color_struct, &colorStruct, &errInfo);
        RFC_INT colorVal = 0;
        RfcGetInt(colorStruct, cfg.color_field, &colorVal, &errInfo);
        *outColor = static_cast<int>(colorVal);
        vlog(verbose, "MTE color=" + to_string(*outColor));
    }

    RfcDestroyFunction(handle, &errInfo);
    return result;
}



// ----------------------------------------------------------------------------
// Alert color source: the GET*VALUE BAPIs return the color as an INT4 field
// in their result structure (LASTALSTAT for MTCLASS 100, VALUEFLTRD for 101,
// SMSGVALUE for 102).  This reflects the live alert state at fetch time.
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
    string mtclass;
    auto tid_fn = resolveMtClass(conn,
        uc_ctx.get(), uc_mte.get(), uc_obj.get(), uc_sid.get(),
        tid, mtclass, errInfo, p.verbose);

    SAP_UC message[8192] = iU("");
    int color = 0;
    string value = readMteValue(conn, mtclass, tid, message, sizeofU(message), errInfo, p.verbose, &color);
    RfcDestroyFunction(tid_fn, &errInfo);  // safe — readMteValue is done with tid

    if (value.empty()) {
        RfcCloseConnection(conn, &errInfo);
        exit(-1);
    }

    static const char* color_names[] = { "unknown", "green", "yellow", "red" };
    const char* cname = (color >= 1 && color <= 3) ? color_names[color] : "unknown";
    vlog(p.verbose, string("ALCOLOR=") + to_string(color) + " (" + cname + ")");

    if (!p.warn.empty() && !p.critical.empty()) {
        try {
            int val_int      = stoi(value);
            int warn_int     = stoi(p.warn);
            int critical_int = stoi(p.critical);

            // Infer direction from threshold ordering:
            //   critical > warn → higher value is worse (fault counts, CPU usage, …)
            //   critical < warn → lower  value is worse (free memory, free space, …)
            int rc_out = 0;
            if (critical_int >= warn_int) {
                if      (val_int >= critical_int) rc_out = 2;
                else if (val_int >= warn_int)     rc_out = 1;
            } else {
                if      (val_int <= critical_int) rc_out = 2;
                else if (val_int <= warn_int)     rc_out = 1;
            }

            if      (rc_out == 2) { cout << "CRITICAL - " << value << endl; return 2; }
            else if (rc_out == 1) { cout << "WARNING - "  << value << endl; return 1; }
            else                  { cout << "OK - "       << value << endl; }
        } catch (const std::invalid_argument&) {
            // Non-numeric value with thresholds — use the BAPI alert color.
            int rc_out = (color == 3) ? 2 : (color == 2) ? 1 : 0;
            if      (rc_out == 2) { cout << "CRITICAL - " << value << endl; return 2; }
            else if (rc_out == 1) { cout << "WARNING - "  << value << endl; return 1; }
            else                  { cout << "OK - "       << value << endl; }
        } catch (const std::exception& e) {
            cerr << "handle_check: warn/critical comparison error: " << e.what() << endl;
            return 3;
        }
    } else {
        // No thresholds: use the alert color returned by the BAPI directly.
        int rc_out = (color == 3) ? 2 : (color == 2) ? 1 : 0;
        if      (rc_out == 2) { cout << "CRITICAL - " << value << endl; return 2; }
        else if (rc_out == 1) { cout << "WARNING - "  << value << endl; return 1; }
        else                  { cout << "OK - "       << value << endl; return 0; }
    }
    return 0;
}

// ----------------------------------------------------------------------------
// Alert color source: ALCOLOR field in TREE_NODES returned by
// BAPI_SYSTEM_MON_GETTREE.  This is the pre-computed traffic-light color
// stored in the monitor tree (same value shown in RZ20), updated by the CCMS
// background collector — may lag slightly behind the live alert state.
int handle_checkall(RFC_CONNECTION_HANDLE conn, const CliParams& p, RFC_ERROR_INFO& errInfo) {
    xmiLogon(conn, "XAL", errInfo, p.verbose);

    // Parse -monitor= path: SID[\MTMCNAME[\OBJECTNAME]]
    // Filters tree nodes by MTMCNAME and/or OBJECTNAME; empty = match all.
    const string& mon = p.monitor;
    size_t bs1 = mon.find('\\');
    size_t bs2 = (bs1 != string::npos) ? mon.find('\\', bs1 + 1) : string::npos;
    string sap_sid      = (bs1 != string::npos) ? mon.substr(0, bs1) : mon;
    string mtmc_filter  = (bs1 != string::npos && bs2 != string::npos) ? mon.substr(bs1 + 1, bs2 - bs1 - 1)
                        : (bs1 != string::npos)                        ? mon.substr(bs1 + 1)
                        : string{};
    string obj_filter   = (bs2 != string::npos) ? mon.substr(bs2 + 1) : string{};

    vlog(p.verbose, "checkall: sid=" + sap_sid + " mtmc_filter=" + mtmc_filter + " obj_filter=" + obj_filter);

    // Enumerate all monitor sets, then walk each tree — same as -show.
    auto bapi_list = RfcGetFunctionDesc(conn, cU("BAPI_SYSTEM_MON_GETLIST"), &errInfo);
    if (!bapi_list) throw std::runtime_error("RfcGetFunctionDesc BAPI_SYSTEM_MON_GETLIST failed");
    auto h_list = RfcCreateFunction(bapi_list, &errInfo);
    RfcSetChars(h_list, cU("EXTERNAL_USER_NAME"), cU("RFC_TEST"), 8, &errInfo);
    RfcInvoke(conn, h_list, &errInfo);

    unsigned monCount = 0;
    RFC_TABLE_HANDLE monTable;
    RfcGetTable(h_list, cU("MONITOR_NAMES"), &monTable, &errInfo);
    RfcGetRowCount(monTable, &monCount, &errInfo);
    vlog(p.verbose, "Monitor sets: " + to_string(monCount));

    static const set<string> LEAF_CLASSES = {"100", "101", "102", "111"};
    SAP_UC message[8192] = iU("");
    int worst_rc = 0;
    set<string> seen;  // deduplicate MTEs that appear in multiple monitor sets

    for (unsigned i = 0; i < monCount; ++i) {
        RfcMoveTo(monTable, i, &errInfo);
        SAP_UC ms_name[4096] = iU(""), moni_name[4096] = iU("");
        unsigned len_ms = 0, len_moni = 0;
        RfcGetString(monTable, cU("MS_NAME"),   ms_name,   sizeofU(ms_name),   &len_ms,   &errInfo);
        RfcGetString(monTable, cU("MONI_NAME"), moni_name, sizeofU(moni_name), &len_moni, &errInfo);

        auto bapi_tree = RfcGetFunctionDesc(conn, cU("BAPI_SYSTEM_MON_GETTREE"), &errInfo);
        if (!bapi_tree) continue;
        auto h_tree = RfcCreateFunction(bapi_tree, &errInfo);
        RfcSetInt(h_tree,  cU("MAX_TREE_DEPTH"),     0, &errInfo);
        RfcSetInt(h_tree,  cU("VIS_ON_USR_LEVEL"),   6, &errInfo);
        RfcSetChars(h_tree, cU("EXTERNAL_USER_NAME"), cU("RFC_TEST"), 8, &errInfo);
        RFC_STRUCTURE_HANDLE monName;
        RfcGetStructure(h_tree, cU("MONITOR_NAME"), &monName, &errInfo);
        RfcSetChars(monName, cU("MS_NAME"),   ms_name,   strlenU(ms_name),   &errInfo);
        RfcSetChars(monName, cU("MONI_NAME"), moni_name, strlenU(moni_name), &errInfo);
        RfcInvoke(conn, h_tree, &errInfo);

        unsigned rowCount = 0;
        RFC_TABLE_HANDLE table;
        RfcGetTable(h_tree, cU("TREE_NODES"), &table, &errInfo);
        RfcGetRowCount(table, &rowCount, &errInfo);

        for (unsigned j = 0; j < rowCount; ++j) {
            RfcMoveTo(table, j, &errInfo);
            SAP_UC sys[256]=iU(""), mtmc[4096]=iU(""), obj[4096]=iU(""), mte[4096]=iU(""), cls[16]=iU("");
            SAP_UC alcolor_buf[8] = iU("");
            unsigned lsys=0, lmtmc=0, lobj=0, lmte=0, lcls=0, lcolor=0;
            RfcGetString(table, cU("MTSYSID"),   sys,  sizeofU(sys),  &lsys,  &errInfo);
            RfcGetString(table, cU("MTMCNAME"),  mtmc, sizeofU(mtmc), &lmtmc, &errInfo);
            RfcGetString(table, cU("OBJECTNAME"),obj,  sizeofU(obj),  &lobj,  &errInfo);
            RfcGetString(table, cU("MTNAMESHRT"),mte,  sizeofU(mte),  &lmte,  &errInfo);
            RfcGetString(table, cU("MTCLASS"),   cls,  sizeofU(cls),  &lcls,  &errInfo);
            // ALCOLOR: CCMS internal traffic-light color (1=green, 2=yellow, 3=red)
            RFC_ERROR_INFO colorErr = {};
            RfcGetString(table, cU("ALCOLOR"), alcolor_buf, sizeofU(alcolor_buf), &lcolor, &colorErr);

            string s_sys  = ucToStr(sys,  lsys);
            string s_mtmc = ucToStr(mtmc, lmtmc);
            string s_obj  = ucToStr(obj,  lobj);
            string s_mte  = ucToStr(mte,  lmte);
            string s_cls  = ucToStr(cls,  min(lcls, 3u));

            if (s_mte.empty() || !LEAF_CLASSES.count(s_cls)) continue;
            if (!mtmc_filter.empty() && s_mtmc != mtmc_filter) continue;
            if (!obj_filter.empty()  && s_obj  != obj_filter)  continue;

            string key = s_sys + "\\" + s_mtmc + "\\" + s_obj + "\\" + s_mte;
            if (!seen.insert(key).second) continue;  // already processed

            auto uc_sys2  = utf8ToSapUc(s_sys,  errInfo);
            auto uc_mtmc2 = utf8ToSapUc(s_mtmc, errInfo);
            auto uc_obj2  = utf8ToSapUc(s_obj,  errInfo);
            auto uc_mte2  = utf8ToSapUc(s_mte,  errInfo);

            RFC_STRUCTURE_HANDLE tid;
            string mtclass;
            auto tid_fn = resolveMtClass(conn,
                uc_mtmc2.get(), uc_mte2.get(), uc_obj2.get(), uc_sys2.get(),
                tid, mtclass, errInfo, p.verbose);

            string value = readMteValue(conn, mtclass, tid, message, sizeofU(message), errInfo, p.verbose);
            RfcDestroyFunction(tid_fn, &errInfo);

            // Determine node exit code from CCMS ALCOLOR when available,
            // otherwise fall back to value-based logic for status MTEs.
            int node_rc = 0;
            string s_alcolor = (colorErr.code == RFC_OK) ? ucToStr(alcolor_buf, min(lcolor, 2u)) : "";
            if (!s_alcolor.empty()) {
                int color = 0;
                try { color = stoi(s_alcolor); } catch (...) {}
                if      (color == 3) node_rc = 2;  // red   → CRITICAL
                else if (color == 2) node_rc = 1;  // yellow→ WARNING
            } else if ((s_cls == "102" || s_cls == "101") && !value.empty()) {
                node_rc = 2;  // status MTE with message → CRITICAL
            }
            worst_rc = max(worst_rc, node_rc);

            const char* label = (node_rc == 2) ? "CRIT" : (node_rc == 1) ? "WARN" : "OK  ";
            cout << label << "  " << s_sys << "\\" << s_mtmc << "\\" << s_obj << "\\" << s_mte;
            if (!value.empty()) cout << "  " << value;
            cout << "\n";
        }
        RfcDestroyFunction(h_tree, &errInfo);
    }
    RfcDestroyFunction(h_list, &errInfo);
    return worst_rc;
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
        unsigned len_name = 0, len_count = 0, len_status = 0, len_datum = 0, len_time = 0;
        RfcGetString(table, cU("JOBNAME"),  job_name,      sizeofU(job_name),      &len_name,   &errInfo);
        RfcGetString(table, cU("JOBCOUNT"), job_count,     sizeofU(job_count),     &len_count,  &errInfo);
        RfcGetString(table, cU("STATUS"),   job_status,    sizeofU(job_status),    &len_status, &errInfo);
        RfcGetString(table, cU("ENDDATE"),  job_end_datum, sizeofU(job_end_datum), &len_datum,  &errInfo);
        RfcGetString(table, cU("ENDTIME"),  job_end_time,  sizeofU(job_end_time),  &len_time,   &errInfo);

        string status = ucToStr(job_status,    len_status);
        if (status.find('A') == string::npos) continue;

        string name   = ucToStr(job_name,      len_name);
        string count  = ucToStr(job_count,     len_count);
        string datum  = ucToStr(job_end_datum, len_datum);
        string uhrzeit= ucToStr(job_end_time,  len_time);

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

    cout << "CRITICAL - " << aborted_jobs.size() << " aborted job(s)\n";
    for (const auto& job : aborted_jobs) {
        string out = job;
        replace(out.begin(), out.end(), ';', '#');
        cout << out << "\n";
    }
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
        unsigned len = 0;
        RfcGetString(t, field, buf, sizeofU(buf), &len, &errInfo);
        return ucToStr(buf, len);
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

    // Helper: parse "Subject;;;CONTEXT;;;APPLIC;;;###ValidUntil" entry
    // Returns days until expiry; fills subject/context/applic/expiry out-params.
    auto parse_entry = [](const string& entry,
                          string& subj, string& ctx, string& applic, string& expiry) -> long {
        size_t s1  = entry.find(";;;");
        size_t wt  = entry.find(";;;###");
        subj       = entry.substr(0, s1);
        string mid = entry.substr(s1 + 3, wt - s1 - 3);  // "CONTEXT;;;APPLIC"
        size_t s2  = mid.find(";;;");
        ctx        = mid.substr(0, s2);
        applic     = mid.substr(s2 + 3);
        expiry     = entry.substr(wt + 6);
        struct tm zeit{};
        strptime(expiry.c_str(), "%b %d %H:%M:%S %Y %Z", &zeit);
        long diff = static_cast<long>(mktime(&zeit)) - static_cast<long>(std::time(nullptr));
        return diff / 86400;
    };

    // Default thresholds: warn=30 days, critical=7 days.
    // For certificate expiry lower days = worse, so critical must be <= warn.
    // Swap if the user accidentally provides them in the wrong order.
    long tw = p.warn.empty()     ? 30 : stol(p.warn);
    long tc = p.critical.empty() ?  7 : stol(p.critical);
    if (tc > tw) swap(tc, tw);

    if (!p.subject.empty()) {
        // Single-certificate check: find first matching entry
        for (const auto& entry : certlist_subj_valid) {
            if (entry.find(p.subject) == string::npos) continue;
            string subj, ctx, applic, expiry;
            long tage = parse_entry(entry, subj, ctx, applic, expiry);
            vlog(p.verbose, "Certificate expires in " + to_string(tage) + " days");
            if (tage >= tw) { cout << "OK - "       << tage << endl; return 0; }
            if (tage >= tc) { cout << "WARNING - "  << tage << endl; return 1; }
                            { cout << "CRITICAL - " << tage << endl; return 2; }
        }
        return 0;
    }
    int worst = 0;
    vector<string> lines;

    for (const auto& entry : certlist_subj_valid) {
        string subj, ctx, applic, expiry;
        long tage = parse_entry(entry, subj, ctx, applic, expiry);
        int rc = (tage < tc) ? 2 : (tage < tw) ? 1 : 0;
        if (rc == 0) continue;
        if (rc > worst) worst = rc;
        string label = (rc == 2) ? "CRITICAL" : "WARNING";
        lines.push_back(label + " - " + ctx + "/" + applic + " - " + subj
                        + " expires in " + to_string(tage) + " days"
                        + " (" + expiry + ")");
    }

    if (worst == 0) {
        cout << "OK - " << certlist_subj_valid.size() << " certificate(s) valid" << endl;
        return 0;
    }
    for (const auto& l : lines) cout << l << "\n";
    return worst;
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
"    -monitor=<path>        Monitor path: SID\\MTMCNAME\\OBJECTNAME\\MTEname\n"
"                           (use -show to list available paths)\n"
"    -warn=<n>              Warning threshold (numeric, optional)\n"
"    -critical=<n>          Critical threshold (numeric, optional)\n"
"                           Threshold direction is inferred: if critical > warn,\n"
"                           higher values are worse (e.g. fault counts, CPU %);\n"
"                           if critical < warn, lower values are worse\n"
"                           (e.g. free memory, free space).\n"
"                           Without thresholds, SAP's own CCMS alert color\n"
"                           (ALCOLOR) is used to determine the exit code.\n"
"  -checkall              Check all monitors under a monitor set\n"
"    -monitor=<path>        Monitor set path: SID[\\MTMCNAME[\\OBJECTNAME]]\n"
"                           Uses SAP's CCMS ALCOLOR for exit codes.\n"
"  -aborted-job           Check for aborted background jobs\n"
"  -abap-dump             Check for ABAP short dumps\n"
"  -sslview               List all X.509 certificates with expiry dates\n"
"  -sslcheck              Check certificate expiry\n"
"    -subjectname=<subj>    Check a specific certificate by subject (substring match)\n"
"                           Without -subjectname: checks all certificates, returns worst case\n"
"    -warn=<days>           Warning threshold in days (default: 30)\n"
"    -critical=<days>       Critical threshold in days (default: 7)\n"
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
"  # Check with numeric thresholds (lower free space = worse, so critical < warn):\n"
"  sap_mon -check -username=RFC_TEST -password=Test123 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100\\\n"
"          -monitor='AL1\\saplnx_AL1_01\\OperatingSystem\\Filesystems\\/tmp\\Freespace' -warn=4000 -critical=2999\n"
"  # Check using SAP's own CCMS alert color (no thresholds needed):\n"
"  sap_mon -check -username=RFC_TEST -password=Test123 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100\\\n"
"          -monitor='AL1\\saplnx_AL1_01\\Background\\AbortedJobs'\n"
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
