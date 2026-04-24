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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/array.hpp>

#include "sap_utils.h"

using namespace std;
namespace pt = boost::property_tree;

// Returns Icinga exit code. certlist accumulates entries from OSExecute paths.
int xml_extract(const string& web_response, const CliParams& p, vector<string>& certlist)
{
    smatch reg_match;

    boost::property_tree::ptree ptree;
    istringstream iss(web_response);
    read_xml(iss, ptree);

    size_t wo_ist_sapcontrol_response = web_response.find("SAPControl:");

    string type = p.type;

    // -javashow: print WSDL methods and exit
    regex rx_javashow("^-javashow$");
    if (regex_search(p.sapcontrol, reg_match, rx_javashow)) {
        string buf = web_response;
        bool anzeige = false;
        while (true) {
            size_t anfang = buf.find("<item>");
            size_t ende   = buf.find("</item>");

            string item;
            try { item = buf.substr(anfang + 6, ende - anfang); }
            catch (out_of_range&) { cout << "Error xml_extract.cpp std::out_of_range" << endl; exit(0); }
            try { buf  = buf.substr(ende + 7, buf.length()); }
            catch (out_of_range&) { cout << "Error xml_extract.cpp std::out_of_range" << endl; exit(0); }

            if (item == "WEBMETHODS</item") anzeige = true;
            if (item == "EXITCODES</item")  anzeige = false;

            if (anzeige) {
                string r1, r2, r3;
                regex_replace(back_inserter(r1), item.begin(), item.end(), regex("&lt"), string("<"));
                regex_replace(back_inserter(r2), r1.begin(),  r1.end(),   regex("&gt"), string(">"));
                regex_replace(back_inserter(r3), r2.begin(),  r2.end(),   regex(";"),   string(""));
                try { r3 = r3.substr(0, r3.length() - 6); } catch (...) {}
                cout << r3 << endl;
            }
            if (item.empty()) break;
        }
        exit(0);
    }

    size_t wo_GetProcessList   = web_response.find("<SAPControl:GetProcessListResponse>");
    size_t wo_exitcode_null    = web_response.find("<exitcode>0</exitcode>");
    size_t wo_GetAlerts        = web_response.find("<SAPControl:GetAlertsResponse>");
    size_t wo_exit11           = web_response.find("<exitcode>11</exitcode>");
    size_t wo_GetAlertTree     = web_response.find("<SAPControl:GetAlertTreeResponse>");
    size_t wo_J2EEProcess      = web_response.find("<SAPControl:J2EEGetProcessListResponse>");
    size_t wo_J2EEComponent    = web_response.find("<SAPControl:J2EEGetComponentListResponse>");
    size_t wo_J2EEHeap         = web_response.find("<SAPControl:J2EEGetVMHeapInfoResponse>");

    if (wo_exit11 != string::npos) {
        cout << "\nError: " << web_response << endl;
        return -1;
    }

    if (wo_GetProcessList == string::npos && wo_exitcode_null == string::npos && wo_GetAlerts == string::npos
     && wo_GetAlertTree   == string::npos && wo_J2EEProcess  == string::npos && wo_J2EEComponent == string::npos
     && wo_J2EEHeap       == string::npos)
    {
        cout << "Error: " << web_response << endl;
        return 2;
    }

    if (wo_ist_sapcontrol_response == string::npos) return -1;

    string cmd_resp = web_response.substr(wo_ist_sapcontrol_response, web_response.length());
    size_t gt_pos = cmd_resp.find(">");
    cmd_resp = cmd_resp.substr(11, gt_pos - 11);

    bool name_found = false;
    int retcode        = -1;

    if (cmd_resp == "GetProcessListResponse") {
        BOOST_FOREACH(boost::property_tree::ptree::value_type& v,
            ptree.get_child("SOAP-ENV:Envelope.SOAP-ENV:Body.SAPControl:GetProcessListResponse.process"))
        {
            if (v.first != "item") { cout << "skipped: '" << v.first << "'\n"; continue; }

            auto name       = v.second.get<string>("name");
            auto textstatus = v.second.get<string>("textstatus");
            auto dispstatus = v.second.get<string>("dispstatus");

            if (name.find(p.monitor) == string::npos) continue;
            name_found = true;
            cout << name;

            if (dispstatus.find("SAPControl-GRAY")   != string::npos) { cout << " | GRAY | "   << textstatus << endl; retcode = 2; break; }
            if (dispstatus.find("SAPControl-RED")    != string::npos) { cout << " | RED | "    << textstatus << endl; retcode = 2; break; }
            if (dispstatus.find("SAPControl-YELLOW") != string::npos) { cout << " | YELLOW | " << textstatus << endl; retcode = 1; break; }
            if (dispstatus.find("SAPControl-GREEN")  != string::npos) { cout << " | GREEN | "  << textstatus << endl; retcode = 0; break; }
            break;
        }
        if (!name_found) {
            cout << "Process: " << p.monitor << " not found" << endl;
            cout << "SAP system stopped" << endl;
            retcode = 2;
        }
    }

    if (cmd_resp == "GetAlertsResponse") {
        bool object_found = false;
        BOOST_FOREACH(boost::property_tree::ptree::value_type& v,
            ptree.get_child("SOAP-ENV:Envelope.SOAP-ENV:Body.SAPControl:GetAlertsResponse.alert"))
        {
            if (v.first != "item") { cout << "skipped: '" << v.first << "'\n"; continue; }

            auto name       = v.second.get<string>("Object");
            auto textstatus = v.second.get<string>("Description");
            auto dispstatus = v.second.get<string>("Value");

            if (name.find(p.monitor) == string::npos) continue;
            object_found = true;
            cout << name;

            if (dispstatus.find("SAPControl-GRAY")   != string::npos) { cout << " | GRAY | "   << textstatus << endl; retcode = 2; break; }
            if (dispstatus.find("SAPControl-RED")    != string::npos) { cout << " | RED | "    << textstatus << endl; retcode = 2; break; }
            if (dispstatus.find("SAPControl-YELLOW") != string::npos) { cout << " | YELLOW | " << textstatus << endl; retcode = 1; break; }
            if (dispstatus.find("SAPControl-GREEN")  != string::npos) { cout << " | GREEN | "  << textstatus << endl; retcode = 0; break; }
            break;
        }
        if (!object_found) {
            cout << "Monitor: '" << p.monitor << "' not found" << endl;
            retcode = 2;
        }
    }

    if (cmd_resp == "OSExecuteResponse") {
        string buf = web_response;
        string cert_subject;
        string cert_valid_until;

        regex rx_getname("^get_my_name ");
        regex rx_maintain("^maintain_pk -l ");

        if (regex_search(p.sapgenpse, reg_match, rx_getname)) {
            bool running = true;
            while (running) {
                size_t anfang = buf.find("<item>");
                size_t ende   = buf.find("</item>");
                string item;
                try { item = buf.substr(anfang + 6, ende - anfang); }
                catch (out_of_range&) { cout << "Error xml_extract.cpp std::out_of_range" << endl; exit(0); }
                try { buf  = buf.substr(ende + 7, buf.length()); }
                catch (out_of_range&) { cout << "Error xml_extract.cpp std::out_of_range" << endl; exit(0); }

                if (regex_search(item, reg_match, regex("^Subject               :"))) {
                    cert_subject = item.substr(0, item.length() - 6);
                    cert_subject = cert_subject.substr(cert_subject.find(":") + 4);
                }
                if (regex_search(item, reg_match, regex("^             NotAfter :"))) {
                    cert_valid_until = item.substr(0, item.length() - 6);
                    cert_valid_until = cert_valid_until.substr(cert_valid_until.find(":") + 4);
                    running = false;
                }
            }
        }

        if (regex_search(p.sapgenpse, reg_match, rx_maintain)) {
            bool running = true;
            while (running) {
                size_t anfang = buf.find("<item>");
                size_t ende   = buf.find("</item>");
                string item;
                try { item = buf.substr(anfang + 6, ende - anfang); }
                catch (out_of_range&) { cout << "Error xml_extract.cpp std::out_of_range" << endl; exit(0); }
                try { buf  = buf.substr(ende + 7, buf.length()); }
                catch (out_of_range&) { cout << "Error xml_extract.cpp std::out_of_range" << endl; exit(0); }

                if (regex_search(item, reg_match, regex("^  Subject:"))) {
                    cert_subject = item.substr(0, item.length() - 6);
                    cert_subject = cert_subject.substr(cert_subject.find(":") + 31);
                }
                if (regex_search(item, reg_match, regex("^  Validity not after:"))) {
                    cert_valid_until = item.substr(0, item.length() - 6);
                    cert_valid_until = cert_valid_until.substr(cert_valid_until.find(":") + 20);
                    certlist.push_back(cert_subject + " Validity not after: " + cert_valid_until);
                }
                if (regex_search(item, reg_match, regex("^</item$")))
                    running = false;
            }
        }
    }

    if (cmd_resp == "J2EEGetProcessListResponse") {
        BOOST_FOREACH(boost::property_tree::ptree::value_type& v,
            ptree.get_child("SOAP-ENV:Envelope.SOAP-ENV:Body.SAPControl:J2EEGetProcessListResponse.process"))
        {
            if (v.first != "item") { cout << "skipped: '" << v.first << "'\n"; continue; }

            auto name      = v.second.get<string>("name");
            auto statetext = v.second.get<string>("statetext");

            if (name.find(p.monitor) == string::npos) continue;
            name_found = true;

            if (statetext.find("Disabled") != string::npos) { cout << " | GRAY | "  << statetext << endl; retcode = 2; break; }
            if (statetext.find("Running")  != string::npos) { cout << " | GREEN | " << statetext << endl; retcode = 0; break; }
            break;
        }
    }

    if (cmd_resp == "J2EEGetComponentListResponse") {
        BOOST_FOREACH(boost::property_tree::ptree::value_type& v,
            ptree.get_child("SOAP-ENV:Envelope.SOAP-ENV:Body.SAPControl:J2EEGetComponentListResponse.component"))
        {
            if (v.first != "item") { cout << "skipped: '" << v.first << "'\n"; continue; }

            auto name   = v.second.get<string>("name");
            auto status = v.second.get<string>("status");

            if (name.find(p.monitor) == string::npos) continue;
            name_found = true;

            if (status.find("stopped") != string::npos) { cout << " | GRAY | "  << status << endl; retcode = 2; break; }
            if (status.find("running") != string::npos) { cout << " | GREEN | " << status << endl; retcode = 0; break; }
            break;
        }
    }

    if (cmd_resp == "J2EEGetVMHeapInfoResponse") {
        BOOST_FOREACH(boost::property_tree::ptree::value_type& v,
            ptree.get_child("SOAP-ENV:Envelope.SOAP-ENV:Body.SAPControl:J2EEGetVMHeapInfoResponse.heap"))
        {
            if (v.first != "item") { cout << "skipped: '" << v.first << "'\n"; continue; }

            auto processname = v.second.get<string>("processname");
            auto vtype       = v.second.get<string>("type");
            auto size        = v.second.get<string>("size");

            if (processname.find(p.monitor) != string::npos && vtype.find(type) != string::npos) {
                cout << size << endl;
                retcode = 0;
            }
        }
    }

    return retcode;
}
