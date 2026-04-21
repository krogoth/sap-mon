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
#include "sap_utils.h"

using namespace std;

static const string SOAP_ENVELOPE_NS =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<SOAP-ENV:Envelope"
    " xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\""
    " xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\""
    " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
    " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
    " xmlns:SAPControl=\"urn:SAPControl\""
    " xmlns:SAPCCMS=\"urn:SAPCCMS\""
    " xmlns:SAPHostControl=\"urn:SAPHostControl\""
    " xmlns:SAPOscol=\"urn:SAPOscol\""
    " xmlns:SAPDSR=\"urn:SAPDSR\">"
    "<SOAP-ENV:Body>";

static const string SOAP_ENVELOPE_CLOSE = "</SOAP-ENV:Body></SOAP-ENV:Envelope>";

// Builds and returns the SOAP XML for the sapcontrol command in p.
string sapcontrol_commands(const CliParams& p)
{
    smatch reg_match;
    string command = p.sapcontrol;

    // -javashow: OSExecute listing sapcontrol binary
    regex rx_javashow("^-javashow$");
    if (regex_search(command, reg_match, rx_javashow)) {
        string sapcontrol_path = "/sapmnt/" + p.sid + "/exe/uc/linuxx86_64/sapcontrol";
        return SOAP_ENVELOPE_NS
            + "<SAPControl:OSExecute>"
            + "<command>" + sapcontrol_path + "</command>"
            + "<async>0</async><timeout>30</timeout><protocolfile></protocolfile>"
            + "</SAPControl:OSExecute>"
            + SOAP_ENVELOPE_CLOSE;
    }

    // certificate-show: sapgenpse get_my_name or maintain_pk
    regex rx_certshow("^certificate-show$");
    if (regex_search(command, reg_match, rx_certshow)) {
        regex rx_getname("^get_my_name ");
        regex rx_maintain("^maintain_pk -l ");

        if (regex_search(p.sapgenpse, reg_match, rx_getname)
         || regex_search(p.sapgenpse, reg_match, rx_maintain))
        {
            string exe_path = "/sapmnt/" + p.sid + "/exe/uc/linuxx86_64/sapgenpse "
                            + p.sapgenpse + "-p " + p.psefile;
            return SOAP_ENVELOPE_NS
                + "<SAPControl:OSExecute>"
                + "<command>" + exe_path + "</command>"
                + "<async>0</async><timeout>30</timeout><protocolfile></protocolfile>"
                + "</SAPControl:OSExecute>"
                + SOAP_ENVELOPE_CLOSE;
        }
    }

    // generic sapcontrol command (GetProcessList, GetAlerts, J2EE*, etc.)
    return SOAP_ENVELOPE_NS
        + "<SAPControl:" + command + ">"
        + "</SAPControl:" + command + ">"
        + SOAP_ENVELOPE_CLOSE;
}
