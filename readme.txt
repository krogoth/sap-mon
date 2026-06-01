A small monitoring tool to check SAP base health.
The tool reads SAP CCMS values and sapcontrol (J2EE) values and checks them against your defined thresholds.
When no thresholds are given, the exit code is derived from SAP's CCMS alert color (1=green/OK, 2=yellow/WARNING, 3=red/CRITICAL).
For -checkall, the color comes from BAPI_SYSTEM_MT_GETALERTDATA (HIGHALVAL field), which reflects the highest open/unacknowledged alert state — consistent with what RZ20 shows after operator acknowledgement.
For -check, the color comes from the per-MTE value BAPI (LASTALSTAT).
Exit codes follow the Nagios/Icinga convention (0=OK, 1=WARNING, 2=CRITICAL).
It is based on the SAP RFC SDK 7.50 for SAP communication and SOAP/XML data structures.
A "sap authorization role" transport for the SAP system is also included.
Import the transport request to use minimum permissions for the sap_mon monitoring user.


Directory structure
-------------------
After compilation, the recommended layout is:

  sap_mon/
  ├── sap_mon              # compiled binary
  ├── sap_mon.sh           # wrapper script (sets library paths, run this instead of sap_mon directly)
  ├── nwrfcsdk/            # SAP NetWeaver RFC SDK (required)
  │   └── lib/             # shared libraries (libsapnwrfc.so, libicuuc.so, ...)
  ├── sapcryptolib/        # SAP CommonCryptoLib (optional, for SNC/encrypted connections)
  │   └── libsapcrypto.so
  ├── config/              # runtime configuration
  │   ├── sapnwrfc.ini     # RFC destinations (used with -dest= or -inipath=)
  │   ├── sapcrypto.ini    # CommonCryptoLib profile (required if using sapcryptolib)
  │   └── sec/             # PSE files for SNC (SECUDIR)
  └── logs/                # RFC/SNC/CPIC trace output (created automatically by sap_mon.sh)

Setting up nwrfcsdk (required)
  1. Download "SAP NetWeaver RFC SDK 7.50" from the SAP Support Portal:
       https://support.sap.com/en/product/connectors/nwrfcsdk.html
     (requires an S-user account)
  2. Extract the archive and copy the resulting directory so that
     nwrfcsdk/lib/libsapnwrfc.so exists relative to sap_mon.sh.
  3. Run "make" to compile — check the library path in the Makefile if needed.

Setting up sapcryptolib (optional — only needed for SNC-encrypted connections)
  1. Download "SAP Cryptographic Library" (sapcrypto) from the SAP Support Portal.
  2. Place libsapcrypto.so in sapcryptolib/.
  3. Create config/sapcrypto.ini with at minimum:
       ccl/snc/enable_kerberos=0
  4. Place your PSE file(s) in config/sec/ and set SECUDIR accordingly.
  When sapcryptolib/libsapcrypto.so is present, sap_mon.sh sets all required
  environment variables (SNC_LIB_64, SECUDIR, CCL_PROFILE) automatically.

Using sap_mon.sh
  Always invoke sap_mon.sh instead of sap_mon directly. It:
  - Sets LD_LIBRARY_PATH to nwrfcsdk/lib
  - Configures SNC crypto paths if sapcryptolib is present
  - Passes -inipath=config/ automatically (overridable by passing -inipath= explicitly)
  - Creates the logs/ directory if missing
  - Redirects RFC/SNC/CPIC trace files to logs/

  Example:
    ./sap_mon.sh -checkall -dest=AL1_RFC



The program can check CCMS for "Performance attribute", "Status attribute", "Log attribute" and "Object description/Text attribute".
You can use a SAP router string to connect to your host — just put the router string instead of the hostname.
You can also use sap_mon for SAP base health monitoring without any other monitoring system or SAP Solution Manager.
For example, a simple command-line email notification one-liner:

  while true; do
    ./sap_mon -check -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 \
      -monitor='AL1\saplnx_AL1_01\OperatingSystem\Filesystems\/tmp\Freespace' -warn=4000 -critical=2999 \
      &> /dev/null && echo success || \
      echo "Free Space in /tmp is CRITICAL" | mail -s "sap_mon free space is critical" software.moore@gmail.com
    date; sleep 60
  done

It also checks for ABAP dumps, aborted background jobs, the expiration date of X.509 certificates, and performs RFC connection tests.
Also tested with Zabbix.
The following RFC connection types are supported: type 3 / G / I / T / X.

It is also possible to get monitor data via sapcontrol web services (WSDL / SOAP) over HTTP and HTTPS.
With this option you can monitor a SAP Java stack or TREX system.
The following features are available:
- GetProcessList
- GetAlerts
- J2EEGetVMHeapInfo
- J2EEGetComponentList
- J2EEGetProcessList
- Show and check all certificates with subject and expiration date
- GetAlertTree (under development)

If you change the default profile parameter "service/protectedwebmethods", you can access sapcontrol features with an anonymous user.


Prerequisites:
curl (libcurl) (curl 7.86.0)
Boost C++ Libraries (v1.80)
openssl/libressl (libcrypto) (LibreSSL 3.5.3)

Tested with:

Compiler:
"g++-12 (SUSE Linux) 12.2.1 20220830 [revision e927d1cf141f221c5a32574bde0913307e140984]"
  with -std=c++17
  with -std=c++14
  with -std=c++11
"g++ (SUSE Linux) 7.5.0"
  with -std=c++17
  with -std=c++14
  with -std=c++11

RFCSDK: SAP NetWeaver RFC SDK 7.50 Patch Level 7
OS: openSUSE Leap 15.4
Kernel: 4.20.16-default
GLIBCXX: 20191114

SAP Version:
SAP ERP 6.0 with EHP8 FOR SAP ERP 6.0
SAP_BASIS	750	0001	SAPK-75001INSAPBASIS	SAP Basis Component
SAP_ABA		750	0001	SAPK-75001INSAPABA		Cross-Application Component
kernel release  753	patch number                  700

DB2 Version:
DB2 v11.5.5.0", "special_5354",

Java System:
SAP NETWEAVER 7.5: Application Server Java
SAP NETWEAVER 7.5: EP Core - Application Portal
SAP NETWEAVER 7.5: Enterprise Portal

TREX version info:
version:             7.10.72.00
build number:        710.72.403812


Usage:

#Show the available CCMS monitors
./sap_mon -show -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100

#Check all MTEs under a monitor path (format: SID\MTMCNAME[\OBJECTNAME])
#Color source: HIGHALVAL from BAPI_SYSTEM_MT_GETALERTDATA — reflects open/unacknowledged alert state, consistent with RZ20.
#Acknowledging an alert in RZ20 will turn the check green without requiring deletion of job history or log entries.
#Output: one status line per leaf MTE, followed by indented alert messages for non-green nodes.
./sap_mon -checkall -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor='AL1\saplnx_AL1_01\Background'

#Filter by monitor set (MS_NAME[\MONI_NAME])
./sap_mon -checkall -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor-set='System Monitoring\Background Processing'

#CCMS Status attribute
./sap_mon -check -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor='AL1\saplnx_AL1_01\DatabaseClient\DBConnection\DBServer'

#CCMS Performance attribute without thresholds
#Exit code comes from the BAPI alert color (LASTALSTAT) — reflects the live SAP alert state
./sap_mon -check -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor='AL1\DB2 Universal Database for NT/UNIX\Space management\database related file systems\database directory'

#CCMS Performance attribute with thresholds
#Threshold direction is inferred: critical > warn means higher is worse (e.g. CPU, fault counts)
#                                 critical < warn means lower  is worse (e.g. free space, free memory)
./sap_mon -check -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor='AL1\DB2 Universal Database for NT/UNIX\Space management\database related file systems\database directory' -warn=39 -critical=45

#CCMS Log attribute
./sap_mon -check -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor='AL1\saplnx_AL1_01\R3Syslog\Communication'

#CCMS Text attribute or Object description
./sap_mon -check -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -monitor='AL1\System Configuration\Installed SAP Components\EA-HRCFR\Description'

#Aborted jobs
./sap_mon -aborted-job -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100

#Aborted jobs with SAP router string
./sap_mon -aborted-job -username=RFC_TEST -password=Test123456 -hostname=/H/172.17.190.85/S/3299/H/172.17.190.6 -sid=AL1 -sysnum=01 -client=100

#ABAP dump check
./sap_mon -abap-dump -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100

#SSL certificate list
./sap_mon -sslview -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100

#Check all certificates — returns worst case across every PSE (own cert + CA trust list).
#Default thresholds: warn=30 days, critical=7 days.
./sap_mon -sslcheck -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100

#Check all certificates with custom thresholds
./sap_mon -sslcheck -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -warn=60 -critical=30

#Check a specific certificate by subject (substring match)
./sap_mon -sslcheck -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -subjectname='C=DE, O=SAP Trust Community, OU=SAP Web AS, OU=I0020785703, CN=saplnx.moore.corp' -warn=30 -critical=7

#RFC connection test
./sap_mon -rfc -username=RFC_TEST -password=Test123456 -hostname=saplnx -sid=AL1 -sysnum=01 -client=100 -rfcdestination='AL1'

#Java / ABAP sapcontrol process status (GetProcessList)
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sysnum=01 -proto=http -sapcontrol=GetProcessList -monitorname='disp+work'

#Java / ABAP sapcontrol alerts (GetAlerts)
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sysnum=01 -proto=http -sapcontrol=GetAlerts -monitorname='Objects missing in the database'

#Java / ABAP sapcontrol certificate list
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sid=AL1 -sysnum=01 -proto=http -sapcontrol=certificate-show

#Java / ABAP sapcontrol certificate expiry check
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sid=AL1 -sysnum=01 -proto=http -checkcertificate='CN=AL1, OU=I0020785703, OU=SAP Web AS, O=SAP Trust Community, C=DE' -warn=30 -critical=15

#Java process status (J2EEGetProcessList)
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sysnum=01 -proto=http -sapcontrol=J2EEGetProcessList -monitorname='server0'

#Java component status (J2EEGetComponentList)
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sysnum=01 -proto=http -sapcontrol=J2EEGetComponentList -monitorname='com.adobe/AdobeDocumentServices'

#Java memory usage in bytes (J2EEGetVMHeapInfo)
./sap_mon -java -username=al1adm -password=Test1234 -hostname=saplnx -sysnum=01 -proto=http -sapcontrol=J2EEGetVMHeapInfo -process='server0' -type='local objects' -warn=3000 -critical=15000


Here are some screenshots of a standalone sap_mon:


For questions, bug reports, or suggestions, please open an issue at:
https://github.com/krogoth/sap-mon/issues

Credits:
Originally created by Rocket-Search (https://github.com/Rocket-Search).
This fork extends and refactors the original work.
