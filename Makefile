CXX      := g++
CXXFLAGS := -O3 -std=c++17 -Wall -Wformat=2 -Wformat-security -Werror=format-security \
             -Wno-misleading-indentation \
             -fPIE -fstack-protector-strong -fno-delete-null-pointer-checks -fwrapv \
             -D_FORTIFY_SOURCE=2
LDFLAGS  := -Wl,--as-needed -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie
SAP_FLAGS := -DSAPwithUNICODE -I./nwrfcsdk/include
LIBS     := ./nwrfcsdk/lib/libsapnwrfc.so ./nwrfcsdk/lib/libsapucum.so \
             -lcrypto -lcurl -lboost_system

OBJS := sap_mon.o sapcontrol_commands.o xml_extract.o web_srv.o \
        read_cert_infos.o ssfp_get_pseinfo.o rfc_ping.o

sap_mon: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

sap_mon.o: sap_mon.cpp
	$(CXX) $(CXXFLAGS) $(SAP_FLAGS) -c -o $@ $<

ssfp_get_pseinfo.o: ssfp_get_pseinfo.cpp
	$(CXX) $(CXXFLAGS) $(SAP_FLAGS) -c -o $@ $<

read_cert_infos.o: read_cert_infos.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

rfc_ping.o: rfc_ping.cpp
	$(CXX) $(CXXFLAGS) $(SAP_FLAGS) -c -o $@ $<

sapcontrol_commands.o: sapcontrol_commands.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

web_srv.o: web_srv.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

xml_extract.o: xml_extract.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) sap_mon
