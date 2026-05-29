#!/bin/bash

SAP_MON_BASE_DIR=$(cd "$(dirname "$0")" && pwd)

export SNC_TRACE_FILE="${SAP_MON_BASE_DIR}/logs/"
export RFC_TRACE_DIR="${SAP_MON_BASE_DIR}/logs/"
export CPIC_TRACE_DIR="${SAP_MON_BASE_DIR}/logs/"

mkdir -p "${SAP_MON_BASE_DIR}/logs"

if [[ ! -x "${SAP_MON_BASE_DIR}/sap_mon" ]]; then
    echo "Error: sap_mon binary not found at ${SAP_MON_BASE_DIR}/sap_mon" >&2
    exit 1
fi

export LD_LIBRARY_PATH="${SAP_MON_BASE_DIR}/nwrfcsdk/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

if [[ -f "${SAP_MON_BASE_DIR}/sapcryptolib/libsapcrypto.so" ]]; then
    export SNC_LIB_64="${SAP_MON_BASE_DIR}/sapcryptolib/libsapcrypto.so"
    export CCL_TRACE_DIR="${SAP_MON_BASE_DIR}/logs/"
    export SECUDIR="${SAP_MON_BASE_DIR}/config/sec/"
    export CCL_PROFILE="${SAP_MON_BASE_DIR}/config/sapcrypto.ini"
fi

exec "${SAP_MON_BASE_DIR}/sap_mon" "-inipath=${SAP_MON_BASE_DIR}/config/" "$@"
