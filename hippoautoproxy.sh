#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Casing is important, some tools accept one but not the other.
export http_proxy="http://127.0.0.1:9062"
export HTTP_PROXY="${http_proxy}"
# Some tools expect a separate env var for proxy to use for HTTPS
export HTTPS_PROXY="${http_proxy}"
export https_proxy="${http_proxy}"
# Don't proxy direct connections to the SL asset server
export no_proxy="asset-cdn.glb.agni.lindenlab.com,${no_proxy}"
export NO_PROXY="${no_proxy}"
export LD_PRELOAD="${SCRIPT_DIR}/libhippoautoproxy.so ${LD_PRELOAD}"

exec "$@"
