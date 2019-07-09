#!/bin/bash
set -e
export AUTOPOINT=false
export LIBTOOLIZE_OPTIONS=--quiet
autoreconf -fi "$@"
