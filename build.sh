#!/usr/bin/env bash
# Build + run the Boost.DateTime time_input_facet OOB-read PoC against the
# local Boost 1.44.0 source tree.
#
# Usage:
#   ./build.sh            # build with AddressSanitizer (default) and run
#   ./build.sh plain      # build WITHOUT sanitizer (demonstrates the UB read
#                         #   without an ASan abort)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BOOST="$HERE/../boost_1_44_0"          # local Boost 1.44 headers + src
CXX="${CXX:-clang++}"

if [ ! -d "$BOOST/boost/date_time" ]; then
    echo "ERROR: Boost 1.44 source not found at: $BOOST" >&2
    echo "Adjust the BOOST path in build.sh." >&2
    exit 1
fi

# Boost.DateTime needs these three compiled sources (greg month/weekday tables).
SRC=(
    "$BOOST/libs/date_time/src/gregorian/greg_month.cpp"
    "$BOOST/libs/date_time/src/gregorian/greg_weekday.cpp"
    "$BOOST/libs/date_time/src/gregorian/date_generators.cpp"
)

# -D_GLIBCXX_USE_CXX11_ABI=0 : lets the 2010-era Boost headers compile cleanly
#                              against a modern libstdc++.
COMMON=(-std=c++03 -D_GLIBCXX_USE_CXX11_ABI=0 -g -O1 -I"$BOOST")

MODE="${1:-asan}"
if [ "$MODE" = "plain" ]; then
    echo "[*] building WITHOUT sanitizer ..."
    "$CXX" "${COMMON[@]}" "$HERE/poc.cpp" "${SRC[@]}" -o "$HERE/poc" || exit 1
    echo "[*] running ..."
    "$HERE/poc"
else
    echo "[*] building with AddressSanitizer ..."
    "$CXX" "${COMMON[@]}" -fsanitize=address -fno-omit-frame-pointer \
        "$HERE/poc.cpp" "${SRC[@]}" -o "$HERE/poc_asan" || exit 1
    echo "[*] running (expect: AddressSanitizer heap-buffer-overflow) ..."
    ASAN_OPTIONS=abort_on_error=0 "$HERE/poc_asan"
fi
