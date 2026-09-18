# Byte-level vectors

Inputs that are not valid UTF-8, so they cannot be JSON vectors. Every harness that
reads `../valid` and `../invalid` decodes text first; this directory tests the layer
below that: what a verifier does with the bytes it is actually handed.

Verdict is the CLI exit code: `0` valid, `1` invalid, `2` malformed. A conformant pair
of implementations returns the **same** code for every file here, and it must match
`expected.json`. The pinned key is the one in `../README.md`.

| File | Expected | What it pins |
|---|---|---|
| `000-clean-non-ascii.bin` | 0 | control: signed `model` is U+FFFD as a valid three-byte sequence |
| `001-invalid-continuation-byte.bin` | 2 | the reported case: `EF BF BD` replaced by a lone `80`. A decoder that substitutes U+FFFD reconstructs the signed payload and says valid |
| `002-utf8-bom.bin` | 2 | byte order mark before the document; a decoder that strips it accepts |
| `003-truncated-multibyte.bin` | 2 | three-byte sequence cut short |
| `004-overlong-encoding.bin` | 2 | overlong form of U+002F, forbidden by RFC 3629 |
| `005-surrogate-in-utf8.bin` | 2 | UTF-16 surrogate encoded in UTF-8, forbidden |
| `006-invalid-byte-in-ascii-value.bin` | 2 | invalid byte where the signed value was ASCII; both must say malformed, not one invalid and one malformed |

Regenerate with `python3 test-vectors/bytes/generate.py`; run with
`node scripts/bytes-interop-sweep.mjs`. Found through the forgery bounty, 12 September 2026.
