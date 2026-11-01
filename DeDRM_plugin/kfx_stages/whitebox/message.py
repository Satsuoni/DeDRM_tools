"""Stage 1: the 116-byte message that comes out of the client identity token.

message(blob57) = P37 + Q79(blob57) + Q79(B22), with COPY_PERM=(22, 66). The
57-byte token (x2 record 2) is the only delivery-specific input; P37 and B22 are
library constants.
"""

from __future__ import annotations

from . import constants

M32 = 0xFFFFFFFF
N868 = 1079
N880 = 2743

SWAP_CONST_0 = 942821119
SWAP_CONST_1 = 280252159
EMPTY_TOKEN_30 = bytes.fromhex("2e2c6d5d5b703239386577376769776b6c3b776c2c3736357467686a776c")
EMPTY_FALLBACK_20 = bytes.fromhex("36373824255e2639323368776564396537323330")


def s32(x: int) -> int:
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def abs32(x: int) -> int:
    x &= M32
    return (-x) & M32 if x & 0x80000000 else x


def half75(x: int) -> int:
    t = x * 75
    t = t + 2 if t < -1 else t + 1
    return ((t & 0xFFFFFFFFFFFFFFFF) >> 1) & M32


def _pass(
    chars: list[int],
    t868: list[int],
    t880: list[int],
    fn: dict[int, list[int]],
    S: int,
    w20: int,
    w22: int,
    w25: int = 13,
) -> bytes:
    out = []
    fn_map = fn.get(w20, {})
    for w26 in chars:
        w8 = ((w25 + ((w26 << 1) & M32)) & M32) | w22
        w0 = abs32(w8 & 0x5F7B3D)
        w8 = abs32(s32(t880[w0 % N880]))
        w0 = abs32((w8 * S - w25) & M32)
        w8 = s32(t868[w0 % N868])
        w22n = (((w8 * w25 + w22) & M32) * w22 + w25 * w25) & M32
        fn_val = fn_map[w26 & 0xFF] if isinstance(fn_map, list) else fn_map.get(w26 & 0xFF, 0)
        out.append((w22n + w26 + fn_val) & 0xFF)
        w25 = (
            1
            + ((w25 & 0xFF) if s32(w25) > 0 else ((-w25) & 0xFF))
            + ((w26 >> 1) & 0x20)
            + half75(w26)
            + abs32(w22n)
        ) & M32
    return bytes(out)


def message_law(
    blob57: bytes | list[int],
    tables: tuple[list[int], list[int], list[int]] | None = None,
    fn_tables: dict[int, list[int]] | None = None,
    p37: bytes | None = None,
    b22: bytes | None = None,
    apply_perm: bool = True,
) -> bytes:
    if len(blob57) != 57:
        raise ValueError(f"Expected 57-byte client token blob, got {len(blob57)} bytes")
    return message_from_token(
        blob57, tables=tables, fn_tables=fn_tables, p37=p37, b22=b22, apply_perm=apply_perm
    )


def produce_client_token(dsn: str | bytes) -> bytes:
    """Closed form of the 6-step producer at RVA 0x338e014."""
    if isinstance(dsn, (bytes, bytearray)):
        text = bytes(dsn).decode("utf-8")
    else:
        text = str(dsn)
    if not text:
        raise ValueError("dsn must be non-empty")

    # Step 1: UTF-16LE 16-bit code unit decimal expansion (0x338e048..0x338e254)
    raw_u16 = text.encode("utf-16-le")
    units = [int.from_bytes(raw_u16[i : i + 2], "little") for i in range(0, len(raw_u16), 2)]
    s1 = "".join(str(u) for u in units)

    # Step 2: Run-length encoding of maximal contiguous runs (0x33938c0 + 0x339248c)
    rle_parts: list[str] = []
    i = 0
    n1 = len(s1)
    while i < n1:
        ch = s1[i]
        j = i + 1
        while j < n1 and s1[j] == ch:
            j += 1
        run = j - i
        rle_parts.append(f"{run}{ch}" if run > 1 else ch)
        i = j
    s2 = "".join(rle_parts)

    # Step 3: first cyclic left rotation, then double until it's long enough (0x338e2b0..0x338e394)
    b0 = ord(s2[0])
    k1 = max(5, b0 % 30)
    rot1 = k1 % len(s2)
    s3 = s2[rot1:] + s2[:rot1]
    l0 = len(s3)
    while len(s3) + l0 < n1:
        s3 = s3 + s3

    # Step 4: Per-digit octal expansion with boundary truncation (0x3395940)
    oct_parts: list[str] = []
    last_idx = len(s3) - 1
    for idx, ch in enumerate(s3):
        d = ord(ch) - 48
        if idx < last_idx:
            oct_parts.append(oct(d)[2:])
        else:
            oct_parts.append(str(d % 8))
    s4 = "".join(oct_parts)

    # Step 5: Second cyclic left rotation (0x338e404..0x338e448)
    k2 = max(9, b0 % 40)
    rot2 = k2 % len(s4)
    s5 = s4[rot2:] + s4[:rot2]

    # Step 6: Pairwise decimal decode + 0x30 bias (0x33968d4)
    out = bytearray()
    for k in range(0, 2 * (len(s5) // 2), 2):
        out.append((int(s5[k : k + 2]) + 0x30) & 0xFF)
    return bytes(out)


def message_from_token(
    tok: bytes | list[int],
    tables: tuple[list[int], list[int], list[int]] | None = None,
    fn_tables: dict[int, list[int]] | None = None,
    p37: bytes | None = None,
    b22: bytes | None = None,
    apply_perm: bool = True,
) -> bytes:
    """General 0x33bac94 Q79 recurrence, then a parity-gated swap pass."""
    if len(tok) == 0:
        raise ValueError("Expected non-empty client token blob")

    if tables is not None:
        _t850, t868, t880 = tables
    else:
        t868, t880 = constants.T868, constants.T880

    fn = fn_tables if fn_tables is not None else constants.FN_TABLE
    p37_bytes = p37 if p37 is not None else constants.P37
    b22_bytes = b22 if b22 is not None else constants.B22

    chars_a = [b & 0xFF for b in tok]
    chars_b = [b & 0xFF for b in b22_bytes]

    pa = bytearray(_pass(chars_a, t868, t880, fn, len(chars_a), 0, 1))
    pb = bytearray(_pass(chars_b, t868, t880, fn, len(chars_b), 1, 2))

    if apply_perm:
        length_a = len(pa)
        length_b = len(pb)
        i0 = SWAP_CONST_0 % length_a
        j0 = SWAP_CONST_0 % length_b
        pa[i0], pb[j0] = pb[j0], pa[i0]
        if (length_a + length_b - 1) % 2 == 1:
            i1 = SWAP_CONST_1 % length_a
            j1 = SWAP_CONST_1 % length_b
            pa[i1], pb[j1] = pb[j1], pa[i1]

    return p37_bytes + bytes(pa) + bytes(pb)


# the 0x7e message per lock class: per serial for a CLIENT_ID-bound voucher,
# per account secret for an ACCOUNT_SECRET one, or the 2-parameter pairing
def message_for_client_id(dsn: str | bytes) -> bytes:
    return message_from_token(produce_client_token(dsn))


def message_for_account_secret(secret: str | bytes | None = "") -> bytes:
    tok = produce_client_token(secret) if secret else EMPTY_FALLBACK_20
    return message_from_token(tok)


def message_for_two_param(secret: str | bytes | None = "", dsn: str | bytes | None = "") -> bytes:
    tok_sec = produce_client_token(secret) if secret else EMPTY_FALLBACK_20
    tok_cid = produce_client_token(dsn) if dsn else EMPTY_FALLBACK_20
    return message_from_token(tok_sec, b22=tok_cid)
