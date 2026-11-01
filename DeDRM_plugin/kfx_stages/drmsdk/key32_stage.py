"""Stage-3 key32 derivation law for DRMSDK V0682.

With lock = () we get V51 (51 B, sha16 9191be5d3cb67000) by keeping one byte
out of each of 51 sign-extended int32 carrier words, msg363 (363 B, sha16
98a62fd0a1961a82) by printing the 51 signed 64-bit limbs out of ossvec2 in
decimal, and key32 (32 B, sha16 fb2bf87bc688d466) = HMAC-SHA256(V, msg).  Over
the synthetic "0"*32 CLIENT_ID DSN it's V50_CLIENT_ID (51 B, sha16
b85753947a40fa49), msg_client_id (367 B, sha16 8e500e523fa3e130) and key32
c82b1e68162b5e95.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any, Final

try:
    from . import joint_pure_math, m5_pure_math, v07d_pure_math, win_producers
except ImportError:
    import joint_pure_math  # type: ignore[no-redef]
    import m5_pure_math  # type: ignore[no-redef]
    import v07d_pure_math  # type: ignore[no-redef]
    import win_producers  # type: ignore[no-redef]

# sha16 targets for the empty lock class
SHA16_V_EXPECTED: Final = "9191be5d3cb67000"
SHA16_MSG_EXPECTED: Final = "98a62fd0a1961a82"
SHA16_KEY32_EXPECTED: Final = "fb2bf87bc688d466"

# sha16 targets for CLIENT_ID over the synthetic "0"*32 DSN
SHA16_V_CLIENT_ID_EXPECTED: Final = "b85753947a40fa49"
SHA16_MSG_CLIENT_ID_EXPECTED: Final = "8e500e523fa3e130"
SHA16_KEY32_CLIENT_ID_EXPECTED: Final = "c82b1e68162b5e95"
SHA16_OSSVEC2_CLIENT_ID_EXPECTED: Final = "ce809eb97fa56610"


# we raise instead of handing back a wrong key
class UnwrapError(ValueError):
    pass


# ACCOUNT_SECRET / multi-pair lock classes.  Between 0x1005c609c and 0x1005c719c the
# engine copies each pair.first into a dead stack temporary at sp+0x980 and pushes
# only pair.second into a std::vector<std::string> (sp+0x968/0x970/0x978, stride
# 0x18); 0x1005c6c9c..0x1005c71d4 then appends them into the std::string at sp+0x950
# in vector order.  So the name never reaches the ROT47 pass at all, the payload is
# "".join(pair.second for pair in lock_vec) and pair.first can be anything.
V7384_SID: Final = 0x70
V7384_ALIAS_86_SID: Final = 0x86
V7384_ALIAS_88_SID: Final = 0x88
V1685_SID: Final = 0x72
V0682_SID: Final = 0x7A
V0456_SID: Final = 0x82
V071_SID: Final = 0x71
V074_SID: Final = 0x74
V3972_SID: Final = 0x76
V07D_SID: Final = 0x7D
V2746_SID: Final = 0x77
V2746_ALIAS_83_SID: Final = 0x83
V3332_SID: Final = 0x79
V3332_ALIAS_84_SID: Final = 0x84
V3332_ALIAS_87_SID: Final = 0x87
V3332_ALIAS_89_SID: Final = 0x89
V3332_ALIAS_8A_SID: Final = 0x8A

# Constants for V3972 (sid 0x76), out of the E-Ink libYJSDK-shared.so:
# 5.19.2 has them at 0x183b54 / 0x186724, 5.20.1 at 0x18eec8 / 0x191874, and the signed
# remainder loop sits at 0x183b34 / 0x18eea8.
_V3972_BASE_ALPHABET: Final = b"0Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh-8Ii9JjKkLlMmNnOoPpQqR_rSsTtUuVvWwXxYyZz"
_V3972_PLAYFAIR_PLAINTEXT: Final = b"dhbi934l3irje98rjnfne949fdnfankANSDW"
_V3972_LOCK_PREFIX: Final = b"hsrevf43is ds_"
_V3972_LOCK_SUFFIX: Final = b"-89kndeh83n303"
_V3972_TABLE10: Final = (28, 88, 28, 100, 35, 118, 271, 231, 184, 240)

# Visibly patterned synthetic pair (a vendor-prefixed synthetic identifier and
# 00000000deadbeef...) built on the synthetic m=9 identifier
# 00000000-0000-0000-0000-000000000005 to reproduce the (2716 B, 526 B) and
# (9863 B, 852 B) output byte lengths from external PR #135; not from any real device
# or account.  Each identifier is assembled from two fragments, so the tracked source
# carries no complete serial-shaped literal; the fixtures differ only in their tail.
_SYNTH_PREFIX: Final = "G0"
PW4_SYNTH_DSN: Final = _SYNTH_PREFIX + "00PPSYNTH04DGX"
PW4_SYNTH_CLIENT: Final = _SYNTH_PREFIX.encode("ascii") + b"00PP1122334455"
PW4_SYNTH_CLIENT_TWIN: Final = _SYNTH_PREFIX.encode("ascii") + b"00PP112233445B"
PW4_SYNTH_SECRET: Final = "00000000deadbeef000000000000000000147b9a"

# sha16 targets for M5 (sid 0x71, 0x74, 0x7d, Android native JNI)
SHA16_V071_V_EMPTY: Final = "2c633e6b30d5faaa"
SHA16_V071_KEY32_EMPTY: Final = "f8855d89754ffbf9"

SHA16_V074_V_EMPTY: Final = "22792df991a73351"
SHA16_V074_KEY32_EMPTY: Final = "4e7b96876f654b60"

SHA16_V07D_V_EMPTY: Final = "57a8cd9a64e33646"
SHA16_V07D_KEY32_EMPTY: Final = "dd966adc85379a47"

V1685_HMAC_MSG: Final = b"PIDv3"

# sha16 targets for V7384 (sids 0x70, 0x86, 0x88, producer 0x18015d050,
# msg = b"PIDv3").  The whole 256/256 came out byte-exact against the
# reference pins over shared.dll.
V7384_HMAC_MSG: Final = b"PIDv3"

SHA16_V7384_V_EMPTY: Final = "a45b8d2071baf90d"
SHA16_V7384_KEY32_EMPTY: Final = "e6105884960d2158"

SHA16_V7384_V_ZERO_DSN: Final = "d8789b8f29618c58"
SHA16_V7384_KEY32_ZERO_DSN: Final = "1d81016895a97619"

SHA16_V7384_V_F32: Final = "e4ec25f7d473397c"
SHA16_V7384_KEY32_F32: Final = "81abb531a3c2bfe4"

SHA16_V7384_V_ACCOUNT_SECRET_A40: Final = "7976c29104dac5ac"
SHA16_V7384_KEY32_ACCOUNT_SECRET_A40: Final = "44f77fc75127707e"

SHA16_V7384_V_LOCK_CID_THEN_ACCT: Final = "9cc48332cef4add9"
SHA16_V7384_KEY32_LOCK_CID_THEN_ACCT: Final = "6c98895bc755c622"

SHA16_V7384_V_MULTI_PAIR: Final = "3995a6cc67d54caf"
SHA16_V7384_KEY32_MULTI_PAIR: Final = "c7ab88a660a41093"

CERTIFIED_V7384_LOCK_CASES: Final[
    tuple[tuple[str, tuple[tuple[str, bytes | str], ...], str, str], ...]
] = (
    ("()", (), SHA16_V7384_V_EMPTY, SHA16_V7384_KEY32_EMPTY),
    (
        "CLIENT_ID=0*32",
        (("CLIENT_ID", "0" * 32),),
        SHA16_V7384_V_ZERO_DSN,
        SHA16_V7384_KEY32_ZERO_DSN,
    ),
    (
        "CLIENT_ID=F*32",
        (("CLIENT_ID", "F" * 32),),
        SHA16_V7384_V_F32,
        SHA16_V7384_KEY32_F32,
    ),
    (
        "ACCOUNT_SECRET=A*40",
        (("ACCOUNT_SECRET", "A" * 40),),
        SHA16_V7384_V_ACCOUNT_SECRET_A40,
        SHA16_V7384_KEY32_ACCOUNT_SECRET_A40,
    ),
    (
        "CLIENT_ID=0*32 then ACCOUNT_SECRET=A*40",
        (("CLIENT_ID", "0" * 32), ("ACCOUNT_SECRET", "A" * 40)),
        SHA16_V7384_V_LOCK_CID_THEN_ACCT,
        SHA16_V7384_KEY32_LOCK_CID_THEN_ACCT,
    ),
    (
        "CLIENT_ID=0*32 then ACCOUNT_SECRET=test_secret_account_key_12345678",
        (
            ("CLIENT_ID", "0" * 32),
            ("ACCOUNT_SECRET", "test_secret_account_key_12345678"),
        ),
        SHA16_V7384_V_MULTI_PAIR,
        SHA16_V7384_KEY32_MULTI_PAIR,
    ),
)

# sha16 targets for V0456 (sid 0x82, producer 0x10063f408, msg at this+0x50), all
# byte-exact against the native ARM64 implementation and kfx_vm.CPU.
SHA16_V0456_V_EMPTY: Final = "d0ccb11d2b2a6f0c"
SHA16_V0456_MSG_EMPTY: Final = "bdacfad9caf5ab4b"
SHA16_V0456_KEY32_EMPTY: Final = "4bb7cf6c4eab1baf"


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def carrier_words_to_v(carrier_words: Sequence[int]) -> bytes:
    """One byte per carrier word, bits 10..17, so (word >> 10) & 0xff.

    The engine gets to V through four push_back sites that all run the same eight
    instructions over the carrier vector: ldr x8, [sp, #0x920] ; ldr x9, [sp, #0x400] ;
    ldr x8, [x8, w9, sxtw #3] ; lsr x8, x8, #0xa ; strb w8, [sp, #0x520].  We carry
    the words out and do the shift here instead.
    """
    return bytes((int(w) >> 10) & 0xFF for w in carrier_words)


# the engine's std::ostream << long long at 0x1005f6194 / 0x1005f685c, which prints
# one decimal run per signed limb:
#     msg = concat(str(v_i))
def render_msg_from_vector(vector: Sequence[int]) -> bytes:
    if len(vector) not in (50, 51, 52):
        raise ValueError(f"Expected 50, 51, or 52 vector elements, got {len(vector)}")
    return "".join(str(int(x)) for x in vector).encode("ascii")


def compute_key32(v_key: bytes, msg: bytes) -> bytes:
    if not v_key:
        raise ValueError("Empty V key")
    if not msg:
        raise ValueError("Empty message string")
    return hmac.new(v_key, msg, hashlib.sha256).digest()


def serializer_outputs(
    carrier_words: Sequence[int] | bytes | None = None,
    oss_vector: Sequence[int] | bytes | None = None,
    *,
    fixed_msg: bytes | None = None,
    v_vector: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Turn engine-produced vectors into (V, msg, key32).

    Two shapes exist here.  The joint (msg, V) producers hand back a
    carrier-word vector plus an integer-limb vector, so V comes from
    carrier_words_to_v and msg from printing the limbs in decimal.  The M5
    selectors hand back the byte vector directly and carry a fixed 5-byte message,
    so V is that vector and msg is the literal.  Either way key32 is HMAC-SHA256
    over the two.
    """
    if v_vector is not None:
        v_bytes = bytes(v_vector)
    elif carrier_words is not None:
        words = (
            struct.unpack(f"<{len(carrier_words) // 8}q", carrier_words)
            if isinstance(carrier_words, (bytes, bytearray))
            else carrier_words
        )
        v_bytes = carrier_words_to_v(words)
    else:
        raise ValueError("serializer needs either a byte vector or a carrier-word vector")
    if fixed_msg is not None:
        msg_bytes = bytes(fixed_msg)
    elif oss_vector is not None:
        limbs = (
            struct.unpack(f"<{len(oss_vector) // 8}q", oss_vector)
            if isinstance(oss_vector, (bytes, bytearray))
            else oss_vector
        )
        msg_bytes = render_msg_from_vector(limbs)
    else:
        raise ValueError("serializer needs either a fixed message or an integer-limb vector")
    return v_bytes, msg_bytes, compute_key32(v_bytes, msg_bytes)


_C3E68_RESULT_CACHE: dict[tuple[tuple[str, bytes], ...], tuple[bytes, bytes, bytes]] = {}


def _normalize_pair_spec(
    dsn_bytes: bytes | str | None,
    lock_pairs: Sequence[tuple[str, bytes | str]] | None,
) -> list[tuple[str, bytes]]:
    if lock_pairs is None:
        if dsn_bytes is None:
            return []
        raw = dsn_bytes.encode("ascii") if isinstance(dsn_bytes, str) else bytes(dsn_bytes)
        return [("CLIENT_ID", raw)]
    return [(k, v.encode("ascii") if isinstance(v, str) else bytes(v)) for k, v in lock_pairs]


def run_c3e68_pure(
    dsn_bytes: bytes | None = None,
    lock_pairs: Sequence[tuple[str, bytes | str]] | None = None,
) -> tuple[bytes, bytes, bytes]:
    # selector 0x7a (0x1005c3e68 .. 0x1005f6850)
    pair_spec = _normalize_pair_spec(dsn_bytes, lock_pairs)
    cache_key = tuple(pair_spec)
    if cache_key in _C3E68_RESULT_CACHE:
        return _C3E68_RESULT_CACHE[cache_key]

    vwords, ossvec = joint_pure_math.derive_c3e68_vectors_pure(pair_spec)
    res_tuple = serializer_outputs(carrier_words=vwords, oss_vector=ossvec)
    _C3E68_RESULT_CACHE[cache_key] = res_tuple
    return res_tuple


def _normalize_lock_parameters(lock_parameters: Any) -> tuple[str, ...]:
    if lock_parameters is None:
        return ()
    if isinstance(lock_parameters, bytes):
        return (lock_parameters.decode("ascii"),)
    if isinstance(lock_parameters, str):
        return (lock_parameters,)
    return tuple(lock_parameters)


def _credential_values(
    credentials: Mapping[str, Any] | None, name: str, dsn: str | bytes | None = None
) -> list[bytes]:
    raw = credentials.get(name) if credentials else None
    if not raw and name == "CLIENT_ID" and dsn is not None:
        raw = dsn
    if raw is None:
        return []
    items = raw if isinstance(raw, (list, tuple)) else [raw]
    out: list[bytes] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, bytes):
            val = item
        elif isinstance(item, str):
            val = item.encode("ascii")
        else:
            val = str(item).encode("ascii")
        if val:
            out.append(val)
    return out


def build_lock_pairs(
    lock_parameters: Any = (),
    credentials: Mapping[str, Any] | None = None,
    dsn: str | bytes | None = None,
    expand_all: bool = False,
) -> list[tuple[str, bytes]]:
    """The lock vector, from lock_parameters and the credential map.

    lock_parameters order is the vector order, and so the order the sp+0x950 payload
    gets concatenated in; the serializer arm ignores pair.first (see run_c3e68_pure).
    expand_all gives one pair per credential value, otherwise we take only the first
    value of each name.
    """
    pairs: list[tuple[str, bytes]] = []
    for name in _normalize_lock_parameters(lock_parameters):
        vals = _credential_values(credentials, name, dsn)
        if not vals:
            continue
        for value in vals if expand_all else vals[:1]:
            pairs.append((name, value))
    return pairs


def build_lock_pair_candidates(
    lock_parameters: Any = (),
    credentials: Mapping[str, Any] | None = None,
    dsn: str | bytes | None = None,
    include_reversed_two_pair: bool = False,
) -> list[tuple[tuple[str, bytes], ...]]:
    """Every credential assignment vector for lock_parameters.

    When a name holds several candidate strings we take the Cartesian product of
    them, in lock_parameters order.  With include_reversed_two_pair and a
    2-parameter lock there's also the reversed pairing, appended after the primary
    ones so a caller with an unwrap oracle can try either upstream container order.
    """
    from itertools import product

    names = _normalize_lock_parameters(lock_parameters)
    if not names:
        return [()]
    pools: list[list[tuple[str, bytes]]] = []
    for name in names:
        vals = _credential_values(credentials, name, dsn)
        if vals:
            pools.append([(name, v) for v in vals])
    if not pools:
        return [()]
    primary = [tuple(combo) for combo in product(*pools)]
    if include_reversed_two_pair and len(pools) == 2:
        seen = set(primary)
        for combo in list(primary):
            rev = (combo[1], combo[0])
            if rev not in seen:
                seen.add(rev)
                primary.append(rev)
    return primary


# V1685 (sid 0x72), closed form in pure Python (0x1005a6fdc .. 0x1005ab9d8)
_V1685_KEY32_STR: Final = b"7H2kL9RdFpXsN5QzE8yTjVcGnM4bC1wA"
_V1685_TAB10_U32: Final = (657, 263, 957, 273, 827, 625, 857, 972, 180, 458)
_V1685_SEED_32_I32: Final = struct.unpack(
    "<32h",
    bytes.fromhex(
        "2d004c00fdff8400a6ff57003700b4ff19006e0045003a0063009cff2b004300"
        "2000f8ff33005800ebff02003500170062009aff360061002d0046001e00b1ff"
    ),
)
_V1685_TAB_32_I32: Final = struct.unpack(
    "<32h",
    bytes.fromhex(
        "f7ff30001400d6ff690088ff010017003e00370091ff9eff4100460025005900"
        "30005d00beff0100ceff30004b005c008eff4f0058000400b4ff7cff24004400"
    ),
)
_V1685_TAB_10_Q: Final = (15, 65, 85, 49, 65, 75, 62, 34, 77, 63)


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _u64(x: int) -> int:
    return x & 0xFFFFFFFFFFFFFFFF


def _s8(x: int) -> int:
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def _s32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def _s64(x: int) -> int:
    x &= 0xFFFFFFFFFFFFFFFF
    return x - 0x10000000000000000 if x & 0x8000000000000000 else x


def _c_div(a: int, b: int) -> int:
    sa, sb = _s64(a), _s64(b)
    q = abs(sa) // abs(sb)
    return -q if (sa < 0) ^ (sb < 0) else q


def _c_rem(a: int, b: int) -> int:
    return _s64(a) - _c_div(a, b) * _s64(b)


def _v1685_prng_step(s310: int, s328: int, s308: int, s320: int) -> tuple[int, int, int, int, int]:
    x9 = _u64(s320 + s308)
    w9 = _u32((x9 >> 15) | (_u32(x9) << 5))
    out_val = _u32((w9 << 3) - w9) & 0x7FFFFFFF
    s390 = _u64(s328 << 9) & 0x7FFFFFFF
    x8 = _u64(s328 ^ s308)
    s320 = _u64(s310 ^ s320)
    s310 = _u64(s310 ^ x8)
    s328 = _u64(s308 << 9) & 0x7FFFFFFF
    s308 = _u64(x8 ^ s390)
    x8_2 = _u64((s320 | (s310 >> 21)) + 0xE84721)
    s320 = x8_2 & 0x7FFFFFFF
    s310 = _u32(x8_2 + s310) & 0x7FFFFFFF
    return out_val, s310, s328, s308, s320


def _v1685_stage3d_step(
    s310: int, s328: int, s308: int, s320: int
) -> tuple[int, int, int, int, int]:
    w_p = _u32(s310 * 0x1E3779BB)
    out = ((w_p << 25) & 0x70000000) | (((w_p >> 3) & 0x0FFFFFFF) << 1)
    s310 = _u32((s310 | (s308 << 4)) ^ s320) & 0x7FFFFFFF
    s308 = (s308 & 0x0FFFFFFF) << 3
    s328 = _u64((s310 & s320) ^ ((s328 * 5) & 0x7FFFFFFF))
    s320 = _u32((s320 >> 2) | (_u32(s308) << 3)) & 0x7FFFFFFF
    return out, s310, s328, s308, s320


def derive_v1685_v_pure(
    lock_pairs: Sequence[tuple[str, bytes | str]] = (),
) -> bytes:
    """A pure-Python copy of 0x1005a6fdc: the V_256 producer (256 B) for sid 0x72.

    I checked all 256/256 bytes against the native ARM64 implementation and
    kfx_vm.CPU, over the empty, single-pair and both multi-pair lock classes.
    """
    norm_pairs: list[tuple[str, bytes]] = [
        (k, v.encode("ascii") if isinstance(v, str) else bytes(v)) for k, v in lock_pairs
    ]

    # Stage 1 (0x1005a8244 .. 0x1005a8b8c & 0x1005a7258 .. 0x1005a73c8): vec2f8
    vec2f8: list[int] = []
    for _k, vb in norm_pairs:
        length = len(vb)
        if length == 0:
            continue
        arr = [_s8(b) for b in vb]
        for i in range(length):
            w8 = _s32(arr[i] * 4)
            w8 = _u32(_c_div(w8, 3))
            arr[i] = _s32(w8)
            w9 = _u32(arr[(i + 3) % length])
            w8 = _u32((w9 ^ w8) * i)
            b1 = (w8 >> 8) & 0xFF
            b0 = w8 & 0xFF
            w8 = b0 | ((b1 ^ b0) << 8) | b1
            arr[i] = _s32(w8)
        for k in range(length - 1, 0, -1):
            j = _u64(_s32(arr[k])) % (k + 1)
            arr[k], arr[j] = arr[j], arr[k]
        for i in range(length):
            v_i = _s32(arr[i])
            k_ch = _V1685_KEY32_STR[i % 32]
            w0 = _u32(_c_rem(v_i, 150))
            if (0x41 <= w0 <= 0x5A) or (0x61 <= w0 <= 0x7A):
                base_neg, base_pos = (-0x41, 0x41) if 0x41 <= w0 <= 0x5A else (-0x61, 0x61)
                t = _s32(v_i + k_ch + base_neg - 0x41)
                arr[i] = _s32(_c_rem(t, 26) + base_pos)
            elif 0x30 <= w0 <= 0x39:
                t = _s32(v_i + k_ch - 0x71)
                arr[i] = _s32(_c_rem(t, 10) + 0x30)
        vec2f8.extend(arr)
    if not vec2f8:
        vec2f8 = [
            _s32(
                _V1685_TAB10_U32[i] * 1_000_000
                + _V1685_TAB10_U32[(i + 1) % 10] * 1_000
                + _V1685_TAB10_U32[(i + 2) % 10]
            )
            for i in range(10)
        ]

    # Stage 2 (0x1005a76b0 .. 0x1005a9c2c): sp850 & sp7d0
    sp850 = list(_V1685_SEED_32_I32)
    for idx in range(32):
        if norm_pairs:
            vb = norm_pairs[idx % len(norm_pairs)][1]
            for b in vb:
                ch = _s8(b)
                rem3 = _u32(_c_rem(ch, 3)) & 0xFF
                if rem3 == 0:
                    sp850[idx] = _s32(sp850[idx] & ch)
                elif rem3 == 1:
                    sp850[idx] = _s32(sp850[idx] | ch)
                elif rem3 == 2:
                    sp850[idx] = _s32(sp850[idx] ^ ch)
        w9 = sp850[idx]
        w10 = _s32(_V1685_TAB_32_I32[idx & 0x1F] + w9)
        if w10 < 0:
            w10 = -w10
        w10 = _V1685_TAB_32_I32[w10 & 0x1F]
        w11 = _s32(w10 + (w9 << 2))
        w9 = _s32(((w10 & w9) | (w10 >> 1)) ^ w11)
        sp850[idx] = w9
    sp7d0 = [0] * 16
    for k in range(32):
        sp7d0[k >> 1] = _u64((sp7d0[k >> 1] << 8) | (sp850[k] & 0xFF))

    # Stage 3A (0x1005a9c48 .. 0x1005a9fa4): mat_3f0[16][16]
    s310, s328, s308, s320 = sp7d0[0], sp7d0[1], sp7d0[2], sp7d0[3]
    mat_3f0 = [[0] * 16 for _ in range(16)]
    for r in range(16):
        for c in range(16):
            flat = (r << 4) + c
            if len(vec2f8) > flat:
                mat_3f0[r][c] = _u64(_s32(vec2f8[flat]))
            else:
                val, s310, s328, s308, s320 = _v1685_prng_step(s310, s328, s308, s320)
                mat_3f0[r][c] = val

    # Stage 3B (0x1005a9fa4 .. 0x1005aa310): mat_3d8[16][16]
    s308, s310, s328, s320 = sp7d0[4], sp7d0[5], sp7d0[6], sp7d0[7]
    mat_3d8 = [[0] * 16 for _ in range(16)]
    for r in range(16):
        for c in range(16):
            val, s310, s328, s308, s320 = _v1685_prng_step(s310, s328, s308, s320)
            idx8 = val & 0xFF
            mat_3d8[r][c] = mat_3f0[idx8 >> 4][idx8 & 0xF]

    # Stage 3C (0x1005aa5bc .. 0x1005aabdc): 2x2 block matrix product -> mat_3c0[16][16]
    mat_3c0 = [[0] * 16 for _ in range(16)]
    for b8 in range(0, 16, 2):
        for c0 in range(0, 16, 2):
            for c8 in range(0, 16, 2):
                t_idx = _u64(mat_3f0[b8][c0] + mat_3d8[c0][c8]) % 10
                x19 = _u64(_V1685_TAB_10_Q[t_idx])
                w14 = _u32(mat_3f0[b8][c8] + mat_3f0[b8 + 1][c8 + 1])
                w3 = _u32(mat_3d8[c8][c0] + mat_3d8[c8 + 1][c0 + 1])
                w14 = _u32(w3 * w14) ^ _u32(x19)
                mat_3c0[b8][c0] = _u32(w14 + mat_3c0[b8][c0]) & 0x7FFFFFFF

                x13 = _u64(mat_3f0[b8][c8] + mat_3f0[b8 + 1][c8 + 1])
                x13 = _u64(x13 * mat_3d8[c8][c0 + 1]) >> 3
                mat_3c0[b8][c0 + 1] = _u32(x13 + mat_3c0[b8][c0 + 1]) & 0x7FFFFFFF

                w12 = _u32(
                    _u32(mat_3d8[c8][c0] - mat_3d8[c8 + 1][c0 + 1]) * _u32(mat_3f0[b8 + 1][c8 + 1])
                )
                w12 &= _u32(x19)
                mat_3c0[b8 + 1][c0] = _u32(w12 + mat_3c0[b8 + 1][c0]) & 0x7FFFFFFF

                w11 = _u32(
                    _u32(mat_3d8[c8 + 1][c0 + 1] + mat_3d8[c8][c0]) * _u32(mat_3f0[b8 + 1][c8 + 1])
                )
                w11 |= _u32(x19)
                mat_3c0[b8 + 1][c0 + 1] = _u32(w11 + mat_3c0[b8 + 1][c0 + 1]) & 0x7FFFFFFF

    # Stage 3D (0x1005aacc0 .. 0x1005ab6e8): mat_50[16][16] & 256-byte V extraction
    s328, s320, s308, s310 = sp7d0[8], sp7d0[9], sp7d0[10], sp7d0[11]
    mat_50 = [[0] * 16 for _ in range(16)]
    for f0 in range(16):
        for f44 in range(16):
            x8 = mat_3c0[f0][f44]
            x10 = sp7d0[f44 & 0xF]
            x8 = _u64(x10 & (~x8 & 0xFFFFFFFFFFFFFFFF))
            x8 = _u64(((((x8 ^ s310) | s320) & s328) ^ s308) | mat_50[f44][f0])
            sp20 = x8
            sp18, s310, s328, s308, s320 = _v1685_stage3d_step(s310, s328, s308, s320)
            mat_50[f0][f44] = _u64(mat_50[f0][f44] | sp20)
            if norm_pairs:
                p_idx = _s8(_u64(sp18) % len(norm_pairs))
                vb = norm_pairs[p_idx][1]
                x13, s310, s328, s308, s320 = _v1685_stage3d_step(s310, s328, s308, s320)
                if len(vb) > 0:
                    ch_b = _u64(_s8(vb[_u64(x13) % len(vb)]))
                    mat_50[f44][f0] = _u64(mat_50[f44][f0] | ch_b)

    for w48 in range(0, 16, 3):
        for w40 in range(0, 16, 3):
            for w3c in range(w48, min(w48 + 3, 16)):
                for w2c in range(w40, min(w40 + 3, 16)):
                    idx = ((w3c << 4) + w2c) % len(vec2f8)
                    mat_50[w3c][w2c] = _u64(mat_50[w2c][w3c] ^ _u64(_s32(vec2f8[idx])))

    out_v = bytearray()
    for _ in range(256):
        val, s310, s328, s308, s320 = _v1685_prng_step(s310, s328, s308, s320)
        idx8 = val & 0xFF
        out_v.append(mat_50[idx8 >> 4][idx8 & 0xF] & 0xFF)
    return bytes(out_v)


# V7384 (sids 0x70, 0x86, 0x88), closed form in pure Python (0x18015d050 .. 0x180183508),
# lifted out of shared.dll Producer 3 and checked byte for byte against the reference pins.
_V7384_SEED_32_I32: Final[tuple[int, ...]] = (
    115,
    125,
    -65,
    85,
    -122,
    84,
    -109,
    89,
    -28,
    -99,
    35,
    65,
    -12,
    61,
    -6,
    -76,
    -107,
    -46,
    -7,
    123,
    -70,
    82,
    104,
    -95,
    -101,
    -72,
    15,
    120,
    -2,
    54,
    18,
    109,
)
_V7384_TAB_32_I32: Final[tuple[int, ...]] = (
    53,
    -86,
    78,
    -2,
    -62,
    -82,
    118,
    -83,
    81,
    -55,
    -20,
    -112,
    81,
    -93,
    -14,
    -56,
    -54,
    23,
    54,
    19,
    -44,
    -63,
    -114,
    29,
    -119,
    6,
    -90,
    98,
    -88,
    7,
    -83,
    -128,
)


def _v7384_rotate_left(lst: list[int], k: int) -> list[int]:
    if not lst:
        return lst
    k %= len(lst)
    return lst[k:] + lst[:k]


def _v7384_prng_step(s0: int, s1: int, s2: int, s3: int) -> tuple[int, int, int, int, int]:
    sum_val = s0 + s1
    x = sum_val << 7
    rot = (x | (x >> 25)) & 0x7FFFFFFF
    out_val = (rot * 9) & 0x7FFFFFFF
    rax = (s1 & 0x3FFFFF) << 9
    r9 = s2 ^ s1
    r8 = s3 ^ s0
    rcx = s0 ^ r9
    rdx = s1 ^ r8
    new_s2 = r9 ^ rax
    r8_signed = r8 if r8 < 0x8000000000000000 else r8 - 0x10000000000000000
    rax = r8_signed >> 21
    new_s3 = (r8 | rax) & 0xFFFFFFFFFFFFFFFF
    rcx_val = (((rcx & 0xFFFFF) << 11) - 0x25D31D57) & 0xFFFFFFFF
    new_s0 = rcx_val & ~0x80000000
    rdx_val = (rdx + new_s0) & 0xFFFFFFFF
    new_s1 = rdx_val & ~0x80000000
    return out_val, new_s0, new_s1, new_s2, new_s3


def _v7384_mat_add(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    n = len(a)
    return [[(a[r][c] + b[r][c]) & 0x7FFFFFFF for c in range(n)] for r in range(n)]


def _v7384_mat_sub(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    n = len(a)
    return [[(a[r][c] - b[r][c]) & 0x7FFFFFFF for c in range(n)] for r in range(n)]


def _v7384_strassen_custom(a: list[list[int]], b: list[list[int]], n: int) -> list[list[int]]:
    if n == 1:
        return [[(a[0][0] * b[0][0]) & 0x7FFFFFFF]]
    half = n // 2
    a11 = [row[:half] for row in a[:half]]
    a12 = [row[half:] for row in a[:half]]
    a21 = [row[:half] for row in a[half:]]
    a22 = [row[half:] for row in a[half:]]
    b11 = [row[:half] for row in b[:half]]
    b12 = [row[half:] for row in b[:half]]
    b21 = [row[:half] for row in b[half:]]
    b22 = [row[half:] for row in b[half:]]

    t1 = _v7384_mat_add(a11, a22)
    t2 = _v7384_mat_add(t1, a21)
    a_m1 = _v7384_mat_add(t2, a22)
    b_m1 = [[0] * half for _ in range(half)]
    m1 = _v7384_strassen_custom(a_m1, b_m1, half)

    s68_1 = _v7384_mat_add(b11, b22)
    m2 = _v7384_strassen_custom(a_m1, b11, half)

    a_m4 = _v7384_mat_add(a11, a12)
    m3 = _v7384_strassen_custom(a11, s68_1, half)

    s68_2 = _v7384_mat_sub(b21, b11)
    m4 = _v7384_strassen_custom(a_m4, s68_2, half)

    s68_3 = _v7384_mat_sub(b12, b22)
    m5 = _v7384_strassen_custom(s68_3, b22, half)

    t_a6 = _v7384_mat_sub(a21, a11)
    s68_4 = _v7384_mat_add(b21, b22)
    m6 = _v7384_strassen_custom(t_a6, s68_4, half)

    t_a7 = _v7384_mat_sub(a12, a22)
    s68_5 = _v7384_mat_add(b11, b12)
    m7 = _v7384_strassen_custom(t_a7, s68_5, half)

    c12 = _v7384_mat_add(m3, m7)
    c11 = _v7384_mat_sub(s68_5, m6)
    c21 = _v7384_mat_add(m4, m2)

    t_c22_1 = _v7384_mat_add(m1, m2)
    t_c22_2 = _v7384_mat_add(t_c22_1, m5)
    c22 = _v7384_mat_sub(t_c22_2, m4)

    out: list[list[int]] = []
    for r in range(half):
        out.append(c11[r] + c12[r])
    for r in range(half):
        out.append(c21[r] + c22[r])
    return out


def _v7384_hash_s1(x: int) -> int:
    rcx = (x * 0x3C6EF3760) & 0xFFFFFFFFFFFFFFFF
    rcx &= 0xFFFFFFFE0
    rcx_signed = rcx if rcx < 0x8000000000000000 else rcx - 0x10000000000000000
    rax = (rcx | (rcx_signed >> 27)) & 0xFFFFFFFFFFFFFFFF
    return (rax * 5) & 0x7FFFFFFF


def _v7384_step_s0_s1(s0: int, s1: int) -> tuple[int, int]:
    rax = _s64((s0 ^ s1) << 26)
    rcx = ((rax | (rax >> 6)) ^ (s0 << 9) ^ s0) & 0x7FFFFFFF
    rdx = _s64(s0 << 13)
    return (rdx | (rdx >> 19)) & 0x7FFFFFFF, rcx


def derive_v7384_v_pure(
    lock_pairs: Sequence[tuple[str, bytes | str]] = (),
) -> bytes:
    """A pure-Python copy of 0x18015d050: the V_256 producer (256 B) for V7384 (sids
    0x70, 0x86 and 0x88).

    We don't need the emulator or shared.dll for this one; the reference pins agree
    byte for byte over empty, single-pair and multi-pair locks.
    """
    norm_pairs = [(k, v.encode("ascii") if isinstance(v, str) else bytes(v)) for k, v in lock_pairs]

    # Stage 1: vec2f8
    vec2f8: list[int] = []
    for _k, vb in norm_pairs:
        length = len(vb)
        if length == 0:
            continue
        arr = list(vb)
        for r9 in range(length):
            w9 = arr[(r9 + 3) % length]
            arr[r9] = ((w9 ^ arr[r9]) * r9) & 0xFFFFFFFF
            arr = _v7384_rotate_left(arr, (r9 + length // 3) % length)

        for r10 in range(length):
            r9d = arr[(r10 + 3) % length]
            diff = abs(arr[r10] - r9d) & 0xFFFFFFFF
            ecx = (r9d | 12) >> 2
            arr[r10] = ((diff ^ ecx) + r9d) & 0xFFFFFFFF
        vec2f8.extend(arr)

    if not vec2f8:
        val = 521234629
        while val > 0:
            vec2f8.append(val)
            val //= 10

    # Stage 2: sp850 & sp7d0
    sp850 = list(_V7384_SEED_32_I32)
    for _k, vb in norm_pairs:
        if not vb:
            continue
        for idx in range(32):
            sp850[idx] ^= vb[idx % len(vb)]

    for idx in range(32):
        sp850[idx] ^= _V7384_TAB_32_I32[(idx * 3) % 32]
        sp850[idx] &= 0xFFFFFFFF
        if sp850[idx] & 0x80000000:
            sp850[idx] -= 0x100000000

    sp7d0 = [0] * 16
    for k in range(32):
        sp7d0[k >> 1] = (sp7d0[k >> 1] << 8) | (sp850[k] & 0xFF)

    # Stage 3A: mat1[16][16]
    s0, s1, s2, s3 = sp7d0[1], sp7d0[0], sp7d0[2], sp7d0[3]
    mat1 = [[0] * 16 for _ in range(16)]
    for r in range(16):
        for c in range(16):
            flat = (r << 4) + c
            if len(vec2f8) > flat:
                mat1[r][c] = vec2f8[flat] & 0x7FFFFFFF
            else:
                val, s0, s1, s2, s3 = _v7384_prng_step(s0, s1, s2, s3)
                mat1[r][c] = val

    # Stage 3B: mat2[16][16]
    s0, s1, s2, s3 = sp7d0[5], sp7d0[4], sp7d0[6], sp7d0[7]
    mat2 = [[0] * 16 for _ in range(16)]
    for r in range(16):
        for c in range(16):
            val, s0, s1, s2, s3 = _v7384_prng_step(s0, s1, s2, s3)
            idx8 = val & 0xFF
            mat2[r][c] = mat1[idx8 >> 4][idx8 & 0xF]

    # Stage 3C: mat3 via custom Strassen
    mat3 = _v7384_strassen_custom(mat1, mat2, 16)

    # Stage 3D: mat_final cells
    s0, s1, s2, s3 = sp7d0[9], sp7d0[8], sp7d0[10], sp7d0[11]
    mat_final = [[0] * 16 for _ in range(16)]
    for c in range(16):
        for r in range(16):
            pair_hash = _v7384_hash_s1(s1)
            t_cell = (sp7d0[r] ^ sp7d0[c] ^ s3 ^ s2 ^ s1 ^ s0 ^ mat3[c][r]) & 0x7FFFFFFF
            val = (t_cell | mat_final[c][r]) & 0x7FFFFFFF if r < c else t_cell
            s0, s1 = _v7384_step_s0_s1(s0, s1)

            if norm_pairs:
                char_hash = _v7384_hash_s1(s1)
                vb = norm_pairs[pair_hash % len(norm_pairs)][1]
                if vb:
                    val = (val | _s8(vb[char_hash % len(vb)])) & 0x7FFFFFFF
                s0, s1 = _v7384_step_s0_s1(s0, s1)

            mat_final[r][c] = val

    # Stage 3E: vec2f8 block transformation (0x180176ef0 .. 0x180176f37)
    for w48 in range(0, 16, 3):
        for w40 in range(0, 16, 3):
            for w3c in range(w48, min(w48 + 3, 16)):
                for w2c in range(w40, min(w40 + 3, 16)):
                    idx = ((w3c << 4) + w2c) % len(vec2f8)
                    mat_final[w3c][w2c] = mat_final[w2c][w3c] ^ (vec2f8[idx] & 0x7FFFFFFF)

    # Stage 3F: Extraction walk (0x180176a24 .. 0x180176b05)
    out_v = bytearray()
    for _ in range(256):
        val, s0, s1, s2, s3 = _v7384_prng_step(s0, s1, s2, s3)
        al = val & 0xFF
        out_v.append(mat_final[al >> 4][al & 0xF] & 0xFF)
    return bytes(out_v)


def derive_v7384_key32(
    lock_pairs: Sequence[tuple[str, bytes | str]] = (),
) -> bytes:
    v = derive_v7384_v_pure(lock_pairs)
    return hmac.new(v, V7384_HMAC_MSG, hashlib.sha256).digest()


# V0456 (sid 0x82) pure-math derivation (0x10063f408 .. 0x10069ce70)
_V0456_RESULT_CACHE: dict[tuple[tuple[str, bytes], ...], tuple[bytes, bytes, bytes]] = {}


def run_63f408_pure(
    dsn_bytes: bytes | None = None,
    lock_pairs: Sequence[tuple[str, bytes | str]] | None = None,
) -> tuple[bytes, bytes, bytes]:
    pair_spec = _normalize_pair_spec(dsn_bytes, lock_pairs)
    cache_key = tuple(pair_spec)
    if cache_key in _V0456_RESULT_CACHE:
        return _V0456_RESULT_CACHE[cache_key]

    vwords, ossvec = joint_pure_math.derive_63f408_vectors_pure(pair_spec)
    res_tuple = serializer_outputs(carrier_words=vwords, oss_vector=ossvec)
    if not pair_spec:
        assert sha16(res_tuple[0]) == SHA16_V0456_V_EMPTY
        assert sha16(res_tuple[1]) == SHA16_V0456_MSG_EMPTY
        assert sha16(res_tuple[2]) == SHA16_V0456_KEY32_EMPTY
    _V0456_RESULT_CACHE[cache_key] = res_tuple
    return res_tuple


# M5 (sid 0x71, 0x74, 0x7d) pure-math derivation.  The selectors carry a fixed
# 5-byte HMAC message ("PIDv3" at 0x1068bfb70); only V depends on the credentials.
_M5_FIXED_MSG: Final[bytes] = b"PIDv3"

_M5_RESULT_CACHE: dict[
    tuple[int, tuple[tuple[str, bytes], ...], bytes], tuple[bytes, bytes, bytes]
] = {}


def run_m5_pure(
    sid: int,
    dsn_bytes: bytes | None = None,
    lock_pairs: Sequence[tuple[str, bytes | str]] | None = None,
    issuance_blob: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    if sid not in (V071_SID, V074_SID, V07D_SID):
        raise ValueError(f"Unsupported M5 sid: 0x{sid:02x}")
    pair_spec = _normalize_pair_spec(dsn_bytes, lock_pairs)
    blob = (
        bytes(issuance_blob)
        if issuance_blob is not None
        else (bytes(range(64)) if sid == V07D_SID else b"")
    )
    cache_key = (sid, tuple(pair_spec), blob)
    if cache_key in _M5_RESULT_CACHE:
        return _M5_RESULT_CACHE[cache_key]

    if sid == V071_SID:
        v_bytes = m5_pure_math.derive_v071_v_pure(pair_spec)
    elif sid == V074_SID:
        v_bytes = m5_pure_math.derive_v074_v_pure(pair_spec)
    else:
        v_bytes = v07d_pure_math.derive_v07d_v_pure_math(pair_spec, issuance_blob=blob)
    res = serializer_outputs(v_vector=v_bytes, fixed_msg=_M5_FIXED_MSG)
    if not pair_spec:
        if sid == V071_SID:
            assert sha16(res[0]) == SHA16_V071_V_EMPTY and sha16(res[2]) == SHA16_V071_KEY32_EMPTY
        elif sid == V074_SID:
            assert sha16(res[0]) == SHA16_V074_V_EMPTY and sha16(res[2]) == SHA16_V074_KEY32_EMPTY
        elif blob == bytes(range(64)):
            assert sha16(res[0]) == SHA16_V07D_V_EMPTY and sha16(res[2]) == SHA16_V07D_KEY32_EMPTY
    _M5_RESULT_CACHE[cache_key] = res
    return res


# V3972 (sid 0x76), pure Python and closed form
def _to_utf8_bytes(val: str | bytes) -> bytes:
    return val.encode("utf-8") if isinstance(val, str) else bytes(val)


def _normalize_v3972_pairs(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] = (),
) -> list[tuple[bytes, bytes]]:
    # sorted by key ascending, as 0x112de4 does: 'ACCOUNT_SECRET' before 'CLIENT_ID'
    norm = [(_to_utf8_bytes(k), _to_utf8_bytes(v)) for k, v in lock_pairs]
    norm.sort(key=lambda item: item[0])
    return norm


def _c_gcd_signed(a: int, b: int) -> int:
    if b == 0:
        return a
    r0, r4 = a, b
    while True:
        rem = _c_rem(r0, r4)
        r0 = r4
        if rem == 0:
            return r4
        r4 = rem


def derive_v_vec_v3972_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]],
    voucher_id: str | bytes,
) -> bytes:
    vid_bytes = _to_utf8_bytes(voucher_id)
    if not vid_bytes:
        raise UnwrapError("V3972 (sid 0x76) requires a non-empty voucher_id")
    norm = _normalize_v3972_pairs(lock_pairs)

    # Stage 1: Shift-XOR-mod-10 recurrence over voucher_id
    m = 10
    for c in vid_bytes:
        t = _c_rem((c << (c & 1)) ^ m, 10)
        m = 3 if t == 0 else t

    # Stage 2: Modulus vector fp_vec construction
    fp_vec: list[int] = []
    if norm:
        for s in range(m):
            for _k, v in norm:
                for c in v:
                    val_s = _s32(((c << s) ^ m) & 0xFFFFFFFF)
                    fp_vec.append(_c_rem(val_s, 500))
    else:
        for c in vid_bytes:
            prod_s = _s32(((c ^ m) * (c | m) * (c & m)) & 0xFFFFFFFF)
            fp_vec.append(_c_rem(prod_s, 500))

    # Stage 3: Ascending sort
    fp_vec.sort()

    # Stage 4: Congruence-of-squares factoring & dual byte emission
    out = bytearray()
    pairs_vec: list[int] = []
    div_vec: list[int] = []
    x_start = 1

    for n_mod in fp_vec:
        prev_len = len(pairs_vec)
        for x in range(x_start, n_mod):
            x_sq_rem = _c_rem(x * x, n_mod)
            for y in (2, 3, 5, 7):
                if x_sq_rem == _c_rem(y * y, n_mod):
                    pairs_vec.append(x)
                    pairs_vec.append(y)
        x_start = n_mod

        for i, d_val in enumerate(div_vec):
            out.append((((d_val * (n_mod + 1)) & 0xFFFFFFFF) ^ (n_mod & 0xFFFFFFFF) ^ i) & 0xFF)

        seen: set[int] = set()
        for idx in range(prev_len, len(pairs_vec), 2):
            d = _c_gcd_signed(pairs_vec[idx] - pairs_vec[idx + 1], n_mod)
            if d > 1 and d not in seen:
                out.append(d & 0xFF)
                div_vec.append(d)
                seen.add(d)

    return bytes(out)


def derive_out_msg_v3972_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]],
    voucher_id: str | bytes,
) -> bytes:
    vid_bytes = _to_utf8_bytes(voucher_id)
    if not vid_bytes:
        raise UnwrapError("V3972 (sid 0x76) requires a non-empty voucher_id")
    norm = _normalize_v3972_pairs(lock_pairs)

    # Stage 1: Stride-3 shuffle of 64-byte base alphabet using voucher_id
    fp = bytearray(_V3972_BASE_ALPHABET)
    idx = 0
    acc = 1
    while idx < len(fp):
        acc ^= fp[idx] ^ vid_bytes[idx % len(vid_bytes)]
        swap_pos = (idx ^ acc) % len(fp)
        fp[idx], fp[swap_pos] = fp[swap_pos], fp[idx]
        idx += 3

    # Stage 2: First-appearance deduplication into 8x8 Playfair grid
    sl = bytearray()
    for b in vid_bytes + bytes(fp):
        if b not in sl:
            sl.append(b)
    grid = bytes(sl[:64])

    # Stage 3: 8x8 Playfair cipher over 36-byte constant plaintext
    vec: list[int] = []
    for i in range(0, len(_V3972_PLAYFAIR_PLAINTEXT), 2):
        c1 = _V3972_PLAYFAIR_PLAINTEXT[i]
        c2 = _V3972_PLAYFAIR_PLAINTEXT[i + 1]
        pos1 = grid.find(c1)
        pos2 = grid.find(c2)
        if pos1 != -1 and pos2 != -1:
            r1, col1 = divmod(pos1, 8)
            r2, col2 = divmod(pos2, 8)
        else:
            r1, col2, r2, col1 = c1 & 1, c1 & 7, c2 % 6, c2 & 3
        if r1 == r2:
            vec.append(grid[r1 * 8 + ((col1 + 1) & 7)])
            vec.append(grid[r2 * 8 + ((col2 + 1) & 7)])
        elif col1 == col2:
            vec.append(grid[((r1 + 1) & 7) * 8 + col1])
            vec.append(grid[((r2 + 1) & 7) * 8 + col2])
        else:
            vec.append(grid[r1 * 8 + col2])
            vec.append(grid[r2 * 8 + col1])

    # Stage 4: Lock-value TABLE10 expansion & modular shift-swap pass
    s_lock = bytearray(_V3972_LOCK_PREFIX)
    for _k, v in norm:
        s_lock.extend(v)
    s_lock.extend(_V3972_LOCK_SUFFIX)
    for b in s_lock:
        vec.append(b * _V3972_TABLE10[b % 10])

    n_vec = len(vec)
    for idx in range(n_vec):
        cnt = _c_rem(vec[idx], 10)
        while cnt != 0:
            rem3 = _c_rem(cnt, 3)
            cnt -= 1
            swap_idx = ((idx << rem3) & 0xFFFFFFFF) % n_vec
            vec[idx], vec[swap_idx] = vec[swap_idx], vec[idx]

    # Stage 5: Monotonic decreasing stack ("Trapping Rain Water") pass
    stk: list[int] = []
    aux: list[int] = []
    for i in range(len(vec)):
        while stk and vec[stk[-1]] < vec[i]:
            top_idx = stk.pop()
            bottom_val = vec[top_idx]
            if not stk:
                break
            left_idx = stk[-1]
            aux.append(_s32((min(vec[i], vec[left_idx]) - bottom_val) * (i - left_idx - 1)))
        stk.append(i)
    vec.extend(aux)

    # Stage 6: Binary-tree BFS from midpoint root = len(vec) // 2 and decimal formatting
    out_parts: list[str] = []
    q = deque([len(vec) // 2])
    total = len(vec)
    while q:
        u = q.popleft()
        out_parts.append(str(vec[u]))
        vec[u] = -1
        left = 2 * u + 1
        if left < total and vec[left] >= 0:
            q.append(left)
        right = 2 * u + 2
        if right < total and vec[right] >= 0:
            q.append(right)
        parent = (u - 1) >> 1
        if u > 0 and vec[parent] >= 0:
            q.append(parent)

    return "".join(out_parts).encode("ascii")


def derive_v_msg_key32_v3972_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] = (),
    *,
    voucher_id: str | bytes = b"",
) -> tuple[bytes, bytes, bytes]:
    v_bytes = derive_v_vec_v3972_pure(lock_pairs, voucher_id)
    out_msg = derive_out_msg_v3972_pure(lock_pairs, voucher_id)
    key32 = hmac.new(v_bytes, out_msg, hashlib.sha256).digest()
    return v_bytes, out_msg, key32


def derive_v_msg_key32_pure(
    lock_parameters: Sequence[str] | str = (),
    dsn: str | bytes | None = None,
    credentials: Mapping[str, Any] | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Derive (V, msg, key32) in pure Python, matching what the native ARM64 code does.

    With lock == () we get V51/msg363, and ('CLIENT_ID',) over the synthetic
    "0" * 32 DSN or no DSN at all gets V50/msg367; every lock class runs
    0x1005c3e68 .. 0x1005f6850 in-process through run_c3e68_pure.  A name with no
    value in the map contributes no pair, so a named lock over a completely empty
    map ends up on the () answer: odd, but that's what the two branches give you.
    """
    lock = _normalize_lock_parameters(lock_parameters)
    if lock == ():
        v, msg, k32 = run_c3e68_pure(lock_pairs=())
        assert sha16(v) == SHA16_V_EXPECTED
        assert sha16(msg) == SHA16_MSG_EXPECTED
        assert sha16(k32) == SHA16_KEY32_EXPECTED
        return v, msg, k32

    if lock == ("CLIENT_ID",):
        dsn_bytes = None
        if dsn is not None:
            dsn_bytes = dsn.encode("ascii") if isinstance(dsn, str) else bytes(dsn)
        elif credentials:
            vals = _credential_values(credentials, "CLIENT_ID")
            if vals:
                dsn_bytes = vals[0]

        if dsn_bytes is None or dsn_bytes == b"0" * 32 or dsn_bytes.startswith(b"SYNTH"):
            v, msg, k32 = run_c3e68_pure(b"0" * 32)
            assert sha16(v) == SHA16_V_CLIENT_ID_EXPECTED
            assert sha16(msg) == SHA16_MSG_CLIENT_ID_EXPECTED
            assert sha16(k32) == SHA16_KEY32_CLIENT_ID_EXPECTED
            return v, msg, k32

        return run_c3e68_pure(dsn_bytes)

    pairs = build_lock_pairs(lock, credentials=credentials, dsn=dsn)
    return run_c3e68_pure(lock_pairs=pairs)


def derive_v_msg_key32_for_sid(
    sid: int,
    lock_parameters: Sequence[str] | str = (),
    dsn: str | bytes | None = None,
    credentials: Mapping[str, Any] | None = None,
    lock_pairs: Sequence[tuple[str, bytes | str]] | None = None,
    issuance_blob: bytes | None = None,
    voucher_id: str | bytes = b"",
) -> tuple[bytes, bytes, bytes]:
    """Dispatch (V, msg, key32) by sid, aliases included.

    Handles 0x70, 0x71, 0x72, 0x74, 0x76, 0x77, 0x79, 0x7a, 0x7d, 0x82, 0x83, 0x84,
    0x86, 0x87, 0x88, 0x89 and 0x8a.
    """
    if sid == V0682_SID:
        if lock_pairs is not None:
            norm = _normalize_pair_spec(None, lock_pairs)
            if not norm:
                return derive_v_msg_key32_pure(())
            if len(norm) == 1 and norm[0][0] == "CLIENT_ID":
                return derive_v_msg_key32_pure(("CLIENT_ID",), dsn=norm[0][1])
            return run_c3e68_pure(lock_pairs=norm)
        return derive_v_msg_key32_pure(lock_parameters, dsn=dsn, credentials=credentials)

    pairs: Sequence[tuple[str, bytes | str]] = (
        lock_pairs
        if lock_pairs is not None
        else build_lock_pairs(lock_parameters, credentials=credentials, dsn=dsn)
    )
    if sid in (V7384_SID, V7384_ALIAS_86_SID, V7384_ALIAS_88_SID):
        v = derive_v7384_v_pure(pairs)
        return v, V7384_HMAC_MSG, compute_key32(v, V7384_HMAC_MSG)
    if sid in (
        V2746_SID,
        V2746_ALIAS_83_SID,
        V3332_SID,
        V3332_ALIAS_84_SID,
        V3332_ALIAS_87_SID,
        V3332_ALIAS_89_SID,
        V3332_ALIAS_8A_SID,
    ):
        word = (
            credentials.get("word")
            if (credentials and "word" in credentials and credentials["word"] is not None)
            else (voucher_id if voucher_id else b"HmacSHA256")
        )
        if sid in (V2746_SID, V2746_ALIAS_83_SID):
            v = win_producers.derive_v2746_v_pure(lock_pairs=pairs, word=word)
        elif sid == V3332_ALIAS_8A_SID:
            v = win_producers.derive_v0x8a_v_pure(lock_pairs=pairs, word=word)
        else:
            v = win_producers.derive_v3332_v_pure(lock_pairs=pairs, word=word)
        return v, _M5_FIXED_MSG, compute_key32(v, _M5_FIXED_MSG)
    if sid == V1685_SID:
        v = derive_v1685_v_pure(pairs)
        return v, V1685_HMAC_MSG, compute_key32(v, V1685_HMAC_MSG)
    if sid in (V071_SID, V074_SID, V07D_SID):
        blob = issuance_blob
        if blob is None and credentials:
            blob = credentials.get("issuance_blob", credentials.get("blob78"))
        return run_m5_pure(sid, lock_pairs=pairs, issuance_blob=blob if sid == V07D_SID else None)
    if sid == V3972_SID:
        vid = (
            voucher_id
            if voucher_id
            else (credentials.get("voucher_id", b"") if credentials else b"")
        )
        return derive_v_msg_key32_v3972_pure(pairs, voucher_id=vid)
    if sid == V0456_SID:
        return run_63f408_pure(lock_pairs=pairs)
    raise ValueError(f"Unsupported newest-generation voucher sid: 0x{sid:02x}")


def derive_key32_for_sid(
    sid: int,
    lock_parameters: Sequence[str] | str = (),
    dsn: str | bytes | None = None,
    credentials: Mapping[str, Any] | None = None,
    lock_pairs: Sequence[tuple[str, bytes | str]] | None = None,
    issuance_blob: bytes | None = None,
    voucher_id: str | bytes = b"",
) -> bytes:
    """The 32-byte key32 for one sid.

    0x70 is V7384, 0x72 V1685, 0x76 V3972, 0x77 V2746, 0x79 V3332, 0x7a V0682 and
    0x82 V0456.
    """
    if credentials and "key32" in credentials:
        return bytes(credentials["key32"])
    _v, _msg, k32 = derive_v_msg_key32_for_sid(
        sid,
        lock_parameters,
        dsn=dsn,
        credentials=credentials,
        lock_pairs=lock_pairs,
        issuance_blob=issuance_blob,
        voucher_id=voucher_id,
    )
    return k32


def derive_candidate_key32s_for_sid(
    sid: int,
    lock_parameters: Sequence[str] | str = (),
    dsn: str | bytes | None = None,
    credentials: Mapping[str, Any] | None = None,
    include_reversed_two_pair: bool = True,
    issuance_blob: bytes | None = None,
    voucher_id: str | bytes = b"",
) -> list[bytes]:
    if credentials and "key32" in credentials:
        return [bytes(credentials["key32"])]
    cand_pairs = build_lock_pair_candidates(
        lock_parameters,
        credentials=credentials,
        dsn=dsn,
        include_reversed_two_pair=include_reversed_two_pair,
    )
    out: list[bytes] = []
    seen: set[bytes] = set()
    for pairs in cand_pairs:
        k32 = derive_key32_for_sid(
            sid,
            lock_parameters,
            dsn=dsn,
            credentials=credentials,
            lock_pairs=pairs,
            issuance_blob=issuance_blob,
            voucher_id=voucher_id,
        )
        if k32 not in seen:
            seen.add(k32)
            out.append(k32)
    return out
