# kfx_stages package layout and stage architecture

This subpackage holds the key-derivation modules for the plugin's own KFX path,
the module that routes an envelope to them, and the relational container reader.
This file maps the modules, records the stage status and closed-form architecture,
and documents the inlined static table constants they read.

## Layout

| area | modules | contents |
| --- | --- | --- |
| app-generation family | whitebox/ (13 modules) | stages 1..11 (token to M1 to seed) plus closed-form 2-layer AES-256-CBC unwrap (K_C0_0X7E / M32_DEFAULT_0X7E) |
| newest and desktop families | drmsdk/ (9 modules) | stage-3 key32, closed-form V producers, and closed-form 2-layer AES-256-CBC unwrap (K_C0_BY_SID, K_0X85_BY_SID, M32_DEFAULT_BY_SID) |
| envelope routing | drmsdk/voucher_route.py | envelope parse, tag classification, envelope MAC and six checks, stage-operand derivation, 2-layer AES-256-CBC and 0x85 unwrap dispatch |
| Ion reader | _ion.py | binary Ion 1.0 reader and KeySet@1.0 key extraction |
| envelope pages | _envelope.py | envelope classification and page discovery, including _page_plain and first_encrypted_page |
| relational container | container.py | container detection, fingerprint records, row decryption in memory, scrub_delivery |
| crypto shim | _aes.py | AES-CBC backend selection (aes_cbc_decrypt, aes_cbc_encrypt) and the named error raised when no backend imports |
| routing entry | __init__.py | classify, derive, derive_auto, verify_page |
| self-test | selftest.py | one section per entry point, run against the inlined constants |

whitebox/, in stage order: identity.py (recipient class constant),
message.py (116-byte message from the 57-byte token), lcg.py (byte stream and
vector B), verdict.py (state, mixing, fills tensor), k_law.py and
schedule_law.py (K mask and its schedule), builder.py (60-byte vector A),
stepper.py (closed-form 162-cell transform), gate_walk.py (FIFO ring traversal and M1 serializer),
unwrapper.py (M1 to seed, 2-layer AES-256-CBC unwrap via K_C0_0X7E and M32_DEFAULT_0X7E, KeySet to 16-byte key),
derive.py (offline derivation and first-page oracle), constants.py (library constants and lookup tables),
and __init__.py.

drmsdk/: key32_stage.py (stage-3 routines and serializer stage),
m5_pure_math.py, v07d_pure_math.py, joint_pure_math.py, win_pure_math.py
and win_producers.py (closed-form V producers), voucher_route.py and
voucher_unwrap.py (2-layer AES-256-CBC C0 mask unwrap, direct AES-256-CBC unwrap,
and inner 0x85 key-container unwrap via K_C0_BY_SID, K_0X85_BY_SID, and M32_DEFAULT_BY_SID),
and __init__.py.

## Module relations

1. Imports between the modules here are relative (from . import constants,
   from .. import _ion), so the subpackage resolves against the plugin
   package.
2. _aes.py tries Cryptodome, then Crypto, then cryptography, and raises a
   named error if none imports; exposes AES, aes_cbc_decrypt, and aes_cbc_encrypt.
3. whitebox/constants.py and whitebox/identity.py unpack and verify their
   inlined constants directly at load time, raising on any digest mismatch.
4. whitebox/unwrapper.py walks the voucher fields, extracts the 64-byte sid-0x78
   tag blob, computes m32 via AES-256-CBC(K_C0_0X7E, blob64[:16], blob64[16:48])
   (or M32_DEFAULT_0X7E), decrypts the 512-byte wrapped KeySet document under
   k_eff = seed32 ^ m32, and extracts the 16-byte book key on _ion.
5. whitebox/derive.py: page discovery via _envelope; decrypt_offline
   archives via container.scrub_delivery.
6. drmsdk/voucher_route.py and drmsdk/voucher_unwrap.py implement Stage-A,
   Path-A, Path-B, and inner 0x85 unwrapping directly as closed-form AES-256-CBC
   using K_C0_BY_SID (13 selectors), K_0X85_BY_SID (6 selectors), and
   M32_DEFAULT_BY_SID (8 selectors).
7. Stage-3 routines (0x71, 0x74, 0x7d, 0x7a, 0x82, 0x77/0x83,
   0x79/0x84/0x87/0x89, 0x8a) are closed-form pure-math, and all whitebox
   Stage 1/2/3 and inner 0x85 VMs across whitebox/ and drmsdk/ are replaced by
   closed-form AES-256-CBC.

## App-generation family (stages 1..15) - kfx_stages/whitebox/

Routed by the recipient class in the envelope's token slot, not by an outer tag.

| # | stage | module | status |
| --- | --- | --- | --- |
| 1 | recipient classification -> identity class constant | identity.py | RE-HOSTED |
| 2 | LCG byte stream + 3-tap filter -> vector B | lcg.py | RE-HOSTED |
| 3 | compute_state -> 256-word unmasked state | verdict.py | RE-HOSTED |
| 4 | K-mask: per-book schedule routine, low-byte XOR | k_law.py + schedule_law.py | RE-HOSTED |
| 5 | builder -> 60-byte vector A | builder.py | RE-HOSTED |
| 6 | mix vector A x vector B -> vector C | verdict.py | RE-HOSTED |
| 7 | fills tensor (162 cells) | derive.fills_scaled | RE-HOSTED |
| 8 | dispatcher-2 -> final 162-cell tensor | stepper.py | RE-HOSTED |
| 9 | FIFO ring traversal over the 2x9x9 grid -> emitted | gate_walk.py | RE-HOSTED |
| 10 | M1 serializer (lone-digit tail routine) | gate_walk.serialize_m1 | RE-HOSTED |
| 11 | seed = HMAC-SHA256(SHA256(M1), "PIDv3") | unwrapper.seed_from_m1 | RE-HOSTED |
| 12..14 | 2-layer AES-256-CBC: m32 = AES-256-CBC(K_C0_0X7E, blob64[:16], blob64[16:48]) (or M32_DEFAULT_0X7E), k_eff = seed ^ m32, doc = AES-256-CBC(k_eff, iv16, ct512) -> 16-byte key | unwrapper.py | RE-HOSTED |
| 15 | oracle: first page must open 00 5d | derive.oracle_check -> _envelope | RE-HOSTED |

Six certified lock-class vectors reproduce the intermediate and seed digests row
for row (empty, account-secret even/odd, two-parameter x4): message -> M1 ->
seed -> 2-layer AES-256-CBC unwrap.

## Newest + desktop families (eighteen outer tags) - kfx_stages/drmsdk/

OUTER_TAGS registers 18 tags across two families: 17 outer voucher envelope
selectors (AES256_SIDS: 0x70 0x71 0x72 0x74 0x76; PATH_A_SIDS: 0x77 0x79 0x83
0x84 0x86 0x87 0x89; PATH_B_SIDS: 0x88 0x8a; LADDER_SIDS: 0x7a 0x7d 0x82) plus
0x85 (V133, INNER_KEYSET_SIDS), the inner 48-byte WrappedSecretKey tag in
Path-B KeySet@1.0 documents - rejected with VoucherRouteError /
WindowUnavailable if routed as an outer stage-3 or window selector.

| stage | module | status | tags |
| --- | --- | --- | --- |
| envelope parse + tag classification | voucher_route.parse_voucher | RE-HOSTED | all 18 (17 outer + 0x85 inner Path-B tag) |
| envelope MAC / generator-head self-auth / six checks | voucher_route | RE-HOSTED | all 18 |
| stage-3 closed-form key32 routines (V1685, V3972, V7384) | key32_stage.py | RE-HOSTED | 0x72 0x76 0x70 0x86 0x88 |
| stage-3 empty lock class across all newest/M5 selectors (V071_EMPTY_V_HEX, V074_EMPTY_V, V07D_EMPTY_V_HEX, 0x7a, 0x82) | key32_stage.py | RE-HOSTED | 0x71 0x74 0x7a 0x7d 0x82 (6/6 empty paths engine-free) |
| stage-3 key32 serializer stage (carrier_words_to_v, serializer_outputs, _M5_FIXED_MSG) | key32_stage.py | RE-HOSTED | 0x71 0x74 0x7a 0x7d 0x82 |
| stage-3 M5 closed-form routines (derive_v071_v_pure, derive_v074_v_pure, derive_v07d_v_pure_math) | m5_pure_math.py + v07d_pure_math.py + key32_stage.py | RE-HOSTED | 0x71 0x74 0x7d |
| stage-3 joint (msg, V) closed-form routines (derive_c3e68_vectors_pure, derive_63f408_vectors_pure) | joint_pure_math.py + key32_stage.py | RE-HOSTED | 0x7a 0x82 |
| stage-3 desktop V producer closed-form routines (produce_v_pure_math, derive_v0x8a_v_pure_math, load_table_169) | win_pure_math.py + win_producers.py | RE-HOSTED | 0x77 0x79 0x83 0x84 0x87 0x89 0x8a |
| direct AES-256-CBC document unwrap | voucher_route.stage_a_decode | RE-HOSTED | 0x70 0x71 0x72 0x74 0x76 |
| 2-layer AES-256-CBC C0 mask + document unwrap (K_C0_BY_SID, M32_DEFAULT_BY_SID) | voucher_route.stage_a_decode + voucher_unwrap.unwrap_voucher | RE-HOSTED | 0x77 0x79 0x7a 0x7d 0x82 0x83 0x84 0x86 0x87 0x88 0x89 0x8a |
| inner 0x85 key container AES-256-CBC unwrap (K_0X85_BY_SID, 48-byte blob -> 16-byte key) | voucher_route.unwrap_keyset_0x85 (path_b_unwrap_keyset_0x85) | RE-HOSTED | 0x84 0x86 0x87 0x88 0x89 0x8a (0x85 inner tag) |

### Closed-form AES-256-CBC & pure-math architecture summary

All whitebox Stage 1/2/3 and inner 0x85 VMs across drmsdk/ and whitebox/ reduce
algebraically to standard AES-256-CBC with extracted static 32-byte ASCII keys
(K_C0_BY_SID across 13 selectors: 0x77, 0x79, 0x7a, 0x7d, 0x7e, 0x82, 0x83,
0x84, 0x86, 0x87, 0x88, 0x89, 0x8a; K_0X85_BY_SID across 6 selectors: 0x84,
0x86, 0x87, 0x88, 0x89, 0x8a; and fallback masks M32_DEFAULT_BY_SID). For every
whitebox selector, m32 = AES-256-CBC(K_C0_BY_SID[sid], rec64[0:16], rec64[16:48])
(or M32_DEFAULT_BY_SID[sid]), k_eff = key32 ^ m32, and doc = AES-256-CBC(k_eff,
cipher_iv, cipher_text). For inner 0x85 containers, key16 = AES-256-CBC(K_0X85_BY_SID[sid],
blob48[0:16], blob48[16:32]) ^ voucher_id[:16].

Stage-3 routines, all 17 outer selectors, across drmsdk/m5_pure_math.py,
drmsdk/v07d_pure_math.py, drmsdk/joint_pure_math.py, drmsdk/win_pure_math.py,
drmsdk/key32_stage.py, drmsdk/win_producers.py. M5 (0x71, 0x74, 0x7d):
derive_v071_v_pure, derive_v074_v_pure, and derive_v07d_v_pure_math over
constants.T850/T868/T880/T898 (sha16=1b50c6ed2f351c0c) plus
V07D_EMPTY_V_HEX V sha16=57a8cd9a64e33646, msg sha16=0f8873dd9ec84671,
key32 sha16=dd966adc85379a47; serializer_outputs and _M5_FIXED_MSG go with
them. Joint (msg, V) (0x7a, 0x82): 12-stage closed form,
derive_c3e68_vectors_pure, derive_63f408_vectors_pure, with carrier_words_to_v
and serializer_outputs. Desktop producers (0x77/0x83,
0x79/0x84/0x87/0x89, 0x8a): produce_v_pure_math,
derive_v0x8a_v_pure_math, inlined 169-word tables TABLE_V3332_WORDS
(sha16=2f3bc6f0c98f6e9b) and TABLE_V2746_WORDS (sha16=9f75e1ae09acca97).

## Relational container transition - kfx_stages/container.py

| concern | implementation | status |
| --- | --- | --- |
| detect a relational container | container.is_container (magic only) | RE-HOSTED |
| fingerprint records (1,024 B, signature fa 50 0a 5f) | container.unwrap_fingerprints | RE-HOSTED |
| collision-safe page decryption (00 5d) | _envelope._page_plain (shared with the envelope path) | RE-HOSTED |
| fragments.payload_value decryption in memory | container.decrypt_container | RE-HOSTED |
| first-page oracle over container rows | container.first_encrypted_page + verify_page | RE-HOSTED |
| delivery archive with every component opened | container.scrub_delivery | RE-HOSTED |

## Inlined static table constants

All static tables are inlined directly in Python source: whitebox/constants.py,
whitebox/identity.py, and drmsdk/win_pure_math.py.

| constant | module | bytes | sha16 |
| --- | --- | --- | --- |
| _RAW_TABLES (T850, T868, T880, T898) | whitebox/constants.py | 11429 | 1b50c6ed2f351c0c |
| empty_class_message | whitebox/identity.py | 89 | 1b5c9a64670257c3 |
| client_id_message (synthetic) | whitebox/identity.py | 93 | 6c36afc3ce4f6e65 |

## Verification

kfx_stages/selftest.py (110 checks across 6 sections) verifies inlined table
constants, whitebox stages 1..15, drmsdk stage-3 digests, 2-layer AES-256-CBC
and 0x85 round-trips across all K_C0_BY_SID and K_0X85_BY_SID selectors,
relational container decryption, and top-level routing.
