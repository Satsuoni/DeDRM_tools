// dsx_kinf_decrypt.hpp -- decrypt a Kindle "Katxopo" secure-storage map (.kinf2024).
//
// Chain :
//
//   container : file = <header> '#' rec0 '}' rec1 '}' ...
//   per rec   : F5 Caesar-strip -> base64 -> F4 LZW -> F3 permutation (dwF3Key)
//               -> B64Enc2 -> F2 rotate (dwF2Key) -> F1 transpose -> split on '*'
//   KEY       : A64( MD5(entry name) )                       -- 32 chars / 16 bytes
//   VALUE     : A64( nonce(12) || ciphertext || tag(16) )    -- AES-256-GCM
//   storageIKM= HKDF-SHA256(ikm=master32, salt=<salt file>, info="kindle_ss",       len=32)
//               == SSEV2EncryptEntryValue_18010b6f0, whose output is then DPAPI-wrapped
//   entryKey  = HKDF-SHA256(ikm=storageIKM, salt=SHA1(KEY text), info="kindle_ss_token", len=32)
//               == SSEV2DeriveEntryKey_18010bfa0
//
// The F3/F2 keys are NOT constants. SecureStorageFileObfuscatorV1Ctor_18011c5b0 derives all
// four ObfuscatorV1 keys from one string `s`, which is the DECIMAL volume serial number of the
// volume holding QDir::rootPath() (GetVolumeSerialDecimalString_1810059e0 -> GetVolumeInformationW),
// or "9999999999" if that call fails:
//
//   s        = sprintf("%u", VolumeSerialNumber)
//   f1_key   = last 5 chars of s              -> F1_Dec uses only its length: 5 rows, always
//   dwF3_key = sum of the bytes of s          -> F3 permutation parameter p = dwF3_key - 1
//   dwF2_key = dwF3_key % 5                   -> F2 bit-string rotate amount
//   f5_key   = str(sum(byte[i] * (i+1)) % 8)  -> always 1 char, so the F5 shift is always 1
//
// Reference device: serial 236943134 -> s = "236943134" -> f1_key "43134", dwF3_key 467,
// dwF2_key 2, f5_key "7" -- every value ever captured live from that build. See dsx_storage.md
// sections 24 and 25.
//
// master32 is the NCrypt/TPM unwrap of <dir>/storage/main_shared.blob.
// It is the only machine-bound input on the key-derivation side; the volume serial is the only
// machine-bound input on the obfuscator side, and kinf2024RecoverKeys() recovers it from the
// container itself, so nothing has to be read off the target machine.
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>
#include "filesystem.hpp"


// The four ObfuscatorV1 keys, as SecureStorageFileObfuscatorV1Ctor_18011c5b0 computes them.
struct ObfV1Keys {
    std::string keySource;   // `s`, empty when it was not known (recovered instead)
    uint32_t    dwF3Key = 0; // F3 permutation key; 0 means "not set -- recover it"
    uint32_t    dwF2Key = 0; // F2 rotate amount, always dwF3Key % 5
    std::string f1Key;       // only f1Key.size() (== 5) is consumed by F1_Dec
    std::string f5Key;       // only f5Key.size() (== 1) is consumed by F5_CaesarStrip
};

// Derive the keys from the key-source string. Mirrors ObfV1_DeriveF3Key_18011d230,
// ObfV1_DeriveF1KeyTail5_18011d8a0 and ObfV1_DeriveF5Key_18011cfa0.
// Throws std::runtime_error if the source is shorter than 5 characters.
ObfV1Keys obfDeriveKeys(const std::string& keySource);

// Keys straight from the DWORD volume serial number, i.e. what
// (Get-Volume -DriveLetter C).SerialNumber prints. DECIMAL, not hex.
ObfV1Keys obfKeysFromVolumeSerial(uint32_t serial);

// Keys when only dwF3_key is known. f1_key / f5_key are unrecoverable from it alone, but
// F1_Dec and F5_CaesarStrip consume only their lengths (5 and 1), which these reproduce.
ObfV1Keys obfKeysFromDwKey(uint32_t dwF3Key);

// Recover the keys from the container with no access to the device. `s` is a decimal digit
// string of 1..10 characters, so dwF3_key = sum(bytes) lies in 48..570 and dwF2_key follows
// from it -- 523 candidates, and the record structure (32-char A64 KEY, A64-only VALUE)
// leaves exactly one on a real container. Throws if none survives.
ObfV1Keys kinf2024RecoverKeys(const std::vector<std::string>& records);

// Decrypt every entry. Key = lowercase hex of the entry's MD5 (the decoded KEY field,
// i.e. MD5 of the entry name). Value = recovered plaintext bytes.
// Pass the volume serial with `serial` when it is known; leave it 0 to recover the keys from
// the container. Throws std::runtime_error on a malformed container or a GCM tag mismatch.
std::map<std::string, std::string> decryptKinStorage(const  ghc::filesystem::path& kinfPath,
                                                     const  ghc::filesystem::path& saltFile,
                                                     const std::vector<uint8_t>& master32,
                                                     uint32_t serial = 0);

// Same, with keys supplied directly (e.g. from obfDeriveKeys() on a known key-source string).
std::map<std::string, std::string> decryptKinStorage(const  ghc::filesystem::path& kinfPath,
                                                     const  ghc::filesystem::path& saltFile,
                                                     const std::vector<uint8_t>& master32,
                                                     const ObfV1Keys& keys);

// The keys a given container was written with, for reporting.
ObfV1Keys kinf2024KeysForFile(const ghc::filesystem::path& kinfPath, uint32_t serial = 0);

// Validate the primitives (hashes, AES-256, GCM, HKDF) against published vectors plus vectors
// produced by the Python implementation, and the key derivations against the reference device.
// Returns false and fills `report` on the first failure.
bool kinfSelfTest(std::string& report);

// Lowercase hex MD5 of a string. The storage map's KEY field is exactly MD5(entry name), so
// md5Hex("kindle.device.info") must equal the corresponding key of the returned map.
std::string md5Hex(const std::string& s);

// The 32-byte storage IKM (the value CryptUnprotectMemory hands to HKDF_KEY at runtime).
std::vector<uint8_t> storageIkm(const std::vector<uint8_t>& master32,
                                const  ghc::filesystem::path& saltFile);
