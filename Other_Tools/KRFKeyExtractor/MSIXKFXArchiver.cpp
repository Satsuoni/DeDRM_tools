// MSIXKFXArchiver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <dpapi.h>
#include <iostream>
#include <fstream>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <DbgHelp.h>
#include <map>
#include <set>
#include <winternl.h>
#include <Sddl.h>
#include <sstream>
#include <iomanip>
#include <appmodel.h>
#include <bcrypt.h>
#include <userenv.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>
#include <memoryapi.h>
#include <winnt.h>
#include "filesystem.hpp"
#include "json.hpp"
#include "plusaes.hpp"
#include "miniz.h" 
#define POCKETLZMA_LZMA_C_DEFINE
#include "pocketlzma.hpp"

namespace fs = ghc::filesystem;

// Link with the CNG library
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "mincore.lib")

#include <cstdint>


INT_PTR  globoffs = 0;
std::vector<char> mboxsave(150000);//119424
bool mbox_saved = false;
bool mbox_keyed = false;
bool mbox_bare = false;
struct basic_package_data
{
    std::wstring full_name;
    std::wstring family_name;
    std::wstring install_folder;
};
uint8_t* scandidate = nullptr;
int scancntr = 0;
bool allhex(uint8_t* p, size_t ln)
{
    bool brk = false;
    for (int i = 0; i < ln; i++)
    {
        if (!isxdigit(p[i]) || p[i] == 0)
        {
            brk = true;
            break;
        }
    }
    return !brk;
}

static std::string hexStr(const uint8_t* data, size_t len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}
std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}
std::vector<char> HexToBytesC(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

std::vector<basic_package_data> FindPackagesViaRegistry(const std::wstring& partialName) {
    // The central repository for the current user's registered applications
    const wchar_t* subKeyPath = L"Software\\Classes\\Local Settings\\Software\\"
        L"Microsoft\\Windows\\CurrentVersion\\AppModel\\"
        L"Repository\\Packages";
    std::vector<basic_package_data> ret;
    HKEY hRootKey = nullptr;
    // Open the primary packages container key with Read permissions
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, subKeyPath, 0, KEY_READ, &hRootKey);

    if (rc != ERROR_SUCCESS) 
    {
        std::cout << "Failed to open AppModel Package Repository registry key. Error: " << rc << std::endl;
        return ret;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;

    // Query the key to find out how many packages exist and the maximum string length
    rc = RegQueryInfoKeyW(hRootKey, nullptr, nullptr, nullptr, &subKeyCount,
        &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (rc == ERROR_SUCCESS && subKeyCount > 0) {
        std::wcout << L"Scanning " << subKeyCount << L" registry keys for: \"" << partialName << L"\"...\n\n";

        // Account for the null terminator (+1)
        DWORD nameBufferLength = maxSubKeyLen + 1;
        std::vector<wchar_t> subKeyName(nameBufferLength);

        // Iterate through all package keys sequentially
        for (DWORD i = 0; i < subKeyCount; ++i) {
            DWORD currentLength = nameBufferLength;
            FILETIME ftLastWriteTime;

            rc = RegEnumKeyExW(hRootKey, i, subKeyName.data(), &currentLength,
                nullptr, nullptr, nullptr, &ftLastWriteTime);

            if (rc == ERROR_SUCCESS) {
                std::wstring packageFullName(subKeyName.data());

                // Perform a case-insensitive find (or standard find) on the Full Name
                if (packageFullName.find(partialName) != std::wstring::npos) {
                    basic_package_data dat;
                    dat.full_name = packageFullName;
                    // Open the specific package subkey to read its internal values
                    HKEY hPackageKey = nullptr;
                    if (RegOpenKeyExW(hRootKey, packageFullName.c_str(), 0, KEY_READ, &hPackageKey) == ERROR_SUCCESS) {

                        wchar_t pathBuffer[MAX_PATH] = { 0 };
                        DWORD pathBufferSize = sizeof(pathBuffer);

                        // Fetch the physical installation path on the disk
                        LONG pathRc = RegQueryValueExW(hPackageKey, L"PackageID", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(pathBuffer), &pathBufferSize);

                        wchar_t familyBuffer[MAX_PATH] = { 0 };
                        DWORD familyBufferSize = sizeof(familyBuffer);

                        // Fetch the companion Package Family Name
                        LONG familyRc = RegQueryValueExW(hPackageKey, L"PackageFamilyName", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(familyBuffer), &familyBufferSize);
                      
                        std::wcout << L"Matched Full Name: " << packageFullName << std::endl;
                        if (familyRc == ERROR_SUCCESS) {
                            std::wcout << L"  Family Name:       " << familyBuffer << std::endl;
                            dat.family_name = familyBuffer;
                        }
                        if (pathRc == ERROR_SUCCESS) {
                            // Note: To map the precise data path, use the Family Name 
                            // with the 'GetAppContainerFolderPath' logic shared previously.
                           // std::wcout << L"  Install Root ID:   " << pathBuffer << std::endl;
                            dat.install_folder = pathBuffer;
                        }
                        ret.push_back(dat);
                        std::wcout << L"--------------------------------------------------" << std::endl;

                        RegCloseKey(hPackageKey);
                    }
                }
            }
        }
    }

    RegCloseKey(hRootKey);
    return ret;
}


std::string CalculateMD5(const std::wstring& filePath) 
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string md5String = "";

    // 1. Open the file in binary mode
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return "Error: Cannot open file.";
    }

    // 2. Open the MD5 algorithm provider
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, nullptr, 0) != 0) {
        return "Error: BCryptOpenAlgorithmProvider failed.";
    }

    // 3. Create the hash object
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "Error: BCryptCreateHash failed.";
    }

    // 4. Read file in chunks and stream to the hash object
    constexpr size_t bufferSize = 1024 * 64; // 64KB chunks
    std::vector<char> buffer(bufferSize);
    while (file.read(buffer.data(), bufferSize) || file.gcount() > 0) {
        if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(file.gcount()), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "Error: BCryptHashData failed.";
        }
    }

    // 5. Finalize the hash computation
    DWORD cbHashLen = 16; // MD5 is always 16 bytes
    std::vector<BYTE> hashResult(cbHashLen);
    if (BCryptFinishHash(hHash, hashResult.data(), cbHashLen, 0) == 0) {
        // 6. Convert the raw bytes to a hexadecimal string
        std::stringstream ss;
        for (BYTE b : hashResult) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        md5String = ss.str();
    }
    else {
        md5String = "Error: BCryptFinishHash failed.";
    }

    // Cleanup CNG resources
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return md5String;
}

//BCRYPT_MD5_ALGORITHM,BCRYPT_SHA256_ALGORITHM,BCRYPT_SHA1_ALGORITHM
std::vector<char> CalculateHashVector(const std::vector<char>& data,LPCWSTR algid)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<char> ret;

    // 2. Open the algorithm provider
    if (BCryptOpenAlgorithmProvider(&hAlg, algid, nullptr, 0) != 0)
    {
        std::cout<< "Error: BCryptOpenAlgorithmProvider failed.";
        return ret;
    }

    // 3. Create the hash object
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::cout<< "Error: BCryptCreateHash failed.";
    }
    DWORD hashLength = 0;
    ULONG resultLength = 0;

    // hAlg is the handle returned by BCryptOpenAlgorithmProvider
    NTSTATUS status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&hashLength,
        sizeof(hashLength),
        &resultLength,
        0
    );

    if (!NT_SUCCESS(status)) 
    {
        std::cout << "Could not get alg len" << std::endl;
        return ret;
    }
    if (BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        std::cout<< "Error: BCryptHashData failed.";
        return ret;
    }

    // 4. Read file in chunks and stream to the hash object
   
    // 5. Finalize the hash computation
    std::vector<char> hashResult(hashLength);
    if (BCryptFinishHash(hHash,(PUCHAR) hashResult.data(), hashLength, 0) == 0) {
        // 6. Convert the raw bytes to a hexadecimal string
        ret= hashResult;
    }
    else {
        std::cout<< "Error: BCryptFinishHash failed.";
    }

    // Cleanup CNG resources
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return ret;
}
std::vector<UCHAR>  DeriveKeyPBKDF2(const std::string& password, const std::string& salt, ULONG iterations)
{
    // Specify the algorithm (e.g., BCRYPT_SHA256_ALGORITHM)
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0) != 0) {
        std::cerr << "Failed to open algorithm provider.\n";
        return  std::vector<UCHAR>();
    }

    // Set up buffers
    std::vector<UCHAR> pbPassword(password.begin(), password.end());
    std::vector<UCHAR> pbSalt(salt.begin(), salt.end());

    // Output buffer for the derived key (e.g., 32 bytes)
    DWORD cbDerivedKey = 32;
    std::vector<UCHAR> pbDerivedKey(cbDerivedKey);

    // Derive the key
    NTSTATUS status = BCryptDeriveKeyPBKDF2(
        hAlg,
        pbPassword.data(), (ULONG)pbPassword.size(),
        pbSalt.data(), (ULONG)pbSalt.size(),
        iterations,
        pbDerivedKey.data(), cbDerivedKey,
        0
    );

    if (status == 0) { // 0 indicates STATUS_SUCCESS
        std::cout << "Derived Key (Hex): ";
        for (UCHAR byte : pbDerivedKey) {
            printf("%02X", byte);
        }
        std::cout << "\n";
    }
    else {
        std::cerr << "PBKDF2 Derivation failed with code: " << status << "\n";
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return pbDerivedKey;
}

class CRC32 {
private:
    uint32_t table[256];

public:
    CRC32() {
        uint32_t polynomial = 0xEDB88320;
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (uint32_t j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ polynomial;
                }
                else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
    }

    uint32_t Calculate(const uint8_t* data, size_t length) {
        uint32_t crc = 0;// 0xFFFFFFFF; // Initial value
        for (size_t i = 0; i < length; ++i) {
            uint8_t index = (crc ^ data[i]) & 0xFF;
            crc = (crc >> 8) ^ table[index];
        }
        return crc;// ^ 0xFFFFFFFF; // Final XOR
    }
};

std::string charMap1 = "n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M";
std::string charMap3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string charMap4 = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";

std::string encodeToMap(const std::vector<char>& data,const std::string& smap)
{
    std::ostringstream s;
    size_t l = smap.size();
    for (auto val : data)
    {
        int Q = (val ^ 0x80) / l;
        int R = (val) % l;
        s << smap[Q] << smap[R];
    }
    return s.str();
}
std::string encodeHashToMap(const std::vector<char>& data, const std::string& smap)
{
    return encodeToMap(CalculateHashVector(data, BCRYPT_MD5_ALGORITHM), smap);
}

char getTwoBitsFromBitField(const std::vector<char>& bitField, int offset)
{
    int byteNumber = offset / 4;
    int bitPosition = 6 - 2 * (offset % 4);
    return bitField[byteNumber] >> bitPosition & 3;
}

char getSixBitsFromBitField(const std::vector<char>& bitField, int offset)
{
    offset *= 3;
    char value = value = (getTwoBitsFromBitField(bitField, offset) << 4) + (getTwoBitsFromBitField(bitField, offset + 1) << 2) + getTwoBitsFromBitField(bitField, offset + 2);
    return value;
}

std::string encodePID(const std::vector<char>& hash)
{
    std::ostringstream s;
    for (int pos = 0; pos < 8; pos++)
    {
        s << charMap3[getSixBitsFromBitField(hash, pos)];
    }
    return s.str();
}

std::vector<uint32_t> generatePidEncryptionTable()
{
    std::vector<uint32_t> ret;
    ret.reserve(0x100);
    for (uint32_t counter1 = 0; counter1 < 0x100; counter1++)
    {
        uint32_t value = counter1;
        for (uint32_t counter2 = 0; counter2 < 8; counter2++)
        {
            if ((value & 1) == 0)
            {
                value >>= 1;
            }
            else
            {
                value >>= 1;
                value = value ^ 0xEDB88320;
            }
        }
        ret.push_back(value);

    }
    return ret;
}

uint32_t generatePidSeed(const std::vector<uint32_t>& table,const std::string& dsn)
{
    uint32_t value = 0;
    for (int i = 0; i < 4; i++)
    {
        int index = (dsn[i] ^ value) & 0xff;
        value = (value >> 8) ^ table[index];
    }
    return value;
}

std::string generateDevicePID(const std::vector<uint32_t>& table, const std::string& dsn,int nbRoll)
{
    uint32_t seed = generatePidSeed(table, dsn);
    std::ostringstream s;
    std::vector<unsigned int> pid = {(seed>>24)&0xff,(seed >> 16) & 0xff, (seed >> 8) & 0xff ,(seed) & 0xff,(seed >> 24) & 0xff,(seed >> 16) & 0xff, (seed >> 8) & 0xff ,(seed) & 0xff };
    int index = 0;
    for (int cnt = 0; cnt < nbRoll; cnt++)
    {
        pid[index] = pid[index] ^ dsn[cnt];
        index = (index + 1) % 8;
    }
    for (int cnt = 0; cnt < 8; cnt++)
    {
        index = ((((pid[cnt] >> 5) & 3) ^ pid[cnt]) & 0x1f) + (pid[cnt] >> 7);
        s << charMap4[index];
    }
    return s.str();
}
std::string checksumPID(const std::string& pid)
{
    CRC32 crcCalculator;
    uint32_t crc = crcCalculator.Calculate((const uint8_t*)(pid.data()),pid.length());
    crc = crc ^ (crc >> 16);
    std::ostringstream s;
    s << pid;
    int l = charMap4.size();
    for (int a = 0; a <= 1; a++)
    {
        int b = crc & 0xff;
        int pos = (b / l) ^ (b % l);
        s << charMap4[pos % l];
        crc >>= 8;
    }
    return s.str();
}

template<typename T>
size_t clen(T finalArg) 
{
    return finalArg.size();
}

template<typename T, typename... Args>
size_t clen(T first, Args... args) 
{
    return first.size() + clen(args...);
}


template<typename T>
void mcpy(std::vector<char>& into,size_t offset,T finalArg)
{
    memcpy(&into[offset], finalArg.data(),finalArg.size());
}

template<typename T, typename... Args>
void mcpy(std::vector<char>& into, size_t offset, T first, Args... args)
{
    memcpy(&into[offset], first.data(), first.size());
    mcpy(into, offset + first.size(), args...);
}

template<typename T>
std::vector<char> ccat(T finalArg)
{
    std::vector<char> ret(finalArg.begin(), finalArg.end());
    return ret;
}

template<typename T, typename... Args>
std::vector<char> ccat(T first, Args... args)
{   
    std::vector<char> sm(clen(first, args...));
    mcpy(sm, 0, first, args...);
    return sm;
}

std::vector<std::string> getK4Pids(const std::vector<char>& rec209, const std::vector<char>& token,const std::string& dsn, const std::vector<std::string>& extraKindleTokens)
{
    std::vector<std::string> ret;
    if (rec209.size() == 0)
    {
        for (auto accountToken : extraKindleTokens)
        {
            ret.push_back(dsn+ accountToken);
        }
        return ret;
    }
    std::vector<uint32_t> table = generatePidEncryptionTable();
    std::string devicePID = checksumPID(generateDevicePID(table,dsn,4));
    ret.push_back(devicePID);
    std::vector<char> sm;
    std::vector<char> pidHash;
    std::string bookPID;
    for (auto accountToken : extraKindleTokens)
    {
        sm = ccat(dsn, accountToken, rec209,token);
        pidHash = CalculateHashVector(sm, BCRYPT_SHA1_ALGORITHM);
        //std::string sm DSN + accToken + rec209 + token;
        bookPID=  checksumPID(encodePID(pidHash));
        ret.push_back(bookPID);

        sm = ccat( accountToken, rec209, token);
        pidHash = CalculateHashVector(sm, BCRYPT_SHA1_ALGORITHM);
        bookPID = checksumPID(encodePID(pidHash));
        ret.push_back(bookPID);
    }
    sm = ccat(dsn,  rec209, token);
    pidHash = CalculateHashVector(sm, BCRYPT_SHA1_ALGORITHM);
    bookPID = checksumPID(encodePID(pidHash));
    ret.push_back(bookPID);
    return ret;
}


std::string ReadFileToString(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

std::vector<char> ReadFileToVector(const fs::path& filePath) 
{

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Could not open " << filePath << " with " << strerror(errno) << std::endl;
        return std::vector<char>();
    }
    return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

}

//Kinda AI-assisted port of Dedrm for other two book formats
class DrmException : public std::runtime_error
{
public:
    explicit DrmException(const std::string& message) : std::runtime_error(message) {}
};
//mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), outme.data(), outme.size(), NULL, 0, MZ_BEST_COMPRESSION)
struct BookInterface 
{
    virtual ~BookInterface() = default;
    virtual std::string getBookType() { return "UNK"; }
    virtual std::pair<std::vector<char>, std::vector<char>> getPIDMetaInfo() 
    { 
        return { std::vector<char>(), std::vector<char> ()};
    }
    virtual void processBook(const std::vector<std::string>& pids) {}
    virtual void cleanup() {}
    virtual std::string  getBookExtension() { return ".unk"; }
    virtual void writeFile(const fs::path& fl) {};
  
};


//MOBI stuff

void writeFileBasic(const fs::path& filename, const std::vector<char>& data)
{
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (!file)
    {
        std::cout << " Could not open file " << filename << " For writing " << strerror(errno) << std::endl;
        return;
    }
    //  std::cout << hexStr((uint8_t*) & data[0], 16) << std::endl;
    file.write(data.data(), data.size());
}

uint16_t unpack_H(const std::vector<char>& buffer, size_t offset = 0) 
{

    uint16_t b1 = buffer[offset];
    uint16_t b2 = (UCHAR)buffer[offset+1];
    return (b1<<8)|b2;
}

uint16_t unpack_H(const char* buffer, size_t offset = 0)
{
    return (static_cast<uint16_t>((UCHAR)buffer[offset]) << 8) |
        (static_cast<uint16_t>((UCHAR)buffer[offset + 1]));
}

size_t getSizeOfTrailingDataEntry(const char *ptr, size_t size)
{
    size_t bitpos = 0;
    size_t result = 0;
    if (size <= 0)
    {
        return result;
    }
    while (true)
    {
        UCHAR v = (UCHAR)ptr[size-1];
        result |= (size_t)(v & 0x7F) << bitpos;
        bitpos += 7;
        size -= 1;
        if ((v & 0x80) != 0 || (bitpos >= 28) || (size == 0))
        {
            return result;
        }
    }
    return 0;
}

size_t getSizeOfTrailingDataEntries(const char* ptr, size_t size,uint32_t flags)
{
    size_t num = 0;
    uint32_t testflags = flags >> 1;
    while (testflags)
    {
        if (testflags & 1) num += getSizeOfTrailingDataEntry(ptr, size - num);
        testflags >>= 1;
    }
    if (flags & 1)
    {
        num += (ptr[size - num - 1] & 0x3) + 1;
    }
    return num;
}
struct MobiSection
{
    uint32_t offset;
    uint32_t flags;
    uint32_t val;
    MobiSection(char* buffer)
    {
            offset= ((uint32_t)((UCHAR)buffer[0]) << 24) |
                ((uint32_t)((UCHAR)buffer[1]) << 16) |
                ((uint32_t)((UCHAR)buffer[2]) << 8) |
                ((uint32_t)((UCHAR)buffer[3]));
           flags = (UCHAR)buffer[4];
           val = (UCHAR)buffer[5] << 16 | (UCHAR)buffer[6] << 8 | (UCHAR)buffer[7];
        

    }
};
uint32_t unpack_L(const char * buffer, size_t offset = 0) {
    return (static_cast<uint32_t>((UCHAR)buffer[offset]) << 24) |
        (static_cast<uint32_t>((UCHAR)buffer[offset + 1]) << 16) |
        (static_cast<uint32_t>((UCHAR)buffer[offset + 2]) << 8) |
        (static_cast<uint32_t>((UCHAR)buffer[offset + 3]));
}

unsigned char* PC1(const unsigned char* key,size_t klen, const unsigned char* src,
    unsigned char* dest, unsigned int len, int decryption)
{
    size_t sum1 = 0;
    size_t sum2 = 0;
    size_t keyXorVal = 0;
    unsigned short wkey[8];
    unsigned int i;
    if (klen != 16) {
        fprintf(stderr, "Bad key length!\n");
        return NULL;
    }
    for (i = 0; i < 8; i++) {
        wkey[i] = (key[i * 2] << 8) | key[i * 2 + 1];
    }
    for (i = 0; i < len; i++) {
        unsigned int temp1 = 0;
        unsigned int byteXorVal = 0;
        unsigned int j, curByte;
        for (j = 0; j < 8; j++) {
            temp1 ^= wkey[j];
            sum2 = (sum2 + j) * 20021 + sum1;
            sum1 = (temp1 * 346) & 0xFFFF;
            sum2 = (sum2 + sum1) & 0xFFFF;
            temp1 = (temp1 * 20021 + 1) & 0xFFFF;
            byteXorVal ^= temp1 ^ sum2;
        }
        curByte = src[i];
        if (!decryption) {
            keyXorVal = curByte * 257;
        }
        curByte = ((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF;
        if (decryption) {
            keyXorVal = curByte * 257;
        }
        for (j = 0; j < 8; j++) {
            wkey[j] ^= keyXorVal;
        }
        dest[i] = curByte;
    }
    return dest;
}
std::vector<char> PC1d(const std::vector<char>&key, const std::vector<char>& vec,int dec)
{
    std::vector<char> temp_key(vec.size());
    PC1((const unsigned char*)&key[0], key.size(), (const unsigned char*)&vec[0], (unsigned char*)&temp_key[0], vec.size(), dec);
    return temp_key;

}
class MobiBook : public BookInterface
{

public:
    bool init_done = false;
    int num_sections=0;
    std::string magic;
    std::vector<char> data_file;
    std::vector<char> mobi_data;
    std::vector<char> sect;
    //std::vector<char> header;
    std::vector<MobiSection> sections;
    int crypto_type = -1;
    uint16_t records=0;
    uint16_t compression=0;
    bool print_replica=false;
    uint32_t extra_data_flags = 0;
    uint32_t mobi_length = 0;
    uint32_t mobi_codepage = 1252;
    int mobi_version = -1;
    std::map<uint32_t, std::vector<char>> meta_array;
    std::vector<char> loadSection(int section)
    {
        SSIZE_T  endoff = 0;
        if (section + 1 == num_sections)
        {
            endoff = data_file.size();
        }
        else
        {
            endoff = sections[section+1].offset;
        }
        int off= sections[section ].offset;
        return std::vector<char>(data_file.begin() + off, data_file.begin() + endoff);
    }
    void patch(size_t offset, const char* new_data,size_t sz )
    {
        memcpy(&data_file[offset], new_data, sz);
    }
    void patchSection(int section, const char* new_data,size_t sz, size_t in_off=0)
    {
        size_t endoff = 0;
        if (section + 1 == num_sections)
        {
            endoff = data_file.size();
        }
        else
        {
            endoff = sections[section + 1].offset;
        }
        uint32_t off = sections[section].offset;
        if (off + in_off + sz > endoff)
        {
            std::cout << "ERROR* mobi patching exceeds data len" << std::endl;
            return;
        }
        patch(off + in_off, new_data, sz);
     }
 
    MobiBook(const fs::path& path)
    {
        std::cout << "MobiDeDrm Port" << std::endl;
        data_file = ReadFileToVector(path);
        //header.resize(78);
       // memcpy(&header[0],&data_file[0],78);
        magic = std::string(data_file.begin() + 0x3C, data_file.begin() + 0x3C + 8);
        if (magic!= "BOOKMOBI" && magic != "TEXtREAd")
        {
            std::cout << path << " is not a mobi book " << std::endl;
            init_done = false;
            return;
        }

        num_sections = unpack_H(data_file, 76);//.header[76:78]
        for (int i = 0; i < num_sections; i++)
        {
            MobiSection ms(&data_file[78+i*8]);
            sections.push_back(ms);
        }
        sect = loadSection(0);
        records = unpack_H(&sect[8]);
        compression = unpack_H(&sect[0]);
        if (magic == "TEXtREAd")
        {
            std::cout << "PalmDoc format book detected." << std::endl;
            init_done = true;
            return;
        }
        mobi_length = unpack_L(&sect[0x14]);
        mobi_codepage = unpack_L(&sect[0x1c]);
        mobi_version = unpack_L(&sect[0x68]);
        std::cout << "MOBI header version " << mobi_version << ", header length " << mobi_length<< std::endl;
        if (mobi_length >= 0xe4 && mobi_version >= 5)
        {
            extra_data_flags = unpack_H(sect, 0xf2);
        }
        if (compression != 17480)
        {
            extra_data_flags &= 0xFFFE;
        }
        if (sect.size() >= 0x84)
        {
            uint32_t exth_flag= unpack_L(&sect[0x80]);
            std::vector<char> exth;
            if (exth_flag & 0x40&&sect.size()>16+mobi_length)
            {
                exth = std::vector<char>(sect.begin()+16+mobi_length,sect.end());
                if (exth.size() > 12 && exth[0] == 'E' && exth[1] == 'X' && exth[2] == 'T' && exth[3] == 'H')
                {
                    uint32_t nitems = unpack_L(&exth[8]);
                    uint32_t pos = 12;
                    for (uint32_t i = 0; i < nitems; i++)
                    {
                        uint32_t type= unpack_L(&exth[pos]);
                        uint32_t size = unpack_L(&exth[pos+4]);
                        std::vector<char> content(exth.begin()+8+pos, exth.begin()+size+pos);
                        meta_array[type] = content;
                        if (type == 401 && size == 9)
                        {
                           unsigned char b = 144;
                            patchSection(0, (char*) & b, 1, 16 + mobi_length + pos + 8);
                        }
                        if (type == 404 && size == 9)
                        {
                            char b = 0;
                            patchSection(0, &b, 1, 16 + mobi_length + pos + 8);
                        }
                        if (type == 405 && size == 9)
                        {
                            char b = 0;
                            patchSection(0, &b, 1, 16 + mobi_length + pos + 8);
                            
                        }
                        if (type == 406 && size == 16)
                        {
                            char b[8] = { 0,0,0,0,0,0,0,0 };
                            patchSection(0, b, 8, 16 + mobi_length + pos + 8);
                        }
                        if (type == 208)
                        {
                            std::vector<char> b;
                            b.resize(size-8);
                            patchSection(0, &b[0], 8, 16 + mobi_length + pos + 8);
                        }
                        pos += size;
                    }
                }
            }
        }
        init_done = true;
    }
    virtual ~MobiBook() {};
    virtual std::string getBookType() { return "MOBI"; }
    virtual std::string getBookExtension() 
    { 
        if (print_replica)
        {
            return ".azw4";
        }
        if (mobi_version >= 8)
        {
            return ".azw3";
        }
        return ".mobi";
    }
    virtual void writeFile(const fs::path& fl) 
    {
        writeFileBasic(fl, mobi_data);
    };
    virtual std::pair<std::vector<char>, std::vector<char>> getPIDMetaInfo()
    { 
        std::vector<char> rec209;
        std::vector<char> token;
       
        auto fnd = meta_array.find(209);
        if (fnd != meta_array.end())
        {
            rec209 = fnd->second;
            token.clear();
            for (size_t i = 0; i < rec209.size(); i+=5)
            {
                uint32_t val = unpack_L(&rec209[i+1]);
                auto fval = meta_array.find(val);
                if (fval != meta_array.end())
                {
                    token = ccat(token, fval->second);
                }
            }
        }
        return { rec209, token };
    
    }
    std::pair<std::vector<char>, std::string>  parseDRM(const char * data,int count,const std::vector<std::string>& pidlist)
    {
        std::vector<char> found_key;
        std::string fpid = "";
        std::vector<char> keyvec1 = HexToBytesC("723833b0b4f2e3cadf0901d6e2e03f96");
        for (auto pid : pidlist)
        {
            std::string bigpid(16, '\0');
            size_t copy_size = min(pid.length(), size_t(16));
            bigpid.replace(0, copy_size, pid, 0, copy_size);
            std::vector<char> bp(bigpid.begin(),bigpid.end());
            //unsigned char* PC1(const unsigned char* key, unsigned int klen, const unsigned char* src,
             //   unsigned char* dest, unsigned int len, int decryption)
            //temp_key = PC1(keyvec1, bigpid, False)

            std::vector<char> temp_key = PC1d(keyvec1, bp, 0);
            int temp_key_sum = 0;
            for (auto c : temp_key)
            {
                temp_key_sum += (UCHAR)c;
            }
            temp_key_sum &= 0xff;
            found_key.clear();
            for (int i = 0; i < count; i++)
            {
                uint32_t verification = unpack_L(&data[i * 0x30]);
                uint32_t size = unpack_L(&data[i * 0x30+4]);
                uint32_t type = unpack_L(&data[i * 0x30 + 8]);
                char cksum = data[i * 0x30 + 12];
                std::vector<char> cookie(&data[i * 0x30 + 16], &data[i * 0x30 + 16 + 32]);
                if ((UCHAR)cksum == (UCHAR)temp_key_sum)
                {
                    cookie = PC1d(temp_key, cookie, 1);
                    /*
                    ver,flags,finalkey,expiry,expiry2 = struct.unpack('>LL16sLL', cookie)
                    if verification == ver and (flags & 0x1F) == 1:
                        found_key = finalkey
                        break
                    */
                    uint32_t ver = unpack_L(&cookie[0]);
                    uint32_t flags = unpack_L(&cookie[4]);
                    std::vector<char> finalkey(cookie.begin()+8, cookie.begin() + 8+16);
                    if (ver == verification && (flags & 0x1f) == 1)
                    {
                        found_key = finalkey;
                        fpid = pid;
                        break;
                    }
                }
                
            }
            if (found_key.size() > 0)
            {
                break;
            }
        }
        if (found_key.size() == 0)
        {
            std::string  pid = "00000000";
            std::vector<char> temp_key = keyvec1;
            int temp_key_sum = 0;
            for (auto c : temp_key)
            {
                temp_key_sum += (UCHAR)c;
            }
            temp_key_sum &= 0xff;
            for (int i = 0; i < count; i++)
            {
                uint32_t verification = unpack_L(&data[i * 0x30]);
                uint32_t size = unpack_L(&data[i * 0x30 + 4]);
                uint32_t type = unpack_L(&data[i * 0x30 + 8]);
                char cksum = data[i * 0x30 + 9];
                std::vector<char> cookie(&data[i * 0x30 + 12], &data[i * 0x30 + 12 + 32]);
                if (cksum == temp_key_sum)
                {
                    cookie = PC1d(temp_key, cookie, 1);
                    uint32_t ver = unpack_L(&cookie[0]);
                    uint32_t flags = unpack_L(&cookie[4]);
                    std::vector<char> finalkey(cookie.begin() + 8, cookie.begin() + 8 + 16);
                    if (ver == verification && (flags & 0x1f) == 1)
                    {
                        found_key = finalkey;
                        fpid = pid;
                        break;
                    }
                }

            }
        }
        return { found_key,fpid };
    }
    virtual void processBook(const std::vector<std::string>& pids) 
    {
        crypto_type = unpack_H(&sect[0xc]);
        std::cout << "Crypto type is " << crypto_type << std::endl;
        if (crypto_type == 0)
        {
            std::cout << "Book is not encrypted " << std::endl;
            std::vector<char> sec1 = loadSection(1);
            print_replica = (sec1[0] == '%' && sec1[1] == 'M' && sec1[2] == 'O' && sec1[3] == 'P');
            mobi_data = data_file;
            return;
        }
        if (crypto_type != 2 && crypto_type != 1)
        {
            throw DrmException("Cannot decode unknown Mobipocket encryption type");
        }
        std::vector<std::string> goodpids;
        for (auto pid : pids)
        {
            if (pid.size() == 8)
            {
                goodpids.push_back(pid);
            }
            if (pid.size() == 10)
            {
                std::string ck = checksumPID(pid.substr(0, 8));
                if (ck != pid)
                {
                    std::cout << "Warning PID checksum does not match: old: " << pid << " new: " << ck<<std::endl;
                }
                goodpids.push_back(pid.substr(0, 8));
            }
        }
        std::string fpid;
        std::vector<char> found_key;
        if (crypto_type == 1)
        {
            std::vector<char> t1_keyvec = HexToBytesC("5144435645504d55363735525542535a");
            std::vector<char> bookkey_data;
            if (magic == "TEXtREAd")
            {
                bookkey_data = std::vector<char>(sect.begin()+0xe, sect.begin() + 0xe+16);
            }
            else
            {
                if (mobi_version < 0)
                {
                    bookkey_data = std::vector<char>(sect.begin() + 0x90, sect.begin() + 0x90 + 16);
                }
                else
                {
                    bookkey_data = std::vector<char>(sect.begin() + 16+ mobi_length, sect.begin() + mobi_length + 32);
                }

            }
            fpid = "00000000";
            found_key = PC1d(t1_keyvec, bookkey_data,1);
        }
        else
        {
            uint32_t drm_ptr = unpack_L(&sect[0xa8]);
            uint32_t drm_count = unpack_L(&sect[0xa8+4]);
            uint32_t drm_size = unpack_L(&sect[0xa8 + 8]);
            uint32_t drm_flags = unpack_L(&sect[0xa8 + 12]);
            if (drm_count == 0)
            {
                throw DrmException("MOBI Encryption not initialised.");
            }
            std::pair<std::vector<char>, std::string> fkp = parseDRM(&sect[drm_ptr], drm_count, goodpids);
            if (fkp.first.size() == 0)
            {
                std::cout << "Tried  " << goodpids.size() << " PIDS " << std::endl;
                throw DrmException("No key found");
            }
            found_key = fkp.first;
            fpid = fkp.second;
            std::vector<char> b;
            b.resize(drm_size);
            patchSection(0, &b[0], drm_size, drm_ptr);
            b.resize(16);
            b[0] = -1;// 0xff;
            b[1] = -1;// 0xff;
            b[2] = -1;// 0xff;
            b[3] = -1;// 0xff;
            patchSection(0, &b[0], 16, 0xA8);
        }
        if (fpid == "00000000")
        {
            std::cout << "File has default encryption, no specific key needed." << std::endl;
        }
        else
        {
            std::cout << "File is encoded with PID " <<fpid<< std::endl;
        }
        uint16_t ss = 0;
        patchSection(0, (const char*)&ss, 2, 0xC);
        std::cout << "Decrypting..." << std::endl;
        std::vector<std::vector<char>> mobidataList;
        mobidataList.push_back(std::vector<char>(data_file.begin(), data_file.begin()+sections[1].offset));
        for (int i = 1; i < records + 1; i++)
        {
            std::vector<char> data = loadSection(i);
            size_t extra_size = getSizeOfTrailingDataEntries(&data[0], data.size(), extra_data_flags);
            std::vector<char> truncated = std::vector<char>(data.begin(), data.begin() + data.size()-extra_size);
            std::vector<char> decoded_data = PC1d(found_key, truncated, 1);
            print_replica = (decoded_data[0] == '%' && decoded_data[1] == 'M' && decoded_data[2] == 'O' && decoded_data[3] == 'P');
            mobidataList.push_back(decoded_data);
            if (extra_size > 0)
            {
                mobidataList.push_back(std::vector<char>( data.begin() + data.size() - extra_size,data.end()));
            }
        }
        if (num_sections > records + 1)
        {
            mobidataList.push_back(std::vector<char>(data_file.begin()+ sections[records + 1].offset, data_file.end()));
        }
        size_t totalSize = 0;
        for (const auto& subVector : mobidataList) {
            totalSize += subVector.size();
        }
        mobi_data.reserve(totalSize);

        // 3. Append each inner vector to the single flat vector
        for (const auto& subVector : mobidataList) {
            mobi_data.insert(mobi_data.end(), subVector.begin(), subVector.end());
        }
        std::cout << "Done parsing MOBI" << std::endl;
    }
    virtual void cleanup() {}
};

//--------------------------------------- ION reader


const uint8_t TID_NULL = 0;
const uint8_t TID_BOOLEAN = 1;
const uint8_t TID_POSINT = 2;
const uint8_t TID_NEGINT = 3;
const uint8_t TID_FLOAT = 4;
const uint8_t TID_DECIMAL = 5;
const uint8_t TID_TIMESTAMP = 6;
const uint8_t TID_SYMBOL = 7;
const uint8_t TID_STRING = 8;
const uint8_t TID_CLOB = 9;
const uint8_t TID_BLOB = 0xA;
const uint8_t TID_LIST = 0xB;
const uint8_t TID_SEXP = 0xC;
const uint8_t TID_STRUCT = 0xD;
const uint8_t TID_TYPEDECL = 0xE;
const uint8_t TID_UNUSED = 0xF;


const int SID_UNKNOWN = -1;
const int SID_ION = 1;
const int SID_ION_1_0 = 2;
const int SID_ION_SYMBOL_TABLE = 3;
const int SID_NAME = 4;
const int SID_VERSION = 5;
const int SID_IMPORTS = 6;
const int SID_SYMBOLS = 7;
const int SID_MAX_ID = 8;
const int SID_ION_SHARED_SYMBOL_TABLE = 9;
const int SID_ION_1_0_MAX = 10;


const uint8_t LEN_IS_VAR_LEN = 0xE;
const uint8_t LEN_IS_NULL = 0xF;


const uint8_t VERSION_MARKER[3] = { (uint8_t)0x01, (uint8_t)0x00, (uint8_t)0xEA };


struct IonCatalogItem
{
    std::string name = "";
    int version = 0;
    std::vector<std::string> symnames;
    IonCatalogItem(const std::string& nm, int ver, const std::vector < std::string >& snames)
    {
        name = nm;
        version = ver;
        symnames = snames;
    }
};
struct SymbolToken
{
    std::string text;
    int sid = 0;
    SymbolToken(const std::string& txt, int sd)
    {
        text = txt;
        sid = sd;
        if (txt.empty() && sid == 0)
        {
            std::cerr << "SymbolToken must have text or sid " << std::endl;
        }
    }
};

const char* SystemSymbols_ION = "$ion";
const char* SystemSymbols_ION_1_0 = "$ion_1_0";
const char* SystemSymbols_ION_SYMBOL_TABLE = "$ion_symbol_table";
const char* SystemSymbols_NAME = "name";
const char* SystemSymbols_VERSION = "version";
const char* SystemSymbols_IMPORTS = "imports";
const char* SystemSymbols_SYMBOLS = "symbols";
const char* SystemSymbols_MAX_ID = "max_id";
const char* SystemSymbols_ION_SHARED_SYMBOL_TABLE = "$ion_shared_symbol_table";

struct SymbolTable
{
    std::vector <std::string> table;
    SymbolTable()
    {
        table.resize(SID_ION_1_0_MAX, "");
        table[SID_ION] = SystemSymbols_ION;
        table[SID_ION_1_0] = SystemSymbols_ION_1_0;
        table[SID_ION_SYMBOL_TABLE] = SystemSymbols_ION_SYMBOL_TABLE;
        table[SID_NAME] = SystemSymbols_NAME;
        table[SID_VERSION] = SystemSymbols_VERSION;
        table[SID_IMPORTS] = SystemSymbols_IMPORTS;
        table[SID_SYMBOLS] = SystemSymbols_SYMBOLS;
        table[SID_MAX_ID] = SystemSymbols_MAX_ID;
        table[SID_ION_SHARED_SYMBOL_TABLE] = SystemSymbols_ION_SHARED_SYMBOL_TABLE;
    }
    std::string findbyid(int sid)
    {
        if (sid < 1)
        {
            std::cerr << "Invalid SID " << sid << std::endl;
            return "";
        }
        if ((unsigned int)sid < table.size())
        {
            return table[sid];
        }
        return "";
    }
    void import_(const std::vector<std::string>& stable, size_t maxid)
    {
        maxid = (stable.size() < maxid) ? stable.size() : maxid;
        for (size_t i = 0; i < maxid; i++)
        {
            table.push_back(stable[i]);
        }
    }
    void importunknown(const std::string& name, size_t maxid)
    {
        for (size_t i = 0; i < maxid; i++)
        {
            std::ostringstream s;
            s << name << (i + 1);
            std::string query(s.str());
            table.push_back(s.str());
        }
    }
};

enum ParserState
{
    None = 0,
    Invalid = 1,
    BeforeField = 2,
    BeforeTID = 3,
    BeforeValue = 4,
    AfterValue = 5,
    EOFF = 6
};

//ContainerRec = collections.namedtuple("ContainerRec", "nextpos, tid, remaining")
struct ContainerRec
{
    int nextpos;
    int tid;
    int remaining;
    ContainerRec(int n, int t, int r)
    {
        nextpos = n;
        tid = t;
        remaining = r;
    }
};
enum class IonVtype
{
    None = 0,
    String = 1,
    Integer = 2,
    LongInt = 3,
    Vector = 4
};
struct IonValue
{

};
struct BinaryIonParser
{
    bool eof = false;
    ParserState state = None;
    int localremaining = 0;
    bool   needhasnext = false;
    bool  isinstruct = false;
    int valuetid = 0;
    int  valuefieldid = 0;
    int    parenttid = 0;
    int valuelen = 0;
    bool  valueisnull = false;
    bool    valueistrue = false;
    IonVtype vtype = IonVtype::None;
    std::string sval = "";
    int ival = 0;
    long long int lval = 0;
    std::vector<uint8_t> vec;
    void assignIonValue()
    {

    }
    void assignIonValue(const std::string& v)
    {
        valueisnull = false;
        vtype = IonVtype::String;
        sval = v;
    }
    void assignIonValue(const std::vector<uint8_t>& v)
    {
        valueisnull = false;
        vtype = IonVtype::Vector;
        vec = v;
    }
    void assignIonValue(int v)
    {
        valueisnull = false;
        vtype = IonVtype::Integer;
        ival = v;
    }
    void assignIonValue(long long int v)
    {
        valueisnull = false;
        vtype = IonVtype::LongInt;
        lval = v;
    }
    bool didimports = false;
    std::vector<int> annotations;
    std::vector<IonCatalogItem> catalog;
    SymbolTable symbols;
    std::vector<ContainerRec> containerstack;
    uint8_t* stream;
    size_t maxstrlen;
    size_t stream_pos;
    bool readerr = false;
    int eFTid = -1;
    BinaryIonParser(uint8_t* stream, size_t maxlen, int enforceFirstTid)
    {
        this->stream = stream;
        maxstrlen = maxlen;
        stream_pos = 0;
        eFTid = enforceFirstTid;
        reset();
    }
    void resetFor(uint8_t* stream, size_t maxlen)
    {
        this->stream = stream;
        maxstrlen = maxlen;
        stream_pos = 0;
        reset();
        clearvalue();
    }
    void reset()
    {
        state = ParserState::BeforeTID;
        needhasnext = true;
        localremaining = -1;
        eof = false;
        isinstruct = false;
        containerstack.clear();
        stream_pos = 0;
    }
    void addtocatalog(const std::string& name, int ver, const std::vector<std::string>& snames)
    {
        catalog.push_back(IonCatalogItem(name, ver, snames));
    }
    void clearvalue()
    {
        valuetid = -1;
        vtype = IonVtype::None;
        valueisnull = false;
        valuefieldid = SID_UNKNOWN;
        annotations.clear();
        // readerr = false;
    }
    int readfieldid()
    {
        if (readerr) return -1;
        // readerr = false;
        if (localremaining != -1 && localremaining < 1) return -1;
        int ret = readvaruint();
        if (readerr) return -1;
        return ret;
    }
    uint8_t* read()
    {
        return read(1);
    }
    uint8_t* read(int count)
    {
        //std::cout << " Reading " << (int)stream << " at " << stream_pos << " len: " << count << " localrem: "<< localremaining <<std::endl;
        if (localremaining != -1)
        {
            localremaining -= count;
            if (localremaining < 0)
            {
                readerr = true;
                return nullptr;
            }
        }
        uint8_t* res = &stream[stream_pos];
        stream_pos += count;
        if (stream_pos > maxstrlen)
        {
            eof = true;
            readerr = true;
            return nullptr;
        }
        return res;
    }
    int readvarint()
    {
        if (readerr) return 0;
        uint8_t* r = read();
        if (readerr) return 0;
        uint8_t b = r[0];
        bool negative = ((b & 0x40) != 0);
        int result = b & 0x3F;
        int i = 0;
        while ((b & 0x80) == 0 && i < 4)
        {
            r = read();
            b = r[0];
            if (readerr) return 0;
            result = (result << 7) | (b & 0x7F);
            i++;
        }
        if (!(i < 4 || (r[0] & 0x80) != 0))
        {
            readerr = true;
            return 0;
        }
        if (negative) return -result;
        return result;
    }
    unsigned int  readvaruint()
    {
        if (readerr) return 0;
        //std::cout << hexStr(&stream[stream_pos], 4) << std::endl;
        uint8_t* r = read();
        if (readerr) return 0;
        uint8_t b = r[0];
        int result = b & 0x7F;
        int i = 0;
        while ((b & 0x80) == 0 && i < 4)
        {
            r = read();
            b = r[0];
            if (readerr) return 0;
            result = (result << 7) | (b & 0x7F);
            i++;
        }
        if (!(i < 4 || (r[0] & 0x80) != 0))
        {
            readerr = true;
            return 0;
        }
        return result;
    }

    void push(int tpid, int nxtpos, int nxtrem)
    {
        containerstack.push_back(ContainerRec(nxtpos, tpid, nxtrem));
    }
    void skip(int count)
    {
        read(count);
    }

    bool hasnextraw()
    {
        if (readerr) return false;
        clearvalue();
        while (valuetid == -1 && !eof)
        {
            //std::cout << "State:" << (int)state << std::endl;
            needhasnext = false;
            switch (state)
            {
            case ParserState::BeforeField:
            {
                if (valuefieldid != SID_UNKNOWN) return false;
                valuefieldid = readfieldid();
                if (valuefieldid != SID_UNKNOWN)
                    state = ParserState::BeforeTID;
                else
                {
                    eof = true;
                }
            }; break;
            case ParserState::BeforeTID:
            {
                state = ParserState::BeforeValue;
                //std::cout << "Getting tid " << std::endl;
                valuetid = readtypeid();
                // std::cout << "Getvtid " << valuetid <<" "<<readerr<< " Eftid "<< eFTid<<std::endl;
                if (readerr) valuetid = -1;
                if (eFTid >= 0 && valuetid != eFTid)
                {
                    valuetid = -1;
                    eFTid = -1;
                }
                if (valuetid == -1)
                {
                    state = ParserState::EOFF;
                    eof = true;
                    return false;
                    //break;
                }
                else
                {
                    eFTid = -1;
                    // std::cout << "Got tid " << valuetid << "  " << readerr << " vallen "<<valuelen<< std::endl;
                    if (valuetid == TID_TYPEDECL)
                    {
                        if (valuelen == 0)
                        {
                            checkversionmarker();
                            if (readerr) return false;
                        }
                        else
                        {
                            loadannotations();
                            if (readerr) return false;
                        }
                    }
                }
            }; break;
            case ParserState::BeforeValue: {
                skip(valuelen);
                if (readerr) return false;
                state = ParserState::AfterValue;
            }; break;

            case ParserState::AfterValue: {
                if (isinstruct)
                {
                    state = ParserState::BeforeField;
                }
                else
                {
                    state = ParserState::BeforeTID;
                }
            }; break;
            default:
            {
                if (state != ParserState::EOFF) return false;
                eof = true;
            }; break;
            }
            if (eof) break;
        }
        return true;
    }
    bool hasnext()
    {
        if (readerr) return false;
        while (needhasnext && !eof)
        {
            if (!hasnextraw()) return false;
            //std::cout << "Might have next" << std::endl;
            if (containerstack.size() == 0 && !valueisnull)
            {
                if (valuetid == TID_SYMBOL)
                {
                    if (vtype == IonVtype::Integer && ival == SID_ION_1_0)
                    {
                        needhasnext = true;
                    }

                }
                else
                {
                    if (valuetid == TID_STRUCT)
                    {
                        for (size_t ii = 0; ii < annotations.size(); ii++)
                        {
                            if (annotations[ii] == SID_ION_SYMBOL_TABLE)
                            {
                                parsesymboltable();
                                needhasnext = true;
                            }
                        }
                    }
                }
            }
        }
        return !eof;
    }

    int next()
    {
        if (readerr) return -1;
        if (hasnext())
        {
            needhasnext = true;
            return valuetid;
        }
        return -1;
    }
    int readtypeid()
    {
        if (readerr) return -1;
        if (localremaining != -1)
        {
            if (localremaining < 1) return -1;
            localremaining -= 1;
        }
        if (stream_pos >= maxstrlen)
        {
            readerr = true;
            return -1;
        }
        uint8_t b = stream[stream_pos];
        stream_pos += 1;
        int result = (int)b;
        result = result >> 4;
        int ln = (int)b & 0xf;
        //std::cout << "Result: " << result << " len " << ln <<" at " << stream_pos <<std::endl;
        if (ln == LEN_IS_VAR_LEN)
        {
            ln = readvaruint();
            if (readerr) return -1;
        }
        else
        {
            if (ln == LEN_IS_NULL)
            {
                ln = 0;
                state = ParserState::AfterValue;
            }
            else if (result == TID_NULL)
            {
                readerr = true; //invalid stream
                return -1;
            }
            else if (result == TID_BOOLEAN)
            {
                if (ln > 1)
                {
                    readerr = true; //invalid stream
                    return -1;
                }
                valueistrue = (ln == 1);
            }
            else if (result == TID_STRUCT)
            {
                if (ln == 1)
                {
                    ln = readvaruint();
                }
            }
        }
        valuelen = ln;
        //std::cout << "Rlen: " << ln << std::endl;
        return result;
    }
    void stepin()
    {

        if (readerr) return;
        //std::cout << "Valuetid: " << valuetid << std::endl;
        if (eof)
        {
            readerr = true;
            return;
        }
        if (valuetid != TID_STRUCT && valuetid != TID_LIST && valuetid != TID_SEXP)
        {
            readerr = true;
            return;
        }

        if (!((!valueisnull || state == ParserState::AfterValue) && (valueisnull || state == ParserState::BeforeValue)))
        {
            readerr = true;
            return;
        }
        //std::cout << "Stepping in vlen: " << valuelen << " nextpos "<< stream_pos + valuelen<< std::endl;
        int nextrem = localremaining;
        if (nextrem != -1)
        {
            nextrem -= valuelen;
            if (nextrem < 0)
            {
                readerr = true;
                return;
            }
        }
        push(parenttid, stream_pos + valuelen, nextrem);
        isinstruct = (valuetid == TID_STRUCT);
        if (isinstruct)
        {
            state = ParserState::BeforeField;
        }
        else
        {
            state = ParserState::BeforeTID;
        }
        localremaining = valuelen;
        parenttid = valuetid;
        clearvalue();
        needhasnext = true;
    }
    void stepout()
    {
        if (readerr) return;
        if (containerstack.size() == 0)
        {
            readerr = true;
            return;
        }
        //std::cout << "Stepping out " << std::endl;
        ContainerRec rec = containerstack.back();
        containerstack.pop_back();
        eof = false;
        parenttid = rec.tid;
        if (parenttid == (int)TID_STRUCT)
        {
            isinstruct = true;
            state = ParserState::BeforeField;
        }
        else
        {
            isinstruct = false;
            state = ParserState::BeforeTID;
        }
        needhasnext = true;
        clearvalue();
        int curpos = (int)stream_pos;
        // std::cout << "Curpos " << curpos << " nextpos " << rec.nextpos << std::endl;
        if (rec.nextpos > curpos)
        {
            skip(rec.nextpos - curpos);
        }
        else
        {
            if (rec.nextpos != curpos)
            {
                readerr = true;
                return;
            }
        }
        localremaining = rec.remaining;

    }
    long long readdecimal()
    {
        if (valuelen == 0)
        {
            return 0;
        }
        if (readerr) return 0;

        int rem = localremaining - valuelen;
        localremaining = valuelen;
        int exponent = readvarint();
        if (readerr) return 0;
        if (localremaining <= 0 || localremaining > 8)
        {
            readerr = true;
            return 0;
        }
        bool sign = false;
        uint8_t* b = read(localremaining);
        if (readerr) return 0;
        if ((b[0] & 0x80) != 0)
        {
            sign = true;
        }
        long long v = 0;
        for (int j = 0; j < localremaining; j++)
        {
            uint8_t bb = b[j];
            if (j == 0 && sign)
            {
                bb = bb & 0x7f;
            }
            v = (v >> 8) + bb;

        }
        long long res = (long long)v;
        for (int e = 0; e < exponent; e++) //this be dumb;
        {
            res *= e;
        }
        if (sign)
        {
            res = -res;
        }
        localremaining = rem;
        return res;
    }
    void parsesymboltable()
    {
        next();
        if (valuetid != TID_STRUCT)
        {
            readerr = true;
            return;
        }
        if (didimports) return;
        stepin();
        int fieldtype = next();
        // std::cout << "Fieldtype " << fieldtype << std::endl;
        while (fieldtype != -1)
        {
            if (!valueisnull)
            {
                if (valuefieldid != SID_IMPORTS)
                {
                    readerr = true;
                    return;
                }
                if (fieldtype == TID_LIST)
                {
                    gatherimports();
                }
            }
            fieldtype = next();
            //std::cout << "Fieldtype " << fieldtype << std::endl;
        }
        stepout();
        didimports = true;

    }
    void gatherimports()
    {
        stepin();
        int t = next();
        while (t != -1)
        {
            if (!valueisnull && t == TID_STRUCT)
            {
                readimport();
            }
            t = next();
        }
        stepout();
    }
    void erval()
    {
        vtype = IonVtype::None;

    }
    void loadscalarvalue()
    {
        if (valuetid != TID_NULL && valuetid != TID_BOOLEAN && valuetid != TID_POSINT &&
            valuetid != TID_NEGINT && valuetid != TID_FLOAT && valuetid != TID_DECIMAL &&
            valuetid != TID_SYMBOL && valuetid != TID_STRING && valuetid != TID_TIMESTAMP)
        {
            return;
        }
        //std::cout << "Load scalar val " << std::endl;
        if (valueisnull)
        {
            erval();
            return;
        }
        erval();
        switch (valuetid)
        {
        case TID_STRING: {
            char* buf = (char*)read(valuelen);
            if (readerr) return;
            assignIonValue(std::string(buf, valuelen));
        }; break;
        case TID_POSINT:
        case TID_NEGINT:
        case TID_SYMBOL: {
            if (valuelen == 0)
            {
                assignIonValue((int)0);

            }
            else
            {
                if (valuelen > 4)
                {
                    readerr = true;
                    return;
                }
                int v = 0;
                for (int j = 0; j < valuelen; j++)
                {
                    uint8_t* b = read();
                    if (readerr) return;
                    v = (v << 8) + b[0];
                }
                if (valuetid == TID_NEGINT)
                {
                    v = -v;
                }
                assignIonValue(v);
            }
        }; break;
        case TID_DECIMAL: {
            long long r = readdecimal();
            if (readerr) return;
            assignIonValue(r);
        }; break;
        default:
            readerr = true;
        }
        state = ParserState::AfterValue;
    }

    void preparevalue()
    {
        if (vtype == IonVtype::None)
        {
            loadscalarvalue();
        }
    }
    IonCatalogItem findcatalogitem(const std::string& name)
    {
        for (auto it = catalog.begin(); it != catalog.end(); ++it)
        {
            if (it->name == name)
            {
                return *it;
            }
        }
        return IonCatalogItem("-", -1, std::vector<std::string>()); //also dumb
    }

    void readimport()
    {
        int version = -1;
        int maxid = -1;
        std::string name = "";
        stepin();
        int t = next();
        while (t != -1)
        {
            if (!valueisnull && valuefieldid != SID_UNKNOWN)
            {
                switch (valuefieldid)
                {
                case SID_NAME: {
                    name = stringvalue();
                }; break;
                case SID_VERSION: {
                    version = intvalue();
                }; break;
                case SID_MAX_ID: {
                    maxid = intvalue();
                }; break;
                default:break;
                }
            }
            t = next();
        }
        stepout();
        if (name == "" || name == SystemSymbols_ION)
        {
            return;
        }
        if (version < 1) version = 1;
        IonCatalogItem table = findcatalogitem(name);
        if (maxid < 0)
        {
            if (table.name == "-")
            {
                readerr = true;
                return;
            }
            if (version != table.version)
            {
                readerr = true;
                return;
            }
            maxid = (int)table.symnames.size();
        }
        if (table.name != "-")
        {
            symbols.import_(table.symnames, min((size_t)maxid, table.symnames.size()));
            if (table.symnames.size() < (size_t)maxid)
            {
                symbols.importunknown(name + "-unknown", maxid - table.symnames.size());
            }
        }
        else
        {
            symbols.importunknown(name, maxid);
        }
    }
    int  intvalue()
    {
        if (valuetid != TID_POSINT && valuetid != TID_NEGINT)
        {
            readerr = true;
            return 0;
        }
        preparevalue();
        if (readerr || vtype == IonVtype::None)
        {
            return 0;
        }
        return ival;
    }

    std::string  stringvalue()
    {
        //std::cout << "Stringvalue" << std::endl;
        if (valuetid != TID_STRING)
        {
            readerr = true;
            return "";
        }
        preparevalue();
        if (readerr || vtype == IonVtype::None)
        {
            return "";
        }
        //std::cout << "Stringvalue out " << sval<<std::endl;
        return sval;
    }
    std::string symbolvalue()
    {
        if (valuetid != TID_SYMBOL)
        {
            readerr = true;
            return "";
        }
        preparevalue();
        if (readerr || vtype == IonVtype::None)
        {
            return "";
        }
        std::string result = symbols.findbyid(ival);
        if (result == "")
        {
            std::ostringstream s;
            s << "SYMBOL#" << (ival);
            result = s.str();
        }
        return result;
    }
    std::vector<uint8_t> lobvalue()
    {
        if (valuetid != TID_CLOB && valuetid != TID_BLOB)
        {
            readerr = true;
            return  std::vector<uint8_t>();
        }
        if (valueisnull)
        {
            return  std::vector<uint8_t>();
        }
        uint8_t* buf = read(valuelen);
        if (readerr)
        {
            return  std::vector<uint8_t>();
        }
        state = ParserState::AfterValue;
        return std::vector<uint8_t>(&buf[0], &buf[valuelen]);
    }
    long long decimalvalue()
    {
        if (valuetid != TID_DECIMAL)
        {
            readerr = true;
            return 0;
        }
        preparevalue();
        if (readerr || vtype == IonVtype::None)
        {
            return 0;
        }
        return lval;
    }
    void loadannotations()
    {
        unsigned int ln = readvaruint();
        if (readerr) return;
        size_t maxpos = stream_pos + ln;
        //std::cout << "Annots " << ln<<std::endl;
        while (stream_pos < maxpos)
        {
            unsigned int nx = readvaruint();
            if (readerr) return;
            //std::cout << "Annotation " << nx << std::endl;
            annotations.push_back(nx);
        }
        valuetid = readtypeid();
    }
    void  forceimport(const std::vector<std::string>& sym)
    {
        //IonCatalogItem  item = IonCatalogItem("Forced", 1, sym);
        symbols.import_(sym, sym.size());
    }
    std::string getfieldname()
    {
        if (valuefieldid == SID_UNKNOWN) return "";
        return symbols.findbyid(valuefieldid);

    }
    void  checkversionmarker()
    {
        uint8_t* rd = read(sizeof(VERSION_MARKER));

        if (readerr) return;
        for (int i = 0; i < sizeof(VERSION_MARKER); i++)
        {
            if (rd[i] != VERSION_MARKER[i])
            {
                readerr = true;
                return;
            }
        }
        valuelen = true;
        valuetid = TID_SYMBOL;
        assignIonValue(SID_ION_1_0);
        valueisnull = false;
        valuefieldid = SID_UNKNOWN;
        state = ParserState::AfterValue;
    }
    SymbolToken getfieldnamesymbol()
    {
        return SymbolToken(getfieldname(), valuefieldid);
    }
    std::string gettypename()
    {
        if (annotations.size() == 0) return "";
        return symbols.findbyid(annotations[0]);
    }
    int getAnnotType()
    {
        if (annotations.size() == 0) return -1;
        return annotations[0];
    }
};

std::vector<std::string> SYM_NAMES()
{
    std::vector<std::string> SYM_NAMESr = { "com.amazon.drm.Envelope@1.0", "com.amazon.drm.EnvelopeMetadata@1.0","size","page_size",
    "encryption_key","encryption_transformation","encryption_voucher","signing_key","signing_algorithm","signing_voucher",
    "com.amazon.drm.EncryptedPage@1.0","cipher_text","cipher_iv","com.amazon.drm.Signature@1.0",
    "data","com.amazon.drm.EnvelopeIndexTable@1.0","length",
              "offset", "algorithm", "encoded", "encryption_algorithm",
              "hashing_algorithm", "expires", "format", "id",
              "lock_parameters", "strategy", "com.amazon.drm.Key@1.0",
              "com.amazon.drm.KeySet@1.0", "com.amazon.drm.PIDv3@1.0",
              "com.amazon.drm.PlainTextPage@1.0",
              "com.amazon.drm.PlainText@1.0", "com.amazon.drm.PrivateKey@1.0",
              "com.amazon.drm.PublicKey@1.0", "com.amazon.drm.SecretKey@1.0",
              "com.amazon.drm.Voucher@1.0", "public_key", "private_key",
              "com.amazon.drm.KeyPair@1.0", "com.amazon.drm.ProtectedData@1.0",
              "doctype", "com.amazon.drm.EnvelopeIndexTableOffset@1.0",
              "enddoc", "license_type", "license", "watermark", "key", "value",
              "com.amazon.drm.License@1.0", "category", "metadata",
              "categorized_metadata", "com.amazon.drm.CategorizedMetadata@1.0",
              "com.amazon.drm.VoucherEnvelope@1.0", "mac", "voucher",
              "com.amazon.drm.ProtectedData@2.0",
              "com.amazon.drm.Envelope@2.0",
              "com.amazon.drm.EnvelopeMetadata@2.0",
              "com.amazon.drm.EncryptedPage@2.0",
              "com.amazon.drm.PlainText@2.0", "compression_algorithm",
              "com.amazon.drm.Compressed@1.0", "page_index_table" };
    // can not be bothered...
    for (int i = 1; i < 200; i++)
    {
        std::ostringstream s;
        s << "com.amazon.drm.VoucherEnvelope@" << (i);
        SYM_NAMESr.push_back(s.str());
    }
    return SYM_NAMESr;
}
void  addprottable(BinaryIonParser* ion)
{
    if (!ion) return;
    ion->addtocatalog("ProtectedData", 1, SYM_NAMES());
}

SSIZE_T finIndexIn(const std::vector<std::string>& p, const std::string& val)
{
    for (size_t i = 0; i < p.size(); i++)
    {
        if (p[i] == val) return i;
    }
    return -1;
}

//--------------------------------------------------end ION
std::vector<std::string> splitStringBySubstring(const std::string& str, const std::string& delimiter)
{
    std::vector<std::string> result;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::string::npos) {
        result.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    result.push_back(str.substr(start)); // Add the last part

    return result;
}
struct key_maps
{
    std::map<std::string, std::string> keyid_to_key;
    std::map<std::string, std::string> voucherid_to_key;
    void read_file(const fs::path& keyfile)
    {
        //std::list<std::string> splitStringBySubstring(const std::string& str, const std::string& delimiter)
        std::ifstream file(keyfile);
        if (!file.is_open()) 
        {
            std::cout << "Error: Could not open the keyfile at " << keyfile << std::endl;
            return;
        }
        std::string line;
        while (std::getline(file, line)) 
        {
            //amzn1.drm-voucher.v1.167417f9-e193-4833-ad1e-24cc8d6f34eb$secret_key:810xxx
            //std::cout << "Line " << line << std::endl;
            std::vector<std::string> ks = splitStringBySubstring(line, "$");
            if (ks.size() < 2) continue;
            std::string kname = ks[0];
            std::map<std::string, std::string>* ref = &keyid_to_key;
            if (kname.find("drm-voucher") != std::string::npos)
            {
               // printf("VOucher\n");
                ref = &voucherid_to_key;
            }
            for (int i = 1; i < ks.size(); i++)
            {
                std::vector<std::string> t_key= splitStringBySubstring(ks[i], ":");
                if (t_key.size() != 2) continue;
                if (t_key[0] != "secret_key") continue;
                (*ref)[kname] = t_key[1];
                break; //assume 1 key
            }
        }
        printf("Read %zu keyid %zu vouchers\n", keyid_to_key.size(), voucherid_to_key.size());
       // write_file("tmp.keyfile");
    }
    void write_file(const fs::path& keyfile)
    {
        std::ofstream file(keyfile);
        if (!file.is_open())
        {
            std::cout << "Error: Could not open the keyfile for writing at " << keyfile << std::endl;
            return;
        }
        for (const auto& kid : keyid_to_key)
        {
            file << kid.first << "$secret_key:" << kid.second << "\n";
        }
        for (const auto& vid : voucherid_to_key)
        {
            file << vid.first << "$secret_key:" << vid.second << "\n";
        }
    }
};
#if defined(_WIN32) && !defined(_WIN64)
int gedi(void) {
    unsigned int edi_value;
    __asm {
        mov edi_value, edi
    }
    return edi_value;
}
#endif
#ifdef _WIN64
INT_PTR grsi(void) {
    CONTEXT context;
    RtlCaptureContext(&context);
    return context.Rsi;
}
#endif
typedef INT_PTR (* get_mbox_par)(PCONTEXT ledi);
struct ppatch
{
    INT_PTR spatch = 0;
    std::vector<BYTE> patch = { 0x66, 0xB8, 0x01, 0x00, 0xC3 };
    std::vector<BYTE> unpatch;
    ppatch(INT_PTR sp,const  std::vector<BYTE>& ptch)
    {
        spatch = sp;
        patch = ptch;
    }
};
struct MbLut
{
    INT_PTR mpos = 0;
    INT_PTR readout=0;
    std::vector<std::vector<uint8_t>> lut;
    uint8_t slut=0;
    INT_PTR slt_offs = 0x1c000;
    INT_PTR mbox_create = 0;
    INT_PTR mbox_precreate = 0;
    get_mbox_par get_param =nullptr;
};
INT_PTR get_1(PCONTEXT ctx)
{
    // printf("Get2\n");
#if defined(_WIN32) && !defined(_WIN64)
    return ctx->Edi ;
#endif

#ifdef _WIN64
    return ctx->Rsi;
#endif
}
INT_PTR get_2(PCONTEXT ctx)
{
   // printf("Get2\n");
#if defined(_WIN32) && !defined(_WIN64)
    return ctx->Edi + 20;
#endif

#ifdef _WIN64
    return ctx->Rsi+20;
#endif
}
INT_PTR get_3(PCONTEXT ctx)
{
#if defined(_WIN32) && !defined(_WIN64)
    return ctx->Edi + 0x28;
#endif
#ifdef _WIN64
    return ctx->Rdi + 0x28;
#endif
}
struct ExecOffsets
{
    INT_PTR  luceneaddr = 0;
    INT_PTR  make_storage = 0;
    INT_PTR  get_storage_value = 0;
    INT_PTR  deobfuscate_storage = 0;
    INT_PTR  get_plugin_man = 0;
    INT_PTR  load_all = 0;
    INT_PTR  get_factory = 0;
    INT_PTR  open_book = 0;
    INT_PTR  drm_provider = 0;
    //int mem_offset = 0;
    INT_PTR  decr_offset = 0;
    INT_PTR  decr_offset_bare = 0;
   // int mbox_capture = 0;
    INT_PTR  entry = 0;
    size_t  mbox_size = 0;
    INT_PTR  mbox_size_bare = 0;
    INT_PTR  t_bare = 0;
    uint8_t o_bare = 0;
    int mbox_iv_offset = 0;
    int allemaric_shift=0;
  //  int spatch = 0;
    std::string version = "unk ";
    //std::vector<BYTE> patch = { 0x66, 0xB8, 0x01, 0x00, 0xC3 };
    std::vector<ppatch> spatches;
    std::vector<MbLut> mbox_data;
    int vernum = -1;
};
key_maps currentKeymaps;
ExecOffsets curOffs;
ExecOffsets KindleReader1_0_15230()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x11046bb0;
    ret.entry = 0;

    ret.make_storage = 0x10dbf3c0;
    ret.deobfuscate_storage= 0x1009b8d0;

    ret.get_storage_value = 0x1009c820;
    ret.spatches.push_back(ppatch(0x10065a60, { 0x66, 0xB8, 0x01, 0x00, 0xC3 }));
    //ret.spatch= 0x10065a60;
    ret.get_plugin_man = 0x11057890;
    ret.load_all = 0x11057990;

    ret.allemaric_shift = 12;
    ret.get_factory = 0x11067a50;
    ret.open_book = 0x11067b20;
    ret.drm_provider = 0x11067e60;
   // ret.mem_offset = 20;

    ret.decr_offset = 0x11b23780;


    ret.mbox_size = 119212;
    ret.mbox_iv_offset = 0x1d180;
    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.15230";
    ret.vernum = 0;
    return ret;
}

ExecOffsets KindleReader1_0_16034()
{
    ExecOffsets ret;
    ret.make_storage = 0x10dbf3c0;
    //ret.spatch = ;
    ret.spatches.push_back(ppatch(0x10065a60, { 0x66, 0xB8, 0x01, 0x00, 0xC3 }));

    ret.luceneaddr = 0x11046b60;
    ret.entry = 0;
    ret.deobfuscate_storage = 0x1009b8d0;
    ret.get_storage_value = 0x1009c820;
    ret.get_plugin_man = 0x11057840;
    ret.load_all = 0x11057940;
    ret.decr_offset = 0x11b23660;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;
    ret.get_factory = 0x11067a20;
    ret.open_book = 0x11067af0;
    ret.drm_provider = 0x11067e30;

    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.16034";
    ret.vernum = 1;
    return ret;
}
ExecOffsets KindleReader1_0_16118()
{
    ExecOffsets ret;
    ret.entry = 0;
    ret.deobfuscate_storage = 0x1009b8d0;
    ret.get_storage_value = 0x1009c820;
    ret.make_storage = 0x10dbf3c0;
   // ret.spatch = 0x10065a60;
    ret.spatches.push_back(ppatch(0x10065a60, { 0x66, 0xB8, 0x01, 0x00, 0xC3 }));

    ret.luceneaddr = 0x11046b60;
    ret.get_plugin_man = 0x11057840;
    ret.load_all = 0x11057940;
    ret.decr_offset = 0x11b23660;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;
    ret.get_factory = 0x11067a20;
    ret.open_book = 0x11067af0;
    ret.drm_provider = 0x11067e30;

    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.16118";
    ret.vernum = 2;
    return ret;
}
ExecOffsets KindleReader1_0_18320()
{
    ExecOffsets ret;
    ret.make_storage = 0x10dbf770;
    ret.luceneaddr = 0x11047130;
  //  ret.spatch = 0x10065a60;
    ret.spatches.push_back(ppatch(0x10065a60, { 0x66, 0xB8, 0x01, 0x00, 0xC3 }));
    ret.get_storage_value = 0x1009c870;
    ret.deobfuscate_storage = 0x1009b920;
    ret.get_plugin_man = 0x11057e10;
    ret.load_all = 0x11057f10;
    ret.decr_offset = 0x11b23b10;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;
    ret.get_factory = 0x11067fd0;
    ret.open_book = 0x110680a0;
    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.18320";
    ret.vernum = 3;
    ret.drm_provider = 0x110683e0;
    ret.entry = 0;
    return ret;
}

//a5af62fd27d6cf599575ba0c1c112985
ExecOffsets KindleReader1_0_18632()
{
    ExecOffsets ret;
    ret.get_factory = 0x11067fd0;
    ret.open_book = 0x110680a0;
    ret.luceneaddr = 0x11047130;
    ret.make_storage = 0x10dbf770;
   // ret.spatch = 0x10065a60;
    ret.spatches.push_back(ppatch(0x10065a60, { 0x66, 0xB8, 0x01, 0x00, 0xC3 }));
    ret.get_storage_value = 0x1009c870;
    ret.deobfuscate_storage = 0x1009b920;
    ret.get_plugin_man = 0x11057e10;
    ret.load_all = 0x11057f10;
    ret.drm_provider = 0x110683e0;
    

    ret.decr_offset = 0x11b23bf0;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;

    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.18632";
    ret.vernum = 4;
   
    ret.entry = 0;
    return ret;
}

//7a7f3827c80e19a4ebda38c2853eb590
ExecOffsets KindleReader1_0_22326()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x111498e0;
    ret.make_storage = 0x10eca5f0;
  //  ret.patch = { 0xe9, 0xd6, 0x00, 0x00, 0x00};// e9 df 00 00 00
    //ret.spatch = 0x10eca624;
    ret.spatches.push_back(ppatch(0x10eca624, { 0xe9, 0xd6, 0x00, 0x00, 0x00 }));
    ret.spatches.push_back(ppatch(0x10eca054, { 0xe9, 0xf9, 0x00, 0x00, 0x00 }));
   // ret.patch = { 0xe9, 0xf9, 0x00, 0x00, 0x00};// e9 df 00 00 00
   // ret.spatch = 0x10eca054;


    ret.get_storage_value = 0x1008ad10;
    ret.deobfuscate_storage = 0x10089dc0;
    ret.get_plugin_man = 0x1115a620;
    ret.load_all = 0x1115a720;
    ret.get_factory = 0x1116bd00;
    ret.open_book = 0x1116bdd0;
    ret.drm_provider = 0x1116c110;
    ret.decr_offset = 0x11bb80a0;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;

    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.22326";
    ret.vernum = 5;

    ret.entry = 0;
    return ret;
}

//5deec17cc97e250f1954a0c4b2c86005
ExecOffsets KindleReader1_0_22920()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x111498e0;
    ret.make_storage = 0x10eca5f0;
    //  ret.patch = { 0xe9, 0xd6, 0x00, 0x00, 0x00};// e9 df 00 00 00
      //ret.spatch = 0x10eca624;
    ret.spatches.push_back(ppatch(0x10eca624, { 0xe9, 0xd6, 0x00, 0x00, 0x00 }));
    ret.spatches.push_back(ppatch(0x10eca054, { 0xe9, 0xf9, 0x00, 0x00, 0x00 }));
    ret.get_storage_value = 0x1008ad10;
    ret.deobfuscate_storage = 0x10089dc0;
    ret.get_plugin_man = 0x1115a620;
    ret.load_all = 0x1115a720;
    ret.get_factory = 0x1116bd00;
    ret.open_book = 0x1116bdd0;
    ret.drm_provider = 0x1116c110;


    ret.decr_offset = 0x11bb80a0;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;

    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.22920";
    ret.vernum = 5;

    ret.entry = 0;
    return ret;
}
//f21b5ad7e1d05d3430cf2eb80cec6c97
ExecOffsets KindleReader1_0_23514()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x111499e0;
    ret.get_plugin_man = 0x1115a730;
    ret.load_all = 0x1115a830;
    ret.make_storage = 0x10eca690;

    ret.spatches.push_back(ppatch(0x10eca6c4, { 0xe9, 0xd6, 0x00, 0x00, 0x00 }));
    ret.spatches.push_back(ppatch(0x10eca0f4, { 0xe9, 0xf9, 0x00, 0x00, 0x00 }));
    ret.get_storage_value = 0x1008ad10;
    ret.deobfuscate_storage = 0x10089dc0;
    ret.drm_provider = 0x1116c230;

    ret.get_factory = 0x1116be20;
    ret.open_book = 0x1116bef0;



    ret.decr_offset = 0x11bb82b0;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;
    ret.allemaric_shift = 12;

    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.23514";
    ret.vernum = 6;

    ret.entry = 0;
    return ret;
}

//c19569a98e72d4e1109e6cfa37db47cf
ExecOffsets KindleReader1_0_23620()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x111499e0;
    ret.get_plugin_man = 0x1115a730;
    ret.load_all = 0x1115a830;
    ret.make_storage = 0x10eca690;

    ret.spatches.push_back(ppatch(0x10eca6c4, { 0xe9, 0xd6, 0x00, 0x00, 0x00 }));
    ret.spatches.push_back(ppatch(0x10eca0f4, { 0xe9, 0xf9, 0x00, 0x00, 0x00 }));
    ret.get_storage_value = 0x1008ad10;
    ret.deobfuscate_storage = 0x10089dc0;
    ret.drm_provider = 0x1116c230;

    ret.get_factory = 0x1116be20;
    ret.open_book = 0x1116bef0;
    


   // ret.decr_offset = 0x11bb8170;
 
    ret.mbox_size_bare = 119188;//0x1d1ac
    //ret.mbox_iv_offset = 0x1d180;
    
    ret.decr_offset = 0x11bb82b0;
    ret.mbox_size = 119212;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;

    ret.decr_offset_bare = 0x101d27e0;
    ret.t_bare = 0x129f6688;
    ret.o_bare = 30;

    
    ret.allemaric_shift = 12;

    //std::vector<MbLut> mbox_data;
    MbLut m1;
    m1.readout = 0x11bba9f0;//11bba9f0
    m1.lut = { {179, 112, 244, 55, 46, 237, 105, 170, 183, 116, 240, 51, 42, 233, 109, 174, 70, 133, 1, 194, 219, 24, 156, 95, 66, 129, 5, 198, 223, 28, 152, 91, 171, 104, 236, 47, 54, 245, 113, 178, 175, 108, 232, 43, 50, 241, 117, 182, 94, 157, 25, 218, 195, 0, 132, 71, 90, 153, 29, 222, 199, 4, 128, 67, 217, 26, 158, 93, 68, 135, 3, 192, 221, 30, 154, 89, 64, 131, 7, 196, 44, 239, 107, 168, 177, 114, 246, 53, 40, 235, 111, 172, 181, 118, 242, 49, 193, 2, 134, 69, 92, 159, 27, 216, 197, 6, 130, 65, 88, 155, 31, 220, 52, 247, 115, 176, 169, 106, 238, 45, 48, 243, 119, 180, 173, 110, 234, 41, 207, 12, 136, 75, 82, 145, 21, 214, 203, 8, 140, 79, 86, 149, 17, 210, 58, 249, 125, 190, 167, 100, 224, 35, 62, 253, 121, 186, 163, 96, 228, 39, 215, 20, 144, 83, 74, 137, 13, 206, 211, 16, 148, 87, 78, 141, 9, 202, 34, 225, 101, 166, 191, 124, 248, 59, 38, 229, 97, 162, 187, 120, 252, 63, 165, 102, 226, 33, 56, 251, 127, 188, 161, 98, 230, 37, 60, 255, 123, 184, 80, 147, 23, 212, 205, 14, 138, 73, 84, 151, 19, 208, 201, 10, 142, 77, 189, 126, 250, 57, 32, 227, 103, 164, 185, 122, 254, 61, 36, 231, 99, 160, 72, 139, 15, 204, 213, 22, 146, 81, 76, 143, 11, 200, 209, 18, 150, 85}, {159, 68, 24, 195, 50, 233, 181, 110, 221, 6, 90, 129, 112, 171, 247, 44, 5, 222, 130, 89, 168, 115, 47, 244, 71, 156, 192, 27, 234, 49, 109, 182, 36, 255, 163, 120, 137, 82, 14, 213, 102, 189, 225, 58, 203, 16, 76, 151, 190, 101, 57, 226, 19, 200, 148, 79, 252, 39, 123, 160, 81, 138, 214, 13, 119, 172, 240, 43, 218, 1, 93, 134, 53, 238, 178, 105, 152, 67, 31, 196, 237, 54, 106, 177, 64, 155, 199, 28, 175, 116, 40, 243, 2, 217, 133, 94, 204, 23, 75, 144, 97, 186, 230, 61, 142, 85, 9, 210, 35, 248, 164, 127, 86, 141, 209, 10, 251, 32, 124, 167, 20, 207, 147, 72, 185, 98, 62, 229, 205, 22, 74, 145, 96, 187, 231, 60, 143, 84, 8, 211, 34, 249, 165, 126, 87, 140, 208, 11, 250, 33, 125, 166, 21, 206, 146, 73, 184, 99, 63, 228, 118, 173, 241, 42, 219, 0, 92, 135, 52, 239, 179, 104, 153, 66, 30, 197, 236, 55, 107, 176, 65, 154, 198, 29, 174, 117, 41, 242, 3, 216, 132, 95, 37, 254, 162, 121, 136, 83, 15, 212, 103, 188, 224, 59, 202, 17, 77, 150, 191, 100, 56, 227, 18, 201, 149, 78, 253, 38, 122, 161, 80, 139, 215, 12, 158, 69, 25, 194, 51, 232, 180, 111, 220, 7, 91, 128, 113, 170, 246, 45, 4, 223, 131, 88, 169, 114, 46, 245, 70, 157, 193, 26, 235, 48, 108, 183}, {170, 137, 225, 194, 104, 75, 35, 0, 92, 127, 23, 52, 158, 189, 213, 246, 205, 238, 134, 165, 15, 44, 68, 103, 59, 24, 112, 83, 249, 218, 178, 145, 63, 28, 116, 87, 253, 222, 182, 149, 201, 234, 130, 161, 11, 40, 64, 99, 88, 123, 19, 48, 154, 185, 209, 242, 174, 141, 229, 198, 108, 79, 39, 4, 219, 248, 144, 179, 25, 58, 82, 113, 45, 14, 102, 69, 239, 204, 164, 135, 188, 159, 247, 212, 126, 93, 53, 22, 74, 105, 1, 34, 136, 171, 195, 224, 78, 109, 5, 38, 140, 175, 199, 228, 184, 155, 243, 208, 122, 89, 49, 18, 41, 10, 98, 65, 235, 200, 160, 131, 223, 252, 148, 183, 29, 62, 86, 117, 51, 16, 120, 91, 241, 210, 186, 153, 197, 230, 142, 173, 7, 36, 76, 111, 84, 119, 31, 60, 150, 181, 221, 254, 162, 129, 233, 202, 96, 67, 43, 8, 166, 133, 237, 206, 100, 71, 47, 12, 80, 115, 27, 56, 146, 177, 217, 250, 193, 226, 138, 169, 3, 32, 72, 107, 55, 20, 124, 95, 245, 214, 190, 157, 66, 97, 9, 42, 128, 163, 203, 232, 180, 151, 255, 220, 118, 85, 61, 30, 37, 6, 110, 77, 231, 196, 172, 143, 211, 240, 152, 187, 17, 50, 90, 121, 215, 244, 156, 191, 21, 54, 94, 125, 33, 2, 106, 73, 227, 192, 168, 139, 176, 147, 251, 216, 114, 81, 57, 26, 70, 101, 13, 46, 132, 167, 207, 236}, {213, 5, 168, 120, 18, 194, 111, 191, 90, 138, 39, 247, 157, 77, 224, 48, 83, 131, 46, 254, 148, 68, 233, 57, 220, 12, 161, 113, 27, 203, 102, 182, 147, 67, 238, 62, 84, 132, 41, 249, 28, 204, 97, 177, 219, 11, 166, 118, 21, 197, 104, 184, 210, 2, 175, 127, 154, 74, 231, 55, 93, 141, 32, 240, 144, 64, 237, 61, 87, 135, 42, 250, 31, 207, 98, 178, 216, 8, 165, 117, 22, 198, 107, 187, 209, 1, 172, 124, 153, 73, 228, 52, 94, 142, 35, 243, 214, 6, 171, 123, 17, 193, 108, 188, 89, 137, 36, 244, 158, 78, 227, 51, 80, 128, 45, 253, 151, 71, 234, 58, 223, 15, 162, 114, 24, 200, 101, 181, 66, 146, 63, 239, 133, 85, 248, 40, 205, 29, 176, 96, 10, 218, 119, 167, 196, 20, 185, 105, 3, 211, 126, 174, 75, 155, 54, 230, 140, 92, 241, 33, 4, 212, 121, 169, 195, 19, 190, 110, 139, 91, 246, 38, 76, 156, 49, 225, 130, 82, 255, 47, 69, 149, 56, 232, 13, 221, 112, 160, 202, 26, 183, 103, 7, 215, 122, 170, 192, 16, 189, 109, 136, 88, 245, 37, 79, 159, 50, 226, 129, 81, 252, 44, 70, 150, 59, 235, 14, 222, 115, 163, 201, 25, 180, 100, 65, 145, 60, 236, 134, 86, 251, 43, 206, 30, 179, 99, 9, 217, 116, 164, 199, 23, 186, 106, 0, 208, 125, 173, 72, 152, 53, 229, 143, 95, 242, 34}, {129, 154, 51, 40, 222, 197, 108, 119, 177, 170, 3, 24, 238, 245, 92, 71, 188, 167, 14, 21, 227, 248, 81, 74, 140, 151, 62, 37, 211, 200, 97, 122, 223, 196, 109, 118, 128, 155, 50, 41, 239, 244, 93, 70, 176, 171, 2, 25, 226, 249, 80, 75, 189, 166, 15, 20, 210, 201, 96, 123, 141, 150, 63, 36, 120, 99, 202, 209, 39, 60, 149, 142, 72, 83, 250, 225, 23, 12, 165, 190, 69, 94, 247, 236, 26, 1, 168, 179, 117, 110, 199, 220, 42, 49, 152, 131, 38, 61, 148, 143, 121, 98, 203, 208, 22, 13, 164, 191, 73, 82, 251, 224, 27, 0, 169, 178, 68, 95, 246, 237, 43, 48, 153, 130, 116, 111, 198, 221, 192, 219, 114, 105, 159, 132, 45, 54, 240, 235, 66, 89, 175, 180, 29, 6, 253, 230, 79, 84, 162, 185, 16, 11, 205, 214, 127, 100, 146, 137, 32, 59, 158, 133, 44, 55, 193, 218, 115, 104, 174, 181, 28, 7, 241, 234, 67, 88, 163, 184, 17, 10, 252, 231, 78, 85, 147, 136, 33, 58, 204, 215, 126, 101, 57, 34, 139, 144, 102, 125, 212, 207, 9, 18, 187, 160, 86, 77, 228, 255, 4, 31, 182, 173, 91, 64, 233, 242, 52, 47, 134, 157, 107, 112, 217, 194, 103, 124, 213, 206, 56, 35, 138, 145, 87, 76, 229, 254, 8, 19, 186, 161, 90, 65, 232, 243, 5, 30, 183, 172, 106, 113, 216, 195, 53, 46, 135, 156}, {71, 103, 100, 68, 122, 90, 89, 121, 162, 130, 129, 161, 159, 191, 188, 156, 22, 54, 53, 21, 43, 11, 8, 40, 243, 211, 208, 240, 206, 238, 237, 205, 167, 135, 132, 164, 154, 186, 185, 153, 66, 98, 97, 65, 127, 95, 92, 124, 246, 214, 213, 245, 203, 235, 232, 200, 19, 51, 48, 16, 46, 14, 13, 45, 233, 201, 202, 234, 212, 244, 247, 215, 12, 44, 47, 15, 49, 17, 18, 50, 184, 152, 155, 187, 133, 165, 166, 134, 93, 125, 126, 94, 96, 64, 67, 99, 9, 41, 42, 10, 52, 20, 23, 55, 236, 204, 207, 239, 209, 241, 242, 210, 88, 120, 123, 91, 101, 69, 70, 102, 189, 157, 158, 190, 128, 160, 163, 131, 253, 221, 222, 254, 192, 224, 227, 195, 24, 56, 59, 27, 37, 5, 6, 38, 172, 140, 143, 175, 145, 177, 178, 146, 73, 105, 106, 74, 116, 84, 87, 119, 29, 61, 62, 30, 32, 0, 3, 35, 248, 216, 219, 251, 197, 229, 230, 198, 76, 108, 111, 79, 113, 81, 82, 114, 169, 137, 138, 170, 148, 180, 183, 151, 83, 115, 112, 80, 110, 78, 77, 109, 182, 150, 149, 181, 139, 171, 168, 136, 2, 34, 33, 1, 63, 31, 28, 60, 231, 199, 196, 228, 218, 250, 249, 217, 179, 147, 144, 176, 142, 174, 173, 141, 86, 118, 117, 85, 107, 75, 72, 104, 226, 194, 193, 225, 223, 255, 252, 220, 7, 39, 36, 4, 58, 26, 25, 57}, {129, 135, 87, 81, 128, 134, 86, 80, 42, 44, 252, 250, 43, 45, 253, 251, 165, 163, 115, 117, 164, 162, 114, 116, 14, 8, 216, 222, 15, 9, 217, 223, 237, 235, 59, 61, 236, 234, 58, 60, 70, 64, 144, 150, 71, 65, 145, 151, 201, 207, 31, 25, 200, 206, 30, 24, 98, 100, 180, 178, 99, 101, 181, 179, 221, 219, 11, 13, 220, 218, 10, 12, 118, 112, 160, 166, 119, 113, 161, 167, 249, 255, 47, 41, 248, 254, 46, 40, 82, 84, 132, 130, 83, 85, 133, 131, 177, 183, 103, 97, 176, 182, 102, 96, 26, 28, 204, 202, 27, 29, 205, 203, 149, 147, 67, 69, 148, 146, 66, 68, 62, 56, 232, 238, 63, 57, 233, 239, 214, 208, 0, 6, 215, 209, 1, 7, 125, 123, 171, 173, 124, 122, 170, 172, 242, 244, 36, 34, 243, 245, 37, 35, 89, 95, 143, 137, 88, 94, 142, 136, 186, 188, 108, 106, 187, 189, 109, 107, 17, 23, 199, 193, 16, 22, 198, 192, 158, 152, 72, 78, 159, 153, 73, 79, 53, 51, 227, 229, 52, 50, 226, 228, 138, 140, 92, 90, 139, 141, 93, 91, 33, 39, 247, 241, 32, 38, 246, 240, 174, 168, 120, 126, 175, 169, 121, 127, 5, 3, 211, 213, 4, 2, 210, 212, 230, 224, 48, 54, 231, 225, 49, 55, 77, 75, 155, 157, 76, 74, 154, 156, 194, 196, 20, 18, 195, 197, 21, 19, 105, 111, 191, 185, 104, 110, 190, 184}, {205, 163, 150, 248, 116, 26, 47, 65, 204, 162, 151, 249, 117, 27, 46, 64, 99, 13, 56, 86, 218, 180, 129, 239, 98, 12, 57, 87, 219, 181, 128, 238, 105, 7, 50, 92, 208, 190, 139, 229, 104, 6, 51, 93, 209, 191, 138, 228, 199, 169, 156, 242, 126, 16, 37, 75, 198, 168, 157, 243, 127, 17, 36, 74, 161, 207, 250, 148, 24, 118, 67, 45, 160, 206, 251, 149, 25, 119, 66, 44, 15, 97, 84, 58, 182, 216, 237, 131, 14, 96, 85, 59, 183, 217, 236, 130, 5, 107, 94, 48, 188, 210, 231, 137, 4, 106, 95, 49, 189, 211, 230, 136, 171, 197, 240, 158, 18, 124, 73, 39, 170, 196, 241, 159, 19, 125, 72, 38, 247, 153, 172, 194, 78, 32, 21, 123, 246, 152, 173, 195, 79, 33, 20, 122, 89, 55, 2, 108, 224, 142, 187, 213, 88, 54, 3, 109, 225, 143, 186, 212, 83, 61, 8, 102, 234, 132, 177, 223, 82, 60, 9, 103, 235, 133, 176, 222, 253, 147, 166, 200, 68, 42, 31, 113, 252, 146, 167, 201, 69, 43, 30, 112, 155, 245, 192, 174, 34, 76, 121, 23, 154, 244, 193, 175, 35, 77, 120, 22, 53, 91, 110, 0, 140, 226, 215, 185, 52, 90, 111, 1, 141, 227, 214, 184, 63, 81, 100, 10, 134, 232, 221, 179, 62, 80, 101, 11, 135, 233, 220, 178, 145, 255, 202, 164, 40, 70, 115, 29, 144, 254, 203, 165, 41, 71, 114, 28}, {106, 93, 188, 139, 2, 53, 212, 227, 66, 117, 148, 163, 42, 29, 252, 203, 24, 47, 206, 249, 112, 71, 166, 145, 48, 7, 230, 209, 88, 111, 142, 185, 202, 253, 28, 43, 162, 149, 116, 67, 226, 213, 52, 3, 138, 189, 92, 107, 184, 143, 110, 89, 208, 231, 6, 49, 144, 167, 70, 113, 248, 207, 46, 25, 146, 165, 68, 115, 250, 205, 44, 27, 186, 141, 108, 91, 210, 229, 4, 51, 224, 215, 54, 1, 136, 191, 94, 105, 200, 255, 30, 41, 160, 151, 118, 65, 50, 5, 228, 211, 90, 109, 140, 187, 26, 45, 204, 251, 114, 69, 164, 147, 64, 119, 150, 161, 40, 31, 254, 201, 104, 95, 190, 137, 0, 55, 214, 225, 169, 158, 127, 72, 193, 246, 23, 32, 129, 182, 87, 96, 233, 222, 63, 8, 219, 236, 13, 58, 179, 132, 101, 82, 243, 196, 37, 18, 155, 172, 77, 122, 9, 62, 223, 232, 97, 86, 183, 128, 33, 22, 247, 192, 73, 126, 159, 168, 123, 76, 173, 154, 19, 36, 197, 242, 83, 100, 133, 178, 59, 12, 237, 218, 81, 102, 135, 176, 57, 14, 239, 216, 121, 78, 175, 152, 17, 38, 199, 240, 35, 20, 245, 194, 75, 124, 157, 170, 11, 60, 221, 234, 99, 84, 181, 130, 241, 198, 39, 16, 153, 174, 79, 120, 217, 238, 15, 56, 177, 134, 103, 80, 131, 180, 85, 98, 235, 220, 61, 10, 171, 156, 125, 74, 195, 244, 21, 34}, {141, 111, 121, 155, 212, 54, 32, 194, 214, 52, 34, 192, 143, 109, 123, 153, 172, 78, 88, 186, 245, 23, 1, 227, 247, 21, 3, 225, 174, 76, 90, 184, 151, 117, 99, 129, 206, 44, 58, 216, 204, 46, 56, 218, 149, 119, 97, 131, 182, 84, 66, 160, 239, 13, 27, 249, 237, 15, 25, 251, 180, 86, 64, 162, 22, 244, 226, 0, 79, 173, 187, 89, 77, 175, 185, 91, 20, 246, 224, 2, 55, 213, 195, 33, 110, 140, 154, 120, 108, 142, 152, 122, 53, 215, 193, 35, 12, 238, 248, 26, 85, 183, 161, 67, 87, 181, 163, 65, 14, 236, 250, 24, 45, 207, 217, 59, 116, 150, 128, 98, 118, 148, 130, 96, 47, 205, 219, 57, 253, 31, 9, 235, 164, 70, 80, 178, 166, 68, 82, 176, 255, 29, 11, 233, 220, 62, 40, 202, 133, 103, 113, 147, 135, 101, 115, 145, 222, 60, 42, 200, 231, 5, 19, 241, 190, 92, 74, 168, 188, 94, 72, 170, 229, 7, 17, 243, 198, 36, 50, 208, 159, 125, 107, 137, 157, 127, 105, 139, 196, 38, 48, 210, 102, 132, 146, 112, 63, 221, 203, 41, 61, 223, 201, 43, 100, 134, 144, 114, 71, 165, 179, 81, 30, 252, 234, 8, 28, 254, 232, 10, 69, 167, 177, 83, 124, 158, 136, 106, 37, 199, 209, 51, 39, 197, 211, 49, 126, 156, 138, 104, 93, 191, 169, 75, 4, 230, 240, 18, 6, 228, 242, 16, 95, 189, 171, 73}, {123, 26, 24, 121, 53, 84, 86, 55, 8, 105, 107, 10, 70, 39, 37, 68, 157, 252, 254, 159, 211, 178, 176, 209, 238, 143, 141, 236, 160, 193, 195, 162, 140, 237, 239, 142, 194, 163, 161, 192, 255, 158, 156, 253, 177, 208, 210, 179, 106, 11, 9, 104, 36, 69, 71, 38, 25, 120, 122, 27, 87, 54, 52, 85, 139, 234, 232, 137, 197, 164, 166, 199, 248, 153, 155, 250, 182, 215, 213, 180, 109, 12, 14, 111, 35, 66, 64, 33, 30, 127, 125, 28, 80, 49, 51, 82, 124, 29, 31, 126, 50, 83, 81, 48, 15, 110, 108, 13, 65, 32, 34, 67, 154, 251, 249, 152, 212, 181, 183, 214, 233, 136, 138, 235, 167, 198, 196, 165, 59, 90, 88, 57, 117, 20, 22, 119, 72, 41, 43, 74, 6, 103, 101, 4, 221, 188, 190, 223, 147, 242, 240, 145, 174, 207, 205, 172, 224, 129, 131, 226, 204, 173, 175, 206, 130, 227, 225, 128, 191, 222, 220, 189, 241, 144, 146, 243, 42, 75, 73, 40, 100, 5, 7, 102, 89, 56, 58, 91, 23, 118, 116, 21, 203, 170, 168, 201, 133, 228, 230, 135, 184, 217, 219, 186, 246, 151, 149, 244, 45, 76, 78, 47, 99, 2, 0, 97, 94, 63, 61, 92, 16, 113, 115, 18, 60, 93, 95, 62, 114, 19, 17, 112, 79, 46, 44, 77, 1, 96, 98, 3, 218, 187, 185, 216, 148, 245, 247, 150, 169, 200, 202, 171, 231, 134, 132, 229}, {4, 210, 131, 85, 242, 36, 117, 163, 125, 171, 250, 44, 139, 93, 12, 218, 111, 185, 232, 62, 153, 79, 30, 200, 22, 192, 145, 71, 224, 54, 103, 177, 88, 142, 223, 9, 174, 120, 41, 255, 33, 247, 166, 112, 215, 1, 80, 134, 51, 229, 180, 98, 197, 19, 66, 148, 74, 156, 205, 27, 188, 106, 59, 237, 175, 121, 40, 254, 89, 143, 222, 8, 214, 0, 81, 135, 32, 246, 167, 113, 196, 18, 67, 149, 50, 228, 181, 99, 189, 107, 58, 236, 75, 157, 204, 26, 243, 37, 116, 162, 5, 211, 130, 84, 138, 92, 13, 219, 124, 170, 251, 45, 152, 78, 31, 201, 110, 184, 233, 63, 225, 55, 102, 176, 23, 193, 144, 70, 160, 118, 39, 241, 86, 128, 209, 7, 217, 15, 94, 136, 47, 249, 168, 126, 203, 29, 76, 154, 61, 235, 186, 108, 178, 100, 53, 227, 68, 146, 195, 21, 252, 42, 123, 173, 10, 220, 141, 91, 133, 83, 2, 212, 115, 165, 244, 34, 151, 65, 16, 198, 97, 183, 230, 48, 238, 56, 105, 191, 24, 206, 159, 73, 11, 221, 140, 90, 253, 43, 122, 172, 114, 164, 245, 35, 132, 82, 3, 213, 96, 182, 231, 49, 150, 64, 17, 199, 25, 207, 158, 72, 239, 57, 104, 190, 87, 129, 208, 6, 161, 119, 38, 240, 46, 248, 169, 127, 216, 14, 95, 137, 60, 234, 187, 109, 202, 28, 77, 155, 69, 147, 194, 20, 179, 101, 52, 226}, {199, 73, 42, 164, 231, 105, 10, 132, 125, 243, 144, 30, 93, 211, 176, 62, 170, 36, 71, 201, 138, 4, 103, 233, 16, 158, 253, 115, 48, 190, 221, 83, 234, 100, 7, 137, 202, 68, 39, 169, 80, 222, 189, 51, 112, 254, 157, 19, 135, 9, 106, 228, 167, 41, 74, 196, 61, 179, 208, 94, 29, 147, 240, 126, 31, 145, 242, 124, 63, 177, 210, 92, 165, 43, 72, 198, 133, 11, 104, 230, 114, 252, 159, 17, 82, 220, 191, 49, 200, 70, 37, 171, 232, 102, 5, 139, 50, 188, 223, 81, 18, 156, 255, 113, 136, 6, 101, 235, 168, 38, 69, 203, 95, 209, 178, 60, 127, 241, 146, 28, 229, 107, 8, 134, 197, 75, 40, 166, 24, 150, 245, 123, 56, 182, 213, 91, 162, 44, 79, 193, 130, 12, 111, 225, 117, 251, 152, 22, 85, 219, 184, 54, 207, 65, 34, 172, 239, 97, 2, 140, 53, 187, 216, 86, 21, 155, 248, 118, 143, 1, 98, 236, 175, 33, 66, 204, 88, 214, 181, 59, 120, 246, 149, 27, 226, 108, 15, 129, 194, 76, 47, 161, 192, 78, 45, 163, 224, 110, 13, 131, 122, 244, 151, 25, 90, 212, 183, 57, 173, 35, 64, 206, 141, 3, 96, 238, 23, 153, 250, 116, 55, 185, 218, 84, 237, 99, 0, 142, 205, 67, 32, 174, 87, 217, 186, 52, 119, 249, 154, 20, 128, 14, 109, 227, 160, 46, 77, 195, 58, 180, 215, 89, 26, 148, 247, 121}, {221, 126, 250, 89, 208, 115, 247, 84, 120, 219, 95, 252, 117, 214, 82, 241, 26, 185, 61, 158, 23, 180, 48, 147, 191, 28, 152, 59, 178, 17, 149, 54, 64, 227, 103, 196, 77, 238, 106, 201, 229, 70, 194, 97, 232, 75, 207, 108, 135, 36, 160, 3, 138, 41, 173, 14, 34, 129, 5, 166, 47, 140, 8, 171, 71, 228, 96, 195, 74, 233, 109, 206, 226, 65, 197, 102, 239, 76, 200, 107, 128, 35, 167, 4, 141, 46, 170, 9, 37, 134, 2, 161, 40, 139, 15, 172, 218, 121, 253, 94, 215, 116, 240, 83, 127, 220, 88, 251, 114, 209, 85, 246, 29, 190, 58, 153, 16, 179, 55, 148, 184, 27, 159, 60, 181, 22, 146, 49, 169, 10, 142, 45, 164, 7, 131, 32, 12, 175, 43, 136, 1, 162, 38, 133, 110, 205, 73, 234, 99, 192, 68, 231, 203, 104, 236, 79, 198, 101, 225, 66, 52, 151, 19, 176, 57, 154, 30, 189, 145, 50, 182, 21, 156, 63, 187, 24, 243, 80, 212, 119, 254, 93, 217, 122, 86, 245, 113, 210, 91, 248, 124, 223, 51, 144, 20, 183, 62, 157, 25, 186, 150, 53, 177, 18, 155, 56, 188, 31, 244, 87, 211, 112, 249, 90, 222, 125, 81, 242, 118, 213, 92, 255, 123, 216, 174, 13, 137, 42, 163, 0, 132, 39, 11, 168, 44, 143, 6, 165, 33, 130, 105, 202, 78, 237, 100, 199, 67, 224, 204, 111, 235, 72, 193, 98, 230, 69}, {154, 7, 81, 204, 49, 172, 250, 103, 124, 225, 183, 42, 215, 74, 28, 129, 12, 145, 199, 90, 167, 58, 108, 241, 234, 119, 33, 188, 65, 220, 138, 23, 14, 147, 197, 88, 165, 56, 110, 243, 232, 117, 35, 190, 67, 222, 136, 21, 152, 5, 83, 206, 51, 174, 248, 101, 126, 227, 181, 40, 213, 72, 30, 131, 233, 116, 34, 191, 66, 223, 137, 20, 15, 146, 196, 89, 164, 57, 111, 242, 127, 226, 180, 41, 212, 73, 31, 130, 153, 4, 82, 207, 50, 175, 249, 100, 125, 224, 182, 43, 214, 75, 29, 128, 155, 6, 80, 205, 48, 173, 251, 102, 235, 118, 32, 189, 64, 221, 139, 22, 13, 144, 198, 91, 166, 59, 109, 240, 218, 71, 17, 140, 113, 236, 186, 39, 60, 161, 247, 106, 151, 10, 92, 193, 76, 209, 135, 26, 231, 122, 44, 177, 170, 55, 97, 252, 1, 156, 202, 87, 78, 211, 133, 24, 229, 120, 46, 179, 168, 53, 99, 254, 3, 158, 200, 85, 216, 69, 19, 142, 115, 238, 184, 37, 62, 163, 245, 104, 149, 8, 94, 195, 169, 52, 98, 255, 2, 159, 201, 84, 79, 210, 132, 25, 228, 121, 47, 178, 63, 162, 244, 105, 148, 9, 95, 194, 217, 68, 18, 143, 114, 239, 185, 36, 61, 160, 246, 107, 150, 11, 93, 192, 219, 70, 16, 141, 112, 237, 187, 38, 171, 54, 96, 253, 0, 157, 203, 86, 77, 208, 134, 27, 230, 123, 45, 176}, {235, 14, 238, 11, 175, 74, 170, 79, 94, 187, 91, 190, 26, 255, 31, 250, 98, 135, 103, 130, 38, 195, 35, 198, 215, 50, 210, 55, 147, 118, 150, 115, 158, 123, 155, 126, 218, 63, 223, 58, 43, 206, 46, 203, 111, 138, 106, 143, 23, 242, 18, 247, 83, 182, 86, 179, 162, 71, 167, 66, 230, 3, 227, 6, 80, 181, 85, 176, 20, 241, 17, 244, 229, 0, 224, 5, 161, 68, 164, 65, 217, 60, 220, 57, 157, 120, 152, 125, 108, 137, 105, 140, 40, 205, 45, 200, 37, 192, 32, 197, 97, 132, 100, 129, 144, 117, 149, 112, 212, 49, 209, 52, 172, 73, 169, 76, 232, 13, 237, 8, 25, 252, 28, 249, 93, 184, 88, 189, 134, 99, 131, 102, 194, 39, 199, 34, 51, 214, 54, 211, 119, 146, 114, 151, 15, 234, 10, 239, 75, 174, 78, 171, 186, 95, 191, 90, 254, 27, 251, 30, 243, 22, 246, 19, 183, 82, 178, 87, 70, 163, 67, 166, 2, 231, 7, 226, 122, 159, 127, 154, 62, 219, 59, 222, 207, 42, 202, 47, 139, 110, 142, 107, 61, 216, 56, 221, 121, 156, 124, 153, 136, 109, 141, 104, 204, 41, 201, 44, 180, 81, 177, 84, 240, 21, 245, 16, 1, 228, 4, 225, 69, 160, 64, 165, 72, 173, 77, 168, 12, 233, 9, 236, 253, 24, 248, 29, 185, 92, 188, 89, 193, 36, 196, 33, 133, 96, 128, 101, 116, 145, 113, 148, 48, 213, 53, 208} };
    m1.mpos = 0x11bbfd9a;
    m1.slut = 125;
    m1.get_param = &get_2;
    m1.mbox_create = 0x11bb7f80;
    ret.mbox_data.push_back(m1);


    MbLut m2;
    m2.lut = { {121, 52, 140, 193, 47, 98, 218, 151, 9, 68, 252, 177, 95, 18, 170, 231, 75, 6, 190, 243, 29, 80, 232, 165, 59, 118, 206, 131, 109, 32, 152, 213, 119, 58, 130, 207, 33, 108, 212, 153, 7, 74, 242, 191, 81, 28, 164, 233, 69, 8, 176, 253, 19, 94, 230, 171, 53, 120, 192, 141, 99, 46, 150, 219, 182, 251, 67, 14, 224, 173, 21, 88, 198, 139, 51, 126, 144, 221, 101, 40, 132, 201, 113, 60, 210, 159, 39, 106, 244, 185, 1, 76, 162, 239, 87, 26, 184, 245, 77, 0, 238, 163, 27, 86, 200, 133, 61, 112, 158, 211, 107, 38, 138, 199, 127, 50, 220, 145, 41, 100, 250, 183, 15, 66, 172, 225, 89, 20, 134, 203, 115, 62, 208, 157, 37, 104, 246, 187, 3, 78, 160, 237, 85, 24, 180, 249, 65, 12, 226, 175, 23, 90, 196, 137, 49, 124, 146, 223, 103, 42, 136, 197, 125, 48, 222, 147, 43, 102, 248, 181, 13, 64, 174, 227, 91, 22, 186, 247, 79, 2, 236, 161, 25, 84, 202, 135, 63, 114, 156, 209, 105, 36, 73, 4, 188, 241, 31, 82, 234, 167, 57, 116, 204, 129, 111, 34, 154, 215, 123, 54, 142, 195, 45, 96, 216, 149, 11, 70, 254, 179, 93, 16, 168, 229, 71, 10, 178, 255, 17, 92, 228, 169, 55, 122, 194, 143, 97, 44, 148, 217, 117, 56, 128, 205, 35, 110, 214, 155, 5, 72, 240, 189, 83, 30, 166, 235}, {250, 113, 17, 154, 16, 155, 251, 112, 255, 116, 20, 159, 21, 158, 254, 117, 8, 131, 227, 104, 226, 105, 9, 130, 13, 134, 230, 109, 231, 108, 12, 135, 129, 10, 106, 225, 107, 224, 128, 11, 132, 15, 111, 228, 110, 229, 133, 14, 115, 248, 152, 19, 153, 18, 114, 249, 118, 253, 157, 22, 156, 23, 119, 252, 217, 82, 50, 185, 51, 184, 216, 83, 220, 87, 55, 188, 54, 189, 221, 86, 43, 160, 192, 75, 193, 74, 42, 161, 46, 165, 197, 78, 196, 79, 47, 164, 162, 41, 73, 194, 72, 195, 163, 40, 167, 44, 76, 199, 77, 198, 166, 45, 80, 219, 187, 48, 186, 49, 81, 218, 85, 222, 190, 53, 191, 52, 84, 223, 61, 182, 214, 93, 215, 92, 60, 183, 56, 179, 211, 88, 210, 89, 57, 178, 207, 68, 36, 175, 37, 174, 206, 69, 202, 65, 33, 170, 32, 171, 203, 64, 70, 205, 173, 38, 172, 39, 71, 204, 67, 200, 168, 35, 169, 34, 66, 201, 180, 63, 95, 212, 94, 213, 181, 62, 177, 58, 90, 209, 91, 208, 176, 59, 30, 149, 245, 126, 244, 127, 31, 148, 27, 144, 240, 123, 241, 122, 26, 145, 236, 103, 7, 140, 6, 141, 237, 102, 233, 98, 2, 137, 3, 136, 232, 99, 101, 238, 142, 5, 143, 4, 100, 239, 96, 235, 139, 0, 138, 1, 97, 234, 151, 28, 124, 247, 125, 246, 150, 29, 146, 25, 121, 242, 120, 243, 147, 24}, {169, 234, 166, 229, 13, 78, 2, 65, 145, 210, 158, 221, 53, 118, 58, 121, 21, 86, 26, 89, 177, 242, 190, 253, 45, 110, 34, 97, 137, 202, 134, 197, 205, 142, 194, 129, 105, 42, 102, 37, 245, 182, 250, 185, 81, 18, 94, 29, 113, 50, 126, 61, 213, 150, 218, 153, 73, 10, 70, 5, 237, 174, 226, 161, 7, 68, 8, 75, 163, 224, 172, 239, 63, 124, 48, 115, 155, 216, 148, 215, 187, 248, 180, 247, 31, 92, 16, 83, 131, 192, 140, 207, 39, 100, 40, 107, 99, 32, 108, 47, 199, 132, 200, 139, 91, 24, 84, 23, 255, 188, 240, 179, 223, 156, 208, 147, 123, 56, 116, 55, 231, 164, 232, 171, 67, 0, 76, 15, 168, 235, 167, 228, 12, 79, 3, 64, 144, 211, 159, 220, 52, 119, 59, 120, 20, 87, 27, 88, 176, 243, 191, 252, 44, 111, 35, 96, 136, 203, 135, 196, 204, 143, 195, 128, 104, 43, 103, 36, 244, 183, 251, 184, 80, 19, 95, 28, 112, 51, 127, 60, 212, 151, 219, 152, 72, 11, 71, 4, 236, 175, 227, 160, 6, 69, 9, 74, 162, 225, 173, 238, 62, 125, 49, 114, 154, 217, 149, 214, 186, 249, 181, 246, 30, 93, 17, 82, 130, 193, 141, 206, 38, 101, 41, 106, 98, 33, 109, 46, 198, 133, 201, 138, 90, 25, 85, 22, 254, 189, 241, 178, 222, 157, 209, 146, 122, 57, 117, 54, 230, 165, 233, 170, 66, 1, 77, 14}, {232, 216, 255, 207, 52, 4, 35, 19, 49, 1, 38, 22, 237, 221, 250, 202, 210, 226, 197, 245, 14, 62, 25, 41, 11, 59, 28, 44, 215, 231, 192, 240, 115, 67, 100, 84, 175, 159, 184, 136, 170, 154, 189, 141, 118, 70, 97, 81, 73, 121, 94, 110, 149, 165, 130, 178, 144, 160, 135, 183, 76, 124, 91, 107, 158, 174, 137, 185, 66, 114, 85, 101, 71, 119, 80, 96, 155, 171, 140, 188, 164, 148, 179, 131, 120, 72, 111, 95, 125, 77, 106, 90, 161, 145, 182, 134, 5, 53, 18, 34, 217, 233, 206, 254, 220, 236, 203, 251, 0, 48, 23, 39, 63, 15, 40, 24, 227, 211, 244, 196, 230, 214, 241, 193, 58, 10, 45, 29, 129, 177, 150, 166, 93, 109, 74, 122, 88, 104, 79, 127, 132, 180, 147, 163, 187, 139, 172, 156, 103, 87, 112, 64, 98, 82, 117, 69, 190, 142, 169, 153, 26, 42, 13, 61, 198, 246, 209, 225, 195, 243, 212, 228, 31, 47, 8, 56, 32, 16, 55, 7, 252, 204, 235, 219, 249, 201, 238, 222, 37, 21, 50, 2, 247, 199, 224, 208, 43, 27, 60, 12, 46, 30, 57, 9, 242, 194, 229, 213, 205, 253, 218, 234, 17, 33, 6, 54, 20, 36, 3, 51, 200, 248, 223, 239, 108, 92, 123, 75, 176, 128, 167, 151, 181, 133, 162, 146, 105, 89, 126, 78, 86, 102, 65, 113, 138, 186, 157, 173, 143, 191, 152, 168, 83, 99, 68, 116}, {190, 17, 192, 111, 53, 154, 75, 228, 36, 139, 90, 245, 175, 0, 209, 126, 196, 107, 186, 21, 79, 224, 49, 158, 94, 241, 32, 143, 213, 122, 171, 4, 179, 28, 205, 98, 56, 151, 70, 233, 41, 134, 87, 248, 162, 13, 220, 115, 201, 102, 183, 24, 66, 237, 60, 147, 83, 252, 45, 130, 216, 119, 166, 9, 110, 193, 16, 191, 229, 74, 155, 52, 244, 91, 138, 37, 127, 208, 1, 174, 20, 187, 106, 197, 159, 48, 225, 78, 142, 33, 240, 95, 5, 170, 123, 212, 99, 204, 29, 178, 232, 71, 150, 57, 249, 86, 135, 40, 114, 221, 12, 163, 25, 182, 103, 200, 146, 61, 236, 67, 131, 44, 253, 82, 8, 167, 118, 217, 18, 189, 108, 195, 153, 54, 231, 72, 136, 39, 246, 89, 3, 172, 125, 210, 104, 199, 22, 185, 227, 76, 157, 50, 242, 93, 140, 35, 121, 214, 7, 168, 31, 176, 97, 206, 148, 59, 234, 69, 133, 42, 251, 84, 14, 161, 112, 223, 101, 202, 27, 180, 238, 65, 144, 63, 255, 80, 129, 46, 116, 219, 10, 165, 194, 109, 188, 19, 73, 230, 55, 152, 88, 247, 38, 137, 211, 124, 173, 2, 184, 23, 198, 105, 51, 156, 77, 226, 34, 141, 92, 243, 169, 6, 215, 120, 207, 96, 177, 30, 68, 235, 58, 149, 85, 250, 43, 132, 222, 113, 160, 15, 181, 26, 203, 100, 62, 145, 64, 239, 47, 128, 81, 254, 164, 11, 218, 117}, {137, 115, 207, 53, 182, 76, 240, 10, 253, 7, 187, 65, 194, 56, 132, 126, 40, 210, 110, 148, 23, 237, 81, 171, 92, 166, 26, 224, 99, 153, 37, 223, 11, 241, 77, 183, 52, 206, 114, 136, 127, 133, 57, 195, 64, 186, 6, 252, 170, 80, 236, 22, 149, 111, 211, 41, 222, 36, 152, 98, 225, 27, 167, 93, 63, 197, 121, 131, 0, 250, 70, 188, 75, 177, 13, 247, 116, 142, 50, 200, 158, 100, 216, 34, 161, 91, 231, 29, 234, 16, 172, 86, 213, 47, 147, 105, 189, 71, 251, 1, 130, 120, 196, 62, 201, 51, 143, 117, 246, 12, 176, 74, 28, 230, 90, 160, 35, 217, 101, 159, 104, 146, 46, 212, 87, 173, 17, 235, 84, 174, 18, 232, 107, 145, 45, 215, 32, 218, 102, 156, 31, 229, 89, 163, 245, 15, 179, 73, 202, 48, 140, 118, 129, 123, 199, 61, 190, 68, 248, 2, 214, 44, 144, 106, 233, 19, 175, 85, 162, 88, 228, 30, 157, 103, 219, 33, 119, 141, 49, 203, 72, 178, 14, 244, 3, 249, 69, 191, 60, 198, 122, 128, 226, 24, 164, 94, 221, 39, 155, 97, 150, 108, 208, 42, 169, 83, 239, 21, 67, 185, 5, 255, 124, 134, 58, 192, 55, 205, 113, 139, 8, 242, 78, 180, 96, 154, 38, 220, 95, 165, 25, 227, 20, 238, 82, 168, 43, 209, 109, 151, 193, 59, 135, 125, 254, 4, 184, 66, 181, 79, 243, 9, 138, 112, 204, 54}, {95, 100, 91, 96, 182, 141, 178, 137, 192, 251, 196, 255, 41, 18, 45, 22, 177, 138, 181, 142, 88, 99, 92, 103, 46, 21, 42, 17, 199, 252, 195, 248, 183, 140, 179, 136, 94, 101, 90, 97, 40, 19, 44, 23, 193, 250, 197, 254, 89, 98, 93, 102, 176, 139, 180, 143, 198, 253, 194, 249, 47, 20, 43, 16, 151, 172, 147, 168, 126, 69, 122, 65, 8, 51, 12, 55, 225, 218, 229, 222, 121, 66, 125, 70, 144, 171, 148, 175, 230, 221, 226, 217, 15, 52, 11, 48, 127, 68, 123, 64, 150, 173, 146, 169, 224, 219, 228, 223, 9, 50, 13, 54, 145, 170, 149, 174, 120, 67, 124, 71, 14, 53, 10, 49, 231, 220, 227, 216, 152, 163, 156, 167, 113, 74, 117, 78, 7, 60, 3, 56, 238, 213, 234, 209, 118, 77, 114, 73, 159, 164, 155, 160, 233, 210, 237, 214, 0, 59, 4, 63, 112, 75, 116, 79, 153, 162, 157, 166, 239, 212, 235, 208, 6, 61, 2, 57, 158, 165, 154, 161, 119, 76, 115, 72, 1, 58, 5, 62, 232, 211, 236, 215, 80, 107, 84, 111, 185, 130, 189, 134, 207, 244, 203, 240, 38, 29, 34, 25, 190, 133, 186, 129, 87, 108, 83, 104, 33, 26, 37, 30, 200, 243, 204, 247, 184, 131, 188, 135, 81, 106, 85, 110, 39, 28, 35, 24, 206, 245, 202, 241, 86, 109, 82, 105, 191, 132, 187, 128, 201, 242, 205, 246, 32, 27, 36, 31}, {29, 176, 10, 167, 218, 119, 205, 96, 45, 128, 58, 151, 234, 71, 253, 80, 115, 222, 100, 201, 180, 25, 163, 14, 67, 238, 84, 249, 132, 41, 147, 62, 252, 81, 235, 70, 59, 150, 44, 129, 204, 97, 219, 118, 11, 166, 28, 177, 146, 63, 133, 40, 85, 248, 66, 239, 162, 15, 181, 24, 101, 200, 114, 223, 148, 57, 131, 46, 83, 254, 68, 233, 164, 9, 179, 30, 99, 206, 116, 217, 250, 87, 237, 64, 61, 144, 42, 135, 202, 103, 221, 112, 13, 160, 26, 183, 117, 216, 98, 207, 178, 31, 165, 8, 69, 232, 82, 255, 130, 47, 149, 56, 27, 182, 12, 161, 220, 113, 203, 102, 43, 134, 60, 145, 236, 65, 251, 86, 231, 74, 240, 93, 32, 141, 55, 154, 215, 122, 192, 109, 16, 189, 7, 170, 137, 36, 158, 51, 78, 227, 89, 244, 185, 20, 174, 3, 126, 211, 105, 196, 6, 171, 17, 188, 193, 108, 214, 123, 54, 155, 33, 140, 241, 92, 230, 75, 104, 197, 127, 210, 175, 2, 184, 21, 88, 245, 79, 226, 159, 50, 136, 37, 110, 195, 121, 212, 169, 4, 190, 19, 94, 243, 73, 228, 153, 52, 142, 35, 0, 173, 23, 186, 199, 106, 208, 125, 48, 157, 39, 138, 247, 90, 224, 77, 143, 34, 152, 53, 72, 229, 95, 242, 191, 18, 168, 5, 120, 213, 111, 194, 225, 76, 246, 91, 38, 139, 49, 156, 209, 124, 198, 107, 22, 187, 1, 172}, {205, 4, 129, 72, 98, 171, 46, 231, 106, 163, 38, 239, 197, 12, 137, 64, 8, 193, 68, 141, 167, 110, 235, 34, 175, 102, 227, 42, 0, 201, 76, 133, 6, 207, 74, 131, 169, 96, 229, 44, 161, 104, 237, 36, 14, 199, 66, 139, 195, 10, 143, 70, 108, 165, 32, 233, 100, 173, 40, 225, 203, 2, 135, 78, 7, 206, 75, 130, 168, 97, 228, 45, 160, 105, 236, 37, 15, 198, 67, 138, 194, 11, 142, 71, 109, 164, 33, 232, 101, 172, 41, 224, 202, 3, 134, 79, 204, 5, 128, 73, 99, 170, 47, 230, 107, 162, 39, 238, 196, 13, 136, 65, 9, 192, 69, 140, 166, 111, 234, 35, 174, 103, 226, 43, 1, 200, 77, 132, 209, 24, 157, 84, 126, 183, 50, 251, 118, 191, 58, 243, 217, 16, 149, 92, 20, 221, 88, 145, 187, 114, 247, 62, 179, 122, 255, 54, 28, 213, 80, 153, 26, 211, 86, 159, 181, 124, 249, 48, 189, 116, 241, 56, 18, 219, 94, 151, 223, 22, 147, 90, 112, 185, 60, 245, 120, 177, 52, 253, 215, 30, 155, 82, 27, 210, 87, 158, 180, 125, 248, 49, 188, 117, 240, 57, 19, 218, 95, 150, 222, 23, 146, 91, 113, 184, 61, 244, 121, 176, 53, 252, 214, 31, 154, 83, 208, 25, 156, 85, 127, 182, 51, 250, 119, 190, 59, 242, 216, 17, 148, 93, 21, 220, 89, 144, 186, 115, 246, 63, 178, 123, 254, 55, 29, 212, 81, 152}, {60, 1, 229, 216, 252, 193, 37, 24, 230, 219, 63, 2, 38, 27, 255, 194, 241, 204, 40, 21, 49, 12, 232, 213, 43, 22, 242, 207, 235, 214, 50, 15, 55, 10, 238, 211, 247, 202, 46, 19, 237, 208, 52, 9, 45, 16, 244, 201, 250, 199, 35, 30, 58, 7, 227, 222, 32, 29, 249, 196, 224, 221, 57, 4, 170, 151, 115, 78, 106, 87, 179, 142, 112, 77, 169, 148, 176, 141, 105, 84, 103, 90, 190, 131, 167, 154, 126, 67, 189, 128, 100, 89, 125, 64, 164, 153, 161, 156, 120, 69, 97, 92, 184, 133, 123, 70, 162, 159, 187, 134, 98, 95, 108, 81, 181, 136, 172, 145, 117, 72, 182, 139, 111, 82, 118, 75, 175, 146, 165, 152, 124, 65, 101, 88, 188, 129, 127, 66, 166, 155, 191, 130, 102, 91, 104, 85, 177, 140, 168, 149, 113, 76, 178, 143, 107, 86, 114, 79, 171, 150, 174, 147, 119, 74, 110, 83, 183, 138, 116, 73, 173, 144, 180, 137, 109, 80, 99, 94, 186, 135, 163, 158, 122, 71, 185, 132, 96, 93, 121, 68, 160, 157, 51, 14, 234, 215, 243, 206, 42, 23, 233, 212, 48, 13, 41, 20, 240, 205, 254, 195, 39, 26, 62, 3, 231, 218, 36, 25, 253, 192, 228, 217, 61, 0, 56, 5, 225, 220, 248, 197, 33, 28, 226, 223, 59, 6, 34, 31, 251, 198, 245, 200, 44, 17, 53, 8, 236, 209, 47, 18, 246, 203, 239, 210, 54, 11}, {133, 48, 96, 213, 28, 169, 249, 76, 231, 82, 2, 183, 126, 203, 155, 46, 149, 32, 112, 197, 12, 185, 233, 92, 247, 66, 18, 167, 110, 219, 139, 62, 35, 150, 198, 115, 186, 15, 95, 234, 65, 244, 164, 17, 216, 109, 61, 136, 51, 134, 214, 99, 170, 31, 79, 250, 81, 228, 180, 1, 200, 125, 45, 152, 154, 47, 127, 202, 3, 182, 230, 83, 248, 77, 29, 168, 97, 212, 132, 49, 138, 63, 111, 218, 19, 166, 246, 67, 232, 93, 13, 184, 113, 196, 148, 33, 60, 137, 217, 108, 165, 16, 64, 245, 94, 235, 187, 14, 199, 114, 34, 151, 44, 153, 201, 124, 181, 0, 80, 229, 78, 251, 171, 30, 215, 98, 50, 135, 70, 243, 163, 22, 223, 106, 58, 143, 36, 145, 193, 116, 189, 8, 88, 237, 86, 227, 179, 6, 207, 122, 42, 159, 52, 129, 209, 100, 173, 24, 72, 253, 224, 85, 5, 176, 121, 204, 156, 41, 130, 55, 103, 210, 27, 174, 254, 75, 240, 69, 21, 160, 105, 220, 140, 57, 146, 39, 119, 194, 11, 190, 238, 91, 89, 236, 188, 9, 192, 117, 37, 144, 59, 142, 222, 107, 162, 23, 71, 242, 73, 252, 172, 25, 208, 101, 53, 128, 43, 158, 206, 123, 178, 7, 87, 226, 255, 74, 26, 175, 102, 211, 131, 54, 157, 40, 120, 205, 4, 177, 225, 84, 239, 90, 10, 191, 118, 195, 147, 38, 141, 56, 104, 221, 20, 161, 241, 68}, {219, 153, 59, 121, 248, 186, 24, 90, 34, 96, 194, 128, 1, 67, 225, 163, 249, 187, 25, 91, 218, 152, 58, 120, 0, 66, 224, 162, 35, 97, 195, 129, 101, 39, 133, 199, 70, 4, 166, 228, 156, 222, 124, 62, 191, 253, 95, 29, 71, 5, 167, 229, 100, 38, 132, 198, 190, 252, 94, 28, 157, 223, 125, 63, 72, 10, 168, 234, 107, 41, 139, 201, 177, 243, 81, 19, 146, 208, 114, 48, 106, 40, 138, 200, 73, 11, 169, 235, 147, 209, 115, 49, 176, 242, 80, 18, 246, 180, 22, 84, 213, 151, 53, 119, 15, 77, 239, 173, 44, 110, 204, 142, 212, 150, 52, 118, 247, 181, 23, 85, 45, 111, 205, 143, 14, 76, 238, 172, 203, 137, 43, 105, 232, 170, 8, 74, 50, 112, 210, 144, 17, 83, 241, 179, 233, 171, 9, 75, 202, 136, 42, 104, 16, 82, 240, 178, 51, 113, 211, 145, 117, 55, 149, 215, 86, 20, 182, 244, 140, 206, 108, 46, 175, 237, 79, 13, 87, 21, 183, 245, 116, 54, 148, 214, 174, 236, 78, 12, 141, 207, 109, 47, 88, 26, 184, 250, 123, 57, 155, 217, 161, 227, 65, 3, 130, 192, 98, 32, 122, 56, 154, 216, 89, 27, 185, 251, 131, 193, 99, 33, 160, 226, 64, 2, 230, 164, 6, 68, 197, 135, 37, 103, 31, 93, 255, 189, 60, 126, 220, 158, 196, 134, 36, 102, 231, 165, 7, 69, 61, 127, 221, 159, 30, 92, 254, 188}, {68, 201, 164, 41, 9, 132, 233, 100, 249, 116, 25, 148, 180, 57, 84, 217, 28, 145, 252, 113, 81, 220, 177, 60, 161, 44, 65, 204, 236, 97, 12, 129, 83, 222, 179, 62, 30, 147, 254, 115, 238, 99, 14, 131, 163, 46, 67, 206, 11, 134, 235, 102, 70, 203, 166, 43, 182, 59, 86, 219, 251, 118, 27, 150, 146, 31, 114, 255, 223, 82, 63, 178, 47, 162, 207, 66, 98, 239, 130, 15, 202, 71, 42, 167, 135, 10, 103, 234, 119, 250, 151, 26, 58, 183, 218, 87, 133, 8, 101, 232, 200, 69, 40, 165, 56, 181, 216, 85, 117, 248, 149, 24, 221, 80, 61, 176, 144, 29, 112, 253, 96, 237, 128, 13, 45, 160, 205, 64, 244, 121, 20, 153, 185, 52, 89, 212, 73, 196, 169, 36, 4, 137, 228, 105, 172, 33, 76, 193, 225, 108, 1, 140, 17, 156, 241, 124, 92, 209, 188, 49, 227, 110, 3, 142, 174, 35, 78, 195, 94, 211, 190, 51, 19, 158, 243, 126, 187, 54, 91, 214, 246, 123, 22, 155, 6, 139, 230, 107, 75, 198, 171, 38, 34, 175, 194, 79, 111, 226, 143, 2, 159, 18, 127, 242, 210, 95, 50, 191, 122, 247, 154, 23, 55, 186, 215, 90, 199, 74, 39, 170, 138, 7, 106, 231, 53, 184, 213, 88, 120, 245, 152, 21, 136, 5, 104, 229, 197, 72, 37, 168, 109, 224, 141, 0, 32, 173, 192, 77, 208, 93, 48, 189, 157, 16, 125, 240}, {127, 156, 159, 124, 36, 199, 196, 39, 63, 220, 223, 60, 100, 135, 132, 103, 200, 43, 40, 203, 147, 112, 115, 144, 136, 107, 104, 139, 211, 48, 51, 208, 233, 10, 9, 234, 178, 81, 82, 177, 169, 74, 73, 170, 242, 17, 18, 241, 94, 189, 190, 93, 5, 230, 229, 6, 30, 253, 254, 29, 69, 166, 165, 70, 102, 133, 134, 101, 61, 222, 221, 62, 38, 197, 198, 37, 125, 158, 157, 126, 209, 50, 49, 210, 138, 105, 106, 137, 145, 114, 113, 146, 202, 41, 42, 201, 240, 19, 16, 243, 171, 72, 75, 168, 176, 83, 80, 179, 235, 8, 11, 232, 71, 164, 167, 68, 28, 255, 252, 31, 7, 228, 231, 4, 92, 191, 188, 95, 152, 123, 120, 155, 195, 32, 35, 192, 216, 59, 56, 219, 131, 96, 99, 128, 47, 204, 207, 44, 116, 151, 148, 119, 111, 140, 143, 108, 52, 215, 212, 55, 14, 237, 238, 13, 85, 182, 181, 86, 78, 173, 174, 77, 21, 246, 245, 22, 185, 90, 89, 186, 226, 1, 2, 225, 249, 26, 25, 250, 162, 65, 66, 161, 129, 98, 97, 130, 218, 57, 58, 217, 193, 34, 33, 194, 154, 121, 122, 153, 54, 213, 214, 53, 109, 142, 141, 110, 118, 149, 150, 117, 45, 206, 205, 46, 23, 244, 247, 20, 76, 175, 172, 79, 87, 180, 183, 84, 12, 239, 236, 15, 160, 67, 64, 163, 251, 24, 27, 248, 224, 3, 0, 227, 187, 88, 91, 184}, {170, 76, 86, 176, 69, 163, 185, 95, 67, 165, 191, 89, 172, 74, 80, 182, 97, 135, 157, 123, 142, 104, 114, 148, 136, 110, 116, 146, 103, 129, 155, 125, 7, 225, 251, 29, 232, 14, 20, 242, 238, 8, 18, 244, 1, 231, 253, 27, 204, 42, 48, 214, 35, 197, 223, 57, 37, 195, 217, 63, 202, 44, 54, 208, 166, 64, 90, 188, 73, 175, 181, 83, 79, 169, 179, 85, 160, 70, 92, 186, 109, 139, 145, 119, 130, 100, 126, 152, 132, 98, 120, 158, 107, 141, 151, 113, 11, 237, 247, 17, 228, 2, 24, 254, 226, 4, 30, 248, 13, 235, 241, 23, 192, 38, 60, 218, 47, 201, 211, 53, 41, 207, 213, 51, 198, 32, 58, 220, 16, 246, 236, 10, 255, 25, 3, 229, 249, 31, 5, 227, 22, 240, 234, 12, 219, 61, 39, 193, 52, 210, 200, 46, 50, 212, 206, 40, 221, 59, 33, 199, 189, 91, 65, 167, 82, 180, 174, 72, 84, 178, 168, 78, 187, 93, 71, 161, 118, 144, 138, 108, 153, 127, 101, 131, 159, 121, 99, 133, 112, 150, 140, 106, 28, 250, 224, 6, 243, 21, 15, 233, 245, 19, 9, 239, 26, 252, 230, 0, 215, 49, 43, 205, 56, 222, 196, 34, 62, 216, 194, 36, 209, 55, 45, 203, 177, 87, 77, 171, 94, 184, 162, 68, 88, 190, 164, 66, 183, 81, 75, 173, 122, 156, 134, 96, 149, 115, 105, 143, 147, 117, 111, 137, 124, 154, 128, 102}, {96, 171, 166, 109, 203, 0, 13, 198, 242, 57, 52, 255, 89, 146, 159, 84, 20, 223, 210, 25, 191, 116, 121, 178, 134, 77, 64, 139, 45, 230, 235, 32, 142, 69, 72, 131, 37, 238, 227, 40, 28, 215, 218, 17, 183, 124, 113, 186, 250, 49, 60, 247, 81, 154, 151, 92, 104, 163, 174, 101, 195, 8, 5, 206, 143, 68, 73, 130, 36, 239, 226, 41, 29, 214, 219, 16, 182, 125, 112, 187, 251, 48, 61, 246, 80, 155, 150, 93, 105, 162, 175, 100, 194, 9, 4, 207, 97, 170, 167, 108, 202, 1, 12, 199, 243, 56, 53, 254, 88, 147, 158, 85, 21, 222, 211, 24, 190, 117, 120, 179, 135, 76, 65, 138, 44, 231, 234, 33, 74, 129, 140, 71, 225, 42, 39, 236, 216, 19, 30, 213, 115, 184, 181, 126, 62, 245, 248, 51, 149, 94, 83, 152, 172, 103, 106, 161, 7, 204, 193, 10, 164, 111, 98, 169, 15, 196, 201, 2, 54, 253, 240, 59, 157, 86, 91, 144, 208, 27, 22, 221, 123, 176, 189, 118, 66, 137, 132, 79, 233, 34, 47, 228, 165, 110, 99, 168, 14, 197, 200, 3, 55, 252, 241, 58, 156, 87, 90, 145, 209, 26, 23, 220, 122, 177, 188, 119, 67, 136, 133, 78, 232, 35, 46, 229, 75, 128, 141, 70, 224, 43, 38, 237, 217, 18, 31, 212, 114, 185, 180, 127, 63, 244, 249, 50, 148, 95, 82, 153, 173, 102, 107, 160, 6, 205, 192, 11} };
    m2.readout = 0x101ad950;
    m2.mpos = 0x1019b3e0;
    m2.slut = 91;
    m2.get_param = &get_1;
    m2.mbox_create = 0x101ad230;
    
    ret.mbox_data.push_back(m2);
    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.23620";
    ret.vernum = 7;

    ret.entry = 0;


    return ret;
}
#if defined(_WIN64)
//e8d7579f15e15451be300021306ef2af
ExecOffsets KindleReader1_0_25218()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x18114aba0;
    ret.make_storage = 0x180ea31d0;


    ret.get_plugin_man = 0x18115c320;
    ret.load_all = 0x18115c400;

    //180ea3201 
    ret.spatches.push_back(ppatch(0x180ea3201, { 0xe9, 0xd3, 0x00, 0x00, 0x00 }));
    ret.spatches.push_back(ppatch(0x180ea2b6d, { 0xe9, 0xd3, 0x00, 0x00, 0x00 }));
    ret.get_storage_value = 0x18006e100;
    ret.deobfuscate_storage = 0x18006d930;
    ret.drm_provider = 0x181171550;

    ret.get_factory = 0x181171130;
    ret.open_book = 0x1811711e0;



    // ret.decr_offset = 0x11bb8170;

    ret.mbox_size_bare = 0x1d198;
    //ret.mbox_iv_offset = 0x1d180;

    ret.decr_offset = 0x181e51800;
    ret.mbox_size = 0x1d1c0;//0x1d1ac
    ret.mbox_iv_offset = 0x1d180;

    ret.decr_offset_bare = 0x101d27e0;
    ret.t_bare = 0x182d1a5a0;
    ret.o_bare = 30;


    ret.allemaric_shift = 12;

    //std::vector<MbLut> mbox_data;
    MbLut m1;
    m1.readout = 0x181e53dd0;
    m1.lut = { {179, 112, 244, 55, 46, 237, 105, 170, 183, 116, 240, 51, 42, 233, 109, 174, 70, 133, 1, 194, 219, 24, 156, 95, 66, 129, 5, 198, 223, 28, 152, 91, 171, 104, 236, 47, 54, 245, 113, 178, 175, 108, 232, 43, 50, 241, 117, 182, 94, 157, 25, 218, 195, 0, 132, 71, 90, 153, 29, 222, 199, 4, 128, 67, 217, 26, 158, 93, 68, 135, 3, 192, 221, 30, 154, 89, 64, 131, 7, 196, 44, 239, 107, 168, 177, 114, 246, 53, 40, 235, 111, 172, 181, 118, 242, 49, 193, 2, 134, 69, 92, 159, 27, 216, 197, 6, 130, 65, 88, 155, 31, 220, 52, 247, 115, 176, 169, 106, 238, 45, 48, 243, 119, 180, 173, 110, 234, 41, 207, 12, 136, 75, 82, 145, 21, 214, 203, 8, 140, 79, 86, 149, 17, 210, 58, 249, 125, 190, 167, 100, 224, 35, 62, 253, 121, 186, 163, 96, 228, 39, 215, 20, 144, 83, 74, 137, 13, 206, 211, 16, 148, 87, 78, 141, 9, 202, 34, 225, 101, 166, 191, 124, 248, 59, 38, 229, 97, 162, 187, 120, 252, 63, 165, 102, 226, 33, 56, 251, 127, 188, 161, 98, 230, 37, 60, 255, 123, 184, 80, 147, 23, 212, 205, 14, 138, 73, 84, 151, 19, 208, 201, 10, 142, 77, 189, 126, 250, 57, 32, 227, 103, 164, 185, 122, 254, 61, 36, 231, 99, 160, 72, 139, 15, 204, 213, 22, 146, 81, 76, 143, 11, 200, 209, 18, 150, 85}, {159, 68, 24, 195, 50, 233, 181, 110, 221, 6, 90, 129, 112, 171, 247, 44, 5, 222, 130, 89, 168, 115, 47, 244, 71, 156, 192, 27, 234, 49, 109, 182, 36, 255, 163, 120, 137, 82, 14, 213, 102, 189, 225, 58, 203, 16, 76, 151, 190, 101, 57, 226, 19, 200, 148, 79, 252, 39, 123, 160, 81, 138, 214, 13, 119, 172, 240, 43, 218, 1, 93, 134, 53, 238, 178, 105, 152, 67, 31, 196, 237, 54, 106, 177, 64, 155, 199, 28, 175, 116, 40, 243, 2, 217, 133, 94, 204, 23, 75, 144, 97, 186, 230, 61, 142, 85, 9, 210, 35, 248, 164, 127, 86, 141, 209, 10, 251, 32, 124, 167, 20, 207, 147, 72, 185, 98, 62, 229, 205, 22, 74, 145, 96, 187, 231, 60, 143, 84, 8, 211, 34, 249, 165, 126, 87, 140, 208, 11, 250, 33, 125, 166, 21, 206, 146, 73, 184, 99, 63, 228, 118, 173, 241, 42, 219, 0, 92, 135, 52, 239, 179, 104, 153, 66, 30, 197, 236, 55, 107, 176, 65, 154, 198, 29, 174, 117, 41, 242, 3, 216, 132, 95, 37, 254, 162, 121, 136, 83, 15, 212, 103, 188, 224, 59, 202, 17, 77, 150, 191, 100, 56, 227, 18, 201, 149, 78, 253, 38, 122, 161, 80, 139, 215, 12, 158, 69, 25, 194, 51, 232, 180, 111, 220, 7, 91, 128, 113, 170, 246, 45, 4, 223, 131, 88, 169, 114, 46, 245, 70, 157, 193, 26, 235, 48, 108, 183}, {170, 137, 225, 194, 104, 75, 35, 0, 92, 127, 23, 52, 158, 189, 213, 246, 205, 238, 134, 165, 15, 44, 68, 103, 59, 24, 112, 83, 249, 218, 178, 145, 63, 28, 116, 87, 253, 222, 182, 149, 201, 234, 130, 161, 11, 40, 64, 99, 88, 123, 19, 48, 154, 185, 209, 242, 174, 141, 229, 198, 108, 79, 39, 4, 219, 248, 144, 179, 25, 58, 82, 113, 45, 14, 102, 69, 239, 204, 164, 135, 188, 159, 247, 212, 126, 93, 53, 22, 74, 105, 1, 34, 136, 171, 195, 224, 78, 109, 5, 38, 140, 175, 199, 228, 184, 155, 243, 208, 122, 89, 49, 18, 41, 10, 98, 65, 235, 200, 160, 131, 223, 252, 148, 183, 29, 62, 86, 117, 51, 16, 120, 91, 241, 210, 186, 153, 197, 230, 142, 173, 7, 36, 76, 111, 84, 119, 31, 60, 150, 181, 221, 254, 162, 129, 233, 202, 96, 67, 43, 8, 166, 133, 237, 206, 100, 71, 47, 12, 80, 115, 27, 56, 146, 177, 217, 250, 193, 226, 138, 169, 3, 32, 72, 107, 55, 20, 124, 95, 245, 214, 190, 157, 66, 97, 9, 42, 128, 163, 203, 232, 180, 151, 255, 220, 118, 85, 61, 30, 37, 6, 110, 77, 231, 196, 172, 143, 211, 240, 152, 187, 17, 50, 90, 121, 215, 244, 156, 191, 21, 54, 94, 125, 33, 2, 106, 73, 227, 192, 168, 139, 176, 147, 251, 216, 114, 81, 57, 26, 70, 101, 13, 46, 132, 167, 207, 236}, {213, 5, 168, 120, 18, 194, 111, 191, 90, 138, 39, 247, 157, 77, 224, 48, 83, 131, 46, 254, 148, 68, 233, 57, 220, 12, 161, 113, 27, 203, 102, 182, 147, 67, 238, 62, 84, 132, 41, 249, 28, 204, 97, 177, 219, 11, 166, 118, 21, 197, 104, 184, 210, 2, 175, 127, 154, 74, 231, 55, 93, 141, 32, 240, 144, 64, 237, 61, 87, 135, 42, 250, 31, 207, 98, 178, 216, 8, 165, 117, 22, 198, 107, 187, 209, 1, 172, 124, 153, 73, 228, 52, 94, 142, 35, 243, 214, 6, 171, 123, 17, 193, 108, 188, 89, 137, 36, 244, 158, 78, 227, 51, 80, 128, 45, 253, 151, 71, 234, 58, 223, 15, 162, 114, 24, 200, 101, 181, 66, 146, 63, 239, 133, 85, 248, 40, 205, 29, 176, 96, 10, 218, 119, 167, 196, 20, 185, 105, 3, 211, 126, 174, 75, 155, 54, 230, 140, 92, 241, 33, 4, 212, 121, 169, 195, 19, 190, 110, 139, 91, 246, 38, 76, 156, 49, 225, 130, 82, 255, 47, 69, 149, 56, 232, 13, 221, 112, 160, 202, 26, 183, 103, 7, 215, 122, 170, 192, 16, 189, 109, 136, 88, 245, 37, 79, 159, 50, 226, 129, 81, 252, 44, 70, 150, 59, 235, 14, 222, 115, 163, 201, 25, 180, 100, 65, 145, 60, 236, 134, 86, 251, 43, 206, 30, 179, 99, 9, 217, 116, 164, 199, 23, 186, 106, 0, 208, 125, 173, 72, 152, 53, 229, 143, 95, 242, 34}, {129, 154, 51, 40, 222, 197, 108, 119, 177, 170, 3, 24, 238, 245, 92, 71, 188, 167, 14, 21, 227, 248, 81, 74, 140, 151, 62, 37, 211, 200, 97, 122, 223, 196, 109, 118, 128, 155, 50, 41, 239, 244, 93, 70, 176, 171, 2, 25, 226, 249, 80, 75, 189, 166, 15, 20, 210, 201, 96, 123, 141, 150, 63, 36, 120, 99, 202, 209, 39, 60, 149, 142, 72, 83, 250, 225, 23, 12, 165, 190, 69, 94, 247, 236, 26, 1, 168, 179, 117, 110, 199, 220, 42, 49, 152, 131, 38, 61, 148, 143, 121, 98, 203, 208, 22, 13, 164, 191, 73, 82, 251, 224, 27, 0, 169, 178, 68, 95, 246, 237, 43, 48, 153, 130, 116, 111, 198, 221, 192, 219, 114, 105, 159, 132, 45, 54, 240, 235, 66, 89, 175, 180, 29, 6, 253, 230, 79, 84, 162, 185, 16, 11, 205, 214, 127, 100, 146, 137, 32, 59, 158, 133, 44, 55, 193, 218, 115, 104, 174, 181, 28, 7, 241, 234, 67, 88, 163, 184, 17, 10, 252, 231, 78, 85, 147, 136, 33, 58, 204, 215, 126, 101, 57, 34, 139, 144, 102, 125, 212, 207, 9, 18, 187, 160, 86, 77, 228, 255, 4, 31, 182, 173, 91, 64, 233, 242, 52, 47, 134, 157, 107, 112, 217, 194, 103, 124, 213, 206, 56, 35, 138, 145, 87, 76, 229, 254, 8, 19, 186, 161, 90, 65, 232, 243, 5, 30, 183, 172, 106, 113, 216, 195, 53, 46, 135, 156}, {71, 103, 100, 68, 122, 90, 89, 121, 162, 130, 129, 161, 159, 191, 188, 156, 22, 54, 53, 21, 43, 11, 8, 40, 243, 211, 208, 240, 206, 238, 237, 205, 167, 135, 132, 164, 154, 186, 185, 153, 66, 98, 97, 65, 127, 95, 92, 124, 246, 214, 213, 245, 203, 235, 232, 200, 19, 51, 48, 16, 46, 14, 13, 45, 233, 201, 202, 234, 212, 244, 247, 215, 12, 44, 47, 15, 49, 17, 18, 50, 184, 152, 155, 187, 133, 165, 166, 134, 93, 125, 126, 94, 96, 64, 67, 99, 9, 41, 42, 10, 52, 20, 23, 55, 236, 204, 207, 239, 209, 241, 242, 210, 88, 120, 123, 91, 101, 69, 70, 102, 189, 157, 158, 190, 128, 160, 163, 131, 253, 221, 222, 254, 192, 224, 227, 195, 24, 56, 59, 27, 37, 5, 6, 38, 172, 140, 143, 175, 145, 177, 178, 146, 73, 105, 106, 74, 116, 84, 87, 119, 29, 61, 62, 30, 32, 0, 3, 35, 248, 216, 219, 251, 197, 229, 230, 198, 76, 108, 111, 79, 113, 81, 82, 114, 169, 137, 138, 170, 148, 180, 183, 151, 83, 115, 112, 80, 110, 78, 77, 109, 182, 150, 149, 181, 139, 171, 168, 136, 2, 34, 33, 1, 63, 31, 28, 60, 231, 199, 196, 228, 218, 250, 249, 217, 179, 147, 144, 176, 142, 174, 173, 141, 86, 118, 117, 85, 107, 75, 72, 104, 226, 194, 193, 225, 223, 255, 252, 220, 7, 39, 36, 4, 58, 26, 25, 57}, {129, 135, 87, 81, 128, 134, 86, 80, 42, 44, 252, 250, 43, 45, 253, 251, 165, 163, 115, 117, 164, 162, 114, 116, 14, 8, 216, 222, 15, 9, 217, 223, 237, 235, 59, 61, 236, 234, 58, 60, 70, 64, 144, 150, 71, 65, 145, 151, 201, 207, 31, 25, 200, 206, 30, 24, 98, 100, 180, 178, 99, 101, 181, 179, 221, 219, 11, 13, 220, 218, 10, 12, 118, 112, 160, 166, 119, 113, 161, 167, 249, 255, 47, 41, 248, 254, 46, 40, 82, 84, 132, 130, 83, 85, 133, 131, 177, 183, 103, 97, 176, 182, 102, 96, 26, 28, 204, 202, 27, 29, 205, 203, 149, 147, 67, 69, 148, 146, 66, 68, 62, 56, 232, 238, 63, 57, 233, 239, 214, 208, 0, 6, 215, 209, 1, 7, 125, 123, 171, 173, 124, 122, 170, 172, 242, 244, 36, 34, 243, 245, 37, 35, 89, 95, 143, 137, 88, 94, 142, 136, 186, 188, 108, 106, 187, 189, 109, 107, 17, 23, 199, 193, 16, 22, 198, 192, 158, 152, 72, 78, 159, 153, 73, 79, 53, 51, 227, 229, 52, 50, 226, 228, 138, 140, 92, 90, 139, 141, 93, 91, 33, 39, 247, 241, 32, 38, 246, 240, 174, 168, 120, 126, 175, 169, 121, 127, 5, 3, 211, 213, 4, 2, 210, 212, 230, 224, 48, 54, 231, 225, 49, 55, 77, 75, 155, 157, 76, 74, 154, 156, 194, 196, 20, 18, 195, 197, 21, 19, 105, 111, 191, 185, 104, 110, 190, 184}, {205, 163, 150, 248, 116, 26, 47, 65, 204, 162, 151, 249, 117, 27, 46, 64, 99, 13, 56, 86, 218, 180, 129, 239, 98, 12, 57, 87, 219, 181, 128, 238, 105, 7, 50, 92, 208, 190, 139, 229, 104, 6, 51, 93, 209, 191, 138, 228, 199, 169, 156, 242, 126, 16, 37, 75, 198, 168, 157, 243, 127, 17, 36, 74, 161, 207, 250, 148, 24, 118, 67, 45, 160, 206, 251, 149, 25, 119, 66, 44, 15, 97, 84, 58, 182, 216, 237, 131, 14, 96, 85, 59, 183, 217, 236, 130, 5, 107, 94, 48, 188, 210, 231, 137, 4, 106, 95, 49, 189, 211, 230, 136, 171, 197, 240, 158, 18, 124, 73, 39, 170, 196, 241, 159, 19, 125, 72, 38, 247, 153, 172, 194, 78, 32, 21, 123, 246, 152, 173, 195, 79, 33, 20, 122, 89, 55, 2, 108, 224, 142, 187, 213, 88, 54, 3, 109, 225, 143, 186, 212, 83, 61, 8, 102, 234, 132, 177, 223, 82, 60, 9, 103, 235, 133, 176, 222, 253, 147, 166, 200, 68, 42, 31, 113, 252, 146, 167, 201, 69, 43, 30, 112, 155, 245, 192, 174, 34, 76, 121, 23, 154, 244, 193, 175, 35, 77, 120, 22, 53, 91, 110, 0, 140, 226, 215, 185, 52, 90, 111, 1, 141, 227, 214, 184, 63, 81, 100, 10, 134, 232, 221, 179, 62, 80, 101, 11, 135, 233, 220, 178, 145, 255, 202, 164, 40, 70, 115, 29, 144, 254, 203, 165, 41, 71, 114, 28}, {106, 93, 188, 139, 2, 53, 212, 227, 66, 117, 148, 163, 42, 29, 252, 203, 24, 47, 206, 249, 112, 71, 166, 145, 48, 7, 230, 209, 88, 111, 142, 185, 202, 253, 28, 43, 162, 149, 116, 67, 226, 213, 52, 3, 138, 189, 92, 107, 184, 143, 110, 89, 208, 231, 6, 49, 144, 167, 70, 113, 248, 207, 46, 25, 146, 165, 68, 115, 250, 205, 44, 27, 186, 141, 108, 91, 210, 229, 4, 51, 224, 215, 54, 1, 136, 191, 94, 105, 200, 255, 30, 41, 160, 151, 118, 65, 50, 5, 228, 211, 90, 109, 140, 187, 26, 45, 204, 251, 114, 69, 164, 147, 64, 119, 150, 161, 40, 31, 254, 201, 104, 95, 190, 137, 0, 55, 214, 225, 169, 158, 127, 72, 193, 246, 23, 32, 129, 182, 87, 96, 233, 222, 63, 8, 219, 236, 13, 58, 179, 132, 101, 82, 243, 196, 37, 18, 155, 172, 77, 122, 9, 62, 223, 232, 97, 86, 183, 128, 33, 22, 247, 192, 73, 126, 159, 168, 123, 76, 173, 154, 19, 36, 197, 242, 83, 100, 133, 178, 59, 12, 237, 218, 81, 102, 135, 176, 57, 14, 239, 216, 121, 78, 175, 152, 17, 38, 199, 240, 35, 20, 245, 194, 75, 124, 157, 170, 11, 60, 221, 234, 99, 84, 181, 130, 241, 198, 39, 16, 153, 174, 79, 120, 217, 238, 15, 56, 177, 134, 103, 80, 131, 180, 85, 98, 235, 220, 61, 10, 171, 156, 125, 74, 195, 244, 21, 34}, {141, 111, 121, 155, 212, 54, 32, 194, 214, 52, 34, 192, 143, 109, 123, 153, 172, 78, 88, 186, 245, 23, 1, 227, 247, 21, 3, 225, 174, 76, 90, 184, 151, 117, 99, 129, 206, 44, 58, 216, 204, 46, 56, 218, 149, 119, 97, 131, 182, 84, 66, 160, 239, 13, 27, 249, 237, 15, 25, 251, 180, 86, 64, 162, 22, 244, 226, 0, 79, 173, 187, 89, 77, 175, 185, 91, 20, 246, 224, 2, 55, 213, 195, 33, 110, 140, 154, 120, 108, 142, 152, 122, 53, 215, 193, 35, 12, 238, 248, 26, 85, 183, 161, 67, 87, 181, 163, 65, 14, 236, 250, 24, 45, 207, 217, 59, 116, 150, 128, 98, 118, 148, 130, 96, 47, 205, 219, 57, 253, 31, 9, 235, 164, 70, 80, 178, 166, 68, 82, 176, 255, 29, 11, 233, 220, 62, 40, 202, 133, 103, 113, 147, 135, 101, 115, 145, 222, 60, 42, 200, 231, 5, 19, 241, 190, 92, 74, 168, 188, 94, 72, 170, 229, 7, 17, 243, 198, 36, 50, 208, 159, 125, 107, 137, 157, 127, 105, 139, 196, 38, 48, 210, 102, 132, 146, 112, 63, 221, 203, 41, 61, 223, 201, 43, 100, 134, 144, 114, 71, 165, 179, 81, 30, 252, 234, 8, 28, 254, 232, 10, 69, 167, 177, 83, 124, 158, 136, 106, 37, 199, 209, 51, 39, 197, 211, 49, 126, 156, 138, 104, 93, 191, 169, 75, 4, 230, 240, 18, 6, 228, 242, 16, 95, 189, 171, 73}, {123, 26, 24, 121, 53, 84, 86, 55, 8, 105, 107, 10, 70, 39, 37, 68, 157, 252, 254, 159, 211, 178, 176, 209, 238, 143, 141, 236, 160, 193, 195, 162, 140, 237, 239, 142, 194, 163, 161, 192, 255, 158, 156, 253, 177, 208, 210, 179, 106, 11, 9, 104, 36, 69, 71, 38, 25, 120, 122, 27, 87, 54, 52, 85, 139, 234, 232, 137, 197, 164, 166, 199, 248, 153, 155, 250, 182, 215, 213, 180, 109, 12, 14, 111, 35, 66, 64, 33, 30, 127, 125, 28, 80, 49, 51, 82, 124, 29, 31, 126, 50, 83, 81, 48, 15, 110, 108, 13, 65, 32, 34, 67, 154, 251, 249, 152, 212, 181, 183, 214, 233, 136, 138, 235, 167, 198, 196, 165, 59, 90, 88, 57, 117, 20, 22, 119, 72, 41, 43, 74, 6, 103, 101, 4, 221, 188, 190, 223, 147, 242, 240, 145, 174, 207, 205, 172, 224, 129, 131, 226, 204, 173, 175, 206, 130, 227, 225, 128, 191, 222, 220, 189, 241, 144, 146, 243, 42, 75, 73, 40, 100, 5, 7, 102, 89, 56, 58, 91, 23, 118, 116, 21, 203, 170, 168, 201, 133, 228, 230, 135, 184, 217, 219, 186, 246, 151, 149, 244, 45, 76, 78, 47, 99, 2, 0, 97, 94, 63, 61, 92, 16, 113, 115, 18, 60, 93, 95, 62, 114, 19, 17, 112, 79, 46, 44, 77, 1, 96, 98, 3, 218, 187, 185, 216, 148, 245, 247, 150, 169, 200, 202, 171, 231, 134, 132, 229}, {4, 210, 131, 85, 242, 36, 117, 163, 125, 171, 250, 44, 139, 93, 12, 218, 111, 185, 232, 62, 153, 79, 30, 200, 22, 192, 145, 71, 224, 54, 103, 177, 88, 142, 223, 9, 174, 120, 41, 255, 33, 247, 166, 112, 215, 1, 80, 134, 51, 229, 180, 98, 197, 19, 66, 148, 74, 156, 205, 27, 188, 106, 59, 237, 175, 121, 40, 254, 89, 143, 222, 8, 214, 0, 81, 135, 32, 246, 167, 113, 196, 18, 67, 149, 50, 228, 181, 99, 189, 107, 58, 236, 75, 157, 204, 26, 243, 37, 116, 162, 5, 211, 130, 84, 138, 92, 13, 219, 124, 170, 251, 45, 152, 78, 31, 201, 110, 184, 233, 63, 225, 55, 102, 176, 23, 193, 144, 70, 160, 118, 39, 241, 86, 128, 209, 7, 217, 15, 94, 136, 47, 249, 168, 126, 203, 29, 76, 154, 61, 235, 186, 108, 178, 100, 53, 227, 68, 146, 195, 21, 252, 42, 123, 173, 10, 220, 141, 91, 133, 83, 2, 212, 115, 165, 244, 34, 151, 65, 16, 198, 97, 183, 230, 48, 238, 56, 105, 191, 24, 206, 159, 73, 11, 221, 140, 90, 253, 43, 122, 172, 114, 164, 245, 35, 132, 82, 3, 213, 96, 182, 231, 49, 150, 64, 17, 199, 25, 207, 158, 72, 239, 57, 104, 190, 87, 129, 208, 6, 161, 119, 38, 240, 46, 248, 169, 127, 216, 14, 95, 137, 60, 234, 187, 109, 202, 28, 77, 155, 69, 147, 194, 20, 179, 101, 52, 226}, {199, 73, 42, 164, 231, 105, 10, 132, 125, 243, 144, 30, 93, 211, 176, 62, 170, 36, 71, 201, 138, 4, 103, 233, 16, 158, 253, 115, 48, 190, 221, 83, 234, 100, 7, 137, 202, 68, 39, 169, 80, 222, 189, 51, 112, 254, 157, 19, 135, 9, 106, 228, 167, 41, 74, 196, 61, 179, 208, 94, 29, 147, 240, 126, 31, 145, 242, 124, 63, 177, 210, 92, 165, 43, 72, 198, 133, 11, 104, 230, 114, 252, 159, 17, 82, 220, 191, 49, 200, 70, 37, 171, 232, 102, 5, 139, 50, 188, 223, 81, 18, 156, 255, 113, 136, 6, 101, 235, 168, 38, 69, 203, 95, 209, 178, 60, 127, 241, 146, 28, 229, 107, 8, 134, 197, 75, 40, 166, 24, 150, 245, 123, 56, 182, 213, 91, 162, 44, 79, 193, 130, 12, 111, 225, 117, 251, 152, 22, 85, 219, 184, 54, 207, 65, 34, 172, 239, 97, 2, 140, 53, 187, 216, 86, 21, 155, 248, 118, 143, 1, 98, 236, 175, 33, 66, 204, 88, 214, 181, 59, 120, 246, 149, 27, 226, 108, 15, 129, 194, 76, 47, 161, 192, 78, 45, 163, 224, 110, 13, 131, 122, 244, 151, 25, 90, 212, 183, 57, 173, 35, 64, 206, 141, 3, 96, 238, 23, 153, 250, 116, 55, 185, 218, 84, 237, 99, 0, 142, 205, 67, 32, 174, 87, 217, 186, 52, 119, 249, 154, 20, 128, 14, 109, 227, 160, 46, 77, 195, 58, 180, 215, 89, 26, 148, 247, 121}, {221, 126, 250, 89, 208, 115, 247, 84, 120, 219, 95, 252, 117, 214, 82, 241, 26, 185, 61, 158, 23, 180, 48, 147, 191, 28, 152, 59, 178, 17, 149, 54, 64, 227, 103, 196, 77, 238, 106, 201, 229, 70, 194, 97, 232, 75, 207, 108, 135, 36, 160, 3, 138, 41, 173, 14, 34, 129, 5, 166, 47, 140, 8, 171, 71, 228, 96, 195, 74, 233, 109, 206, 226, 65, 197, 102, 239, 76, 200, 107, 128, 35, 167, 4, 141, 46, 170, 9, 37, 134, 2, 161, 40, 139, 15, 172, 218, 121, 253, 94, 215, 116, 240, 83, 127, 220, 88, 251, 114, 209, 85, 246, 29, 190, 58, 153, 16, 179, 55, 148, 184, 27, 159, 60, 181, 22, 146, 49, 169, 10, 142, 45, 164, 7, 131, 32, 12, 175, 43, 136, 1, 162, 38, 133, 110, 205, 73, 234, 99, 192, 68, 231, 203, 104, 236, 79, 198, 101, 225, 66, 52, 151, 19, 176, 57, 154, 30, 189, 145, 50, 182, 21, 156, 63, 187, 24, 243, 80, 212, 119, 254, 93, 217, 122, 86, 245, 113, 210, 91, 248, 124, 223, 51, 144, 20, 183, 62, 157, 25, 186, 150, 53, 177, 18, 155, 56, 188, 31, 244, 87, 211, 112, 249, 90, 222, 125, 81, 242, 118, 213, 92, 255, 123, 216, 174, 13, 137, 42, 163, 0, 132, 39, 11, 168, 44, 143, 6, 165, 33, 130, 105, 202, 78, 237, 100, 199, 67, 224, 204, 111, 235, 72, 193, 98, 230, 69}, {154, 7, 81, 204, 49, 172, 250, 103, 124, 225, 183, 42, 215, 74, 28, 129, 12, 145, 199, 90, 167, 58, 108, 241, 234, 119, 33, 188, 65, 220, 138, 23, 14, 147, 197, 88, 165, 56, 110, 243, 232, 117, 35, 190, 67, 222, 136, 21, 152, 5, 83, 206, 51, 174, 248, 101, 126, 227, 181, 40, 213, 72, 30, 131, 233, 116, 34, 191, 66, 223, 137, 20, 15, 146, 196, 89, 164, 57, 111, 242, 127, 226, 180, 41, 212, 73, 31, 130, 153, 4, 82, 207, 50, 175, 249, 100, 125, 224, 182, 43, 214, 75, 29, 128, 155, 6, 80, 205, 48, 173, 251, 102, 235, 118, 32, 189, 64, 221, 139, 22, 13, 144, 198, 91, 166, 59, 109, 240, 218, 71, 17, 140, 113, 236, 186, 39, 60, 161, 247, 106, 151, 10, 92, 193, 76, 209, 135, 26, 231, 122, 44, 177, 170, 55, 97, 252, 1, 156, 202, 87, 78, 211, 133, 24, 229, 120, 46, 179, 168, 53, 99, 254, 3, 158, 200, 85, 216, 69, 19, 142, 115, 238, 184, 37, 62, 163, 245, 104, 149, 8, 94, 195, 169, 52, 98, 255, 2, 159, 201, 84, 79, 210, 132, 25, 228, 121, 47, 178, 63, 162, 244, 105, 148, 9, 95, 194, 217, 68, 18, 143, 114, 239, 185, 36, 61, 160, 246, 107, 150, 11, 93, 192, 219, 70, 16, 141, 112, 237, 187, 38, 171, 54, 96, 253, 0, 157, 203, 86, 77, 208, 134, 27, 230, 123, 45, 176}, {235, 14, 238, 11, 175, 74, 170, 79, 94, 187, 91, 190, 26, 255, 31, 250, 98, 135, 103, 130, 38, 195, 35, 198, 215, 50, 210, 55, 147, 118, 150, 115, 158, 123, 155, 126, 218, 63, 223, 58, 43, 206, 46, 203, 111, 138, 106, 143, 23, 242, 18, 247, 83, 182, 86, 179, 162, 71, 167, 66, 230, 3, 227, 6, 80, 181, 85, 176, 20, 241, 17, 244, 229, 0, 224, 5, 161, 68, 164, 65, 217, 60, 220, 57, 157, 120, 152, 125, 108, 137, 105, 140, 40, 205, 45, 200, 37, 192, 32, 197, 97, 132, 100, 129, 144, 117, 149, 112, 212, 49, 209, 52, 172, 73, 169, 76, 232, 13, 237, 8, 25, 252, 28, 249, 93, 184, 88, 189, 134, 99, 131, 102, 194, 39, 199, 34, 51, 214, 54, 211, 119, 146, 114, 151, 15, 234, 10, 239, 75, 174, 78, 171, 186, 95, 191, 90, 254, 27, 251, 30, 243, 22, 246, 19, 183, 82, 178, 87, 70, 163, 67, 166, 2, 231, 7, 226, 122, 159, 127, 154, 62, 219, 59, 222, 207, 42, 202, 47, 139, 110, 142, 107, 61, 216, 56, 221, 121, 156, 124, 153, 136, 109, 141, 104, 204, 41, 201, 44, 180, 81, 177, 84, 240, 21, 245, 16, 1, 228, 4, 225, 69, 160, 64, 165, 72, 173, 77, 168, 12, 233, 9, 236, 253, 24, 248, 29, 185, 92, 188, 89, 193, 36, 196, 33, 133, 96, 128, 101, 116, 145, 113, 148, 48, 213, 53, 208} };
    m1.mpos = 0x181e5919f;
    m1.slut = 125;
    m1.get_param = &get_3;
    m1.mbox_create = 0x181e51350;
    ret.mbox_data.push_back(m1);


    MbLut m2;
    m2.lut = { {121, 52, 140, 193, 47, 98, 218, 151, 9, 68, 252, 177, 95, 18, 170, 231, 75, 6, 190, 243, 29, 80, 232, 165, 59, 118, 206, 131, 109, 32, 152, 213, 119, 58, 130, 207, 33, 108, 212, 153, 7, 74, 242, 191, 81, 28, 164, 233, 69, 8, 176, 253, 19, 94, 230, 171, 53, 120, 192, 141, 99, 46, 150, 219, 182, 251, 67, 14, 224, 173, 21, 88, 198, 139, 51, 126, 144, 221, 101, 40, 132, 201, 113, 60, 210, 159, 39, 106, 244, 185, 1, 76, 162, 239, 87, 26, 184, 245, 77, 0, 238, 163, 27, 86, 200, 133, 61, 112, 158, 211, 107, 38, 138, 199, 127, 50, 220, 145, 41, 100, 250, 183, 15, 66, 172, 225, 89, 20, 134, 203, 115, 62, 208, 157, 37, 104, 246, 187, 3, 78, 160, 237, 85, 24, 180, 249, 65, 12, 226, 175, 23, 90, 196, 137, 49, 124, 146, 223, 103, 42, 136, 197, 125, 48, 222, 147, 43, 102, 248, 181, 13, 64, 174, 227, 91, 22, 186, 247, 79, 2, 236, 161, 25, 84, 202, 135, 63, 114, 156, 209, 105, 36, 73, 4, 188, 241, 31, 82, 234, 167, 57, 116, 204, 129, 111, 34, 154, 215, 123, 54, 142, 195, 45, 96, 216, 149, 11, 70, 254, 179, 93, 16, 168, 229, 71, 10, 178, 255, 17, 92, 228, 169, 55, 122, 194, 143, 97, 44, 148, 217, 117, 56, 128, 205, 35, 110, 214, 155, 5, 72, 240, 189, 83, 30, 166, 235}, {250, 113, 17, 154, 16, 155, 251, 112, 255, 116, 20, 159, 21, 158, 254, 117, 8, 131, 227, 104, 226, 105, 9, 130, 13, 134, 230, 109, 231, 108, 12, 135, 129, 10, 106, 225, 107, 224, 128, 11, 132, 15, 111, 228, 110, 229, 133, 14, 115, 248, 152, 19, 153, 18, 114, 249, 118, 253, 157, 22, 156, 23, 119, 252, 217, 82, 50, 185, 51, 184, 216, 83, 220, 87, 55, 188, 54, 189, 221, 86, 43, 160, 192, 75, 193, 74, 42, 161, 46, 165, 197, 78, 196, 79, 47, 164, 162, 41, 73, 194, 72, 195, 163, 40, 167, 44, 76, 199, 77, 198, 166, 45, 80, 219, 187, 48, 186, 49, 81, 218, 85, 222, 190, 53, 191, 52, 84, 223, 61, 182, 214, 93, 215, 92, 60, 183, 56, 179, 211, 88, 210, 89, 57, 178, 207, 68, 36, 175, 37, 174, 206, 69, 202, 65, 33, 170, 32, 171, 203, 64, 70, 205, 173, 38, 172, 39, 71, 204, 67, 200, 168, 35, 169, 34, 66, 201, 180, 63, 95, 212, 94, 213, 181, 62, 177, 58, 90, 209, 91, 208, 176, 59, 30, 149, 245, 126, 244, 127, 31, 148, 27, 144, 240, 123, 241, 122, 26, 145, 236, 103, 7, 140, 6, 141, 237, 102, 233, 98, 2, 137, 3, 136, 232, 99, 101, 238, 142, 5, 143, 4, 100, 239, 96, 235, 139, 0, 138, 1, 97, 234, 151, 28, 124, 247, 125, 246, 150, 29, 146, 25, 121, 242, 120, 243, 147, 24}, {169, 234, 166, 229, 13, 78, 2, 65, 145, 210, 158, 221, 53, 118, 58, 121, 21, 86, 26, 89, 177, 242, 190, 253, 45, 110, 34, 97, 137, 202, 134, 197, 205, 142, 194, 129, 105, 42, 102, 37, 245, 182, 250, 185, 81, 18, 94, 29, 113, 50, 126, 61, 213, 150, 218, 153, 73, 10, 70, 5, 237, 174, 226, 161, 7, 68, 8, 75, 163, 224, 172, 239, 63, 124, 48, 115, 155, 216, 148, 215, 187, 248, 180, 247, 31, 92, 16, 83, 131, 192, 140, 207, 39, 100, 40, 107, 99, 32, 108, 47, 199, 132, 200, 139, 91, 24, 84, 23, 255, 188, 240, 179, 223, 156, 208, 147, 123, 56, 116, 55, 231, 164, 232, 171, 67, 0, 76, 15, 168, 235, 167, 228, 12, 79, 3, 64, 144, 211, 159, 220, 52, 119, 59, 120, 20, 87, 27, 88, 176, 243, 191, 252, 44, 111, 35, 96, 136, 203, 135, 196, 204, 143, 195, 128, 104, 43, 103, 36, 244, 183, 251, 184, 80, 19, 95, 28, 112, 51, 127, 60, 212, 151, 219, 152, 72, 11, 71, 4, 236, 175, 227, 160, 6, 69, 9, 74, 162, 225, 173, 238, 62, 125, 49, 114, 154, 217, 149, 214, 186, 249, 181, 246, 30, 93, 17, 82, 130, 193, 141, 206, 38, 101, 41, 106, 98, 33, 109, 46, 198, 133, 201, 138, 90, 25, 85, 22, 254, 189, 241, 178, 222, 157, 209, 146, 122, 57, 117, 54, 230, 165, 233, 170, 66, 1, 77, 14}, {232, 216, 255, 207, 52, 4, 35, 19, 49, 1, 38, 22, 237, 221, 250, 202, 210, 226, 197, 245, 14, 62, 25, 41, 11, 59, 28, 44, 215, 231, 192, 240, 115, 67, 100, 84, 175, 159, 184, 136, 170, 154, 189, 141, 118, 70, 97, 81, 73, 121, 94, 110, 149, 165, 130, 178, 144, 160, 135, 183, 76, 124, 91, 107, 158, 174, 137, 185, 66, 114, 85, 101, 71, 119, 80, 96, 155, 171, 140, 188, 164, 148, 179, 131, 120, 72, 111, 95, 125, 77, 106, 90, 161, 145, 182, 134, 5, 53, 18, 34, 217, 233, 206, 254, 220, 236, 203, 251, 0, 48, 23, 39, 63, 15, 40, 24, 227, 211, 244, 196, 230, 214, 241, 193, 58, 10, 45, 29, 129, 177, 150, 166, 93, 109, 74, 122, 88, 104, 79, 127, 132, 180, 147, 163, 187, 139, 172, 156, 103, 87, 112, 64, 98, 82, 117, 69, 190, 142, 169, 153, 26, 42, 13, 61, 198, 246, 209, 225, 195, 243, 212, 228, 31, 47, 8, 56, 32, 16, 55, 7, 252, 204, 235, 219, 249, 201, 238, 222, 37, 21, 50, 2, 247, 199, 224, 208, 43, 27, 60, 12, 46, 30, 57, 9, 242, 194, 229, 213, 205, 253, 218, 234, 17, 33, 6, 54, 20, 36, 3, 51, 200, 248, 223, 239, 108, 92, 123, 75, 176, 128, 167, 151, 181, 133, 162, 146, 105, 89, 126, 78, 86, 102, 65, 113, 138, 186, 157, 173, 143, 191, 152, 168, 83, 99, 68, 116}, {190, 17, 192, 111, 53, 154, 75, 228, 36, 139, 90, 245, 175, 0, 209, 126, 196, 107, 186, 21, 79, 224, 49, 158, 94, 241, 32, 143, 213, 122, 171, 4, 179, 28, 205, 98, 56, 151, 70, 233, 41, 134, 87, 248, 162, 13, 220, 115, 201, 102, 183, 24, 66, 237, 60, 147, 83, 252, 45, 130, 216, 119, 166, 9, 110, 193, 16, 191, 229, 74, 155, 52, 244, 91, 138, 37, 127, 208, 1, 174, 20, 187, 106, 197, 159, 48, 225, 78, 142, 33, 240, 95, 5, 170, 123, 212, 99, 204, 29, 178, 232, 71, 150, 57, 249, 86, 135, 40, 114, 221, 12, 163, 25, 182, 103, 200, 146, 61, 236, 67, 131, 44, 253, 82, 8, 167, 118, 217, 18, 189, 108, 195, 153, 54, 231, 72, 136, 39, 246, 89, 3, 172, 125, 210, 104, 199, 22, 185, 227, 76, 157, 50, 242, 93, 140, 35, 121, 214, 7, 168, 31, 176, 97, 206, 148, 59, 234, 69, 133, 42, 251, 84, 14, 161, 112, 223, 101, 202, 27, 180, 238, 65, 144, 63, 255, 80, 129, 46, 116, 219, 10, 165, 194, 109, 188, 19, 73, 230, 55, 152, 88, 247, 38, 137, 211, 124, 173, 2, 184, 23, 198, 105, 51, 156, 77, 226, 34, 141, 92, 243, 169, 6, 215, 120, 207, 96, 177, 30, 68, 235, 58, 149, 85, 250, 43, 132, 222, 113, 160, 15, 181, 26, 203, 100, 62, 145, 64, 239, 47, 128, 81, 254, 164, 11, 218, 117}, {137, 115, 207, 53, 182, 76, 240, 10, 253, 7, 187, 65, 194, 56, 132, 126, 40, 210, 110, 148, 23, 237, 81, 171, 92, 166, 26, 224, 99, 153, 37, 223, 11, 241, 77, 183, 52, 206, 114, 136, 127, 133, 57, 195, 64, 186, 6, 252, 170, 80, 236, 22, 149, 111, 211, 41, 222, 36, 152, 98, 225, 27, 167, 93, 63, 197, 121, 131, 0, 250, 70, 188, 75, 177, 13, 247, 116, 142, 50, 200, 158, 100, 216, 34, 161, 91, 231, 29, 234, 16, 172, 86, 213, 47, 147, 105, 189, 71, 251, 1, 130, 120, 196, 62, 201, 51, 143, 117, 246, 12, 176, 74, 28, 230, 90, 160, 35, 217, 101, 159, 104, 146, 46, 212, 87, 173, 17, 235, 84, 174, 18, 232, 107, 145, 45, 215, 32, 218, 102, 156, 31, 229, 89, 163, 245, 15, 179, 73, 202, 48, 140, 118, 129, 123, 199, 61, 190, 68, 248, 2, 214, 44, 144, 106, 233, 19, 175, 85, 162, 88, 228, 30, 157, 103, 219, 33, 119, 141, 49, 203, 72, 178, 14, 244, 3, 249, 69, 191, 60, 198, 122, 128, 226, 24, 164, 94, 221, 39, 155, 97, 150, 108, 208, 42, 169, 83, 239, 21, 67, 185, 5, 255, 124, 134, 58, 192, 55, 205, 113, 139, 8, 242, 78, 180, 96, 154, 38, 220, 95, 165, 25, 227, 20, 238, 82, 168, 43, 209, 109, 151, 193, 59, 135, 125, 254, 4, 184, 66, 181, 79, 243, 9, 138, 112, 204, 54}, {95, 100, 91, 96, 182, 141, 178, 137, 192, 251, 196, 255, 41, 18, 45, 22, 177, 138, 181, 142, 88, 99, 92, 103, 46, 21, 42, 17, 199, 252, 195, 248, 183, 140, 179, 136, 94, 101, 90, 97, 40, 19, 44, 23, 193, 250, 197, 254, 89, 98, 93, 102, 176, 139, 180, 143, 198, 253, 194, 249, 47, 20, 43, 16, 151, 172, 147, 168, 126, 69, 122, 65, 8, 51, 12, 55, 225, 218, 229, 222, 121, 66, 125, 70, 144, 171, 148, 175, 230, 221, 226, 217, 15, 52, 11, 48, 127, 68, 123, 64, 150, 173, 146, 169, 224, 219, 228, 223, 9, 50, 13, 54, 145, 170, 149, 174, 120, 67, 124, 71, 14, 53, 10, 49, 231, 220, 227, 216, 152, 163, 156, 167, 113, 74, 117, 78, 7, 60, 3, 56, 238, 213, 234, 209, 118, 77, 114, 73, 159, 164, 155, 160, 233, 210, 237, 214, 0, 59, 4, 63, 112, 75, 116, 79, 153, 162, 157, 166, 239, 212, 235, 208, 6, 61, 2, 57, 158, 165, 154, 161, 119, 76, 115, 72, 1, 58, 5, 62, 232, 211, 236, 215, 80, 107, 84, 111, 185, 130, 189, 134, 207, 244, 203, 240, 38, 29, 34, 25, 190, 133, 186, 129, 87, 108, 83, 104, 33, 26, 37, 30, 200, 243, 204, 247, 184, 131, 188, 135, 81, 106, 85, 110, 39, 28, 35, 24, 206, 245, 202, 241, 86, 109, 82, 105, 191, 132, 187, 128, 201, 242, 205, 246, 32, 27, 36, 31}, {29, 176, 10, 167, 218, 119, 205, 96, 45, 128, 58, 151, 234, 71, 253, 80, 115, 222, 100, 201, 180, 25, 163, 14, 67, 238, 84, 249, 132, 41, 147, 62, 252, 81, 235, 70, 59, 150, 44, 129, 204, 97, 219, 118, 11, 166, 28, 177, 146, 63, 133, 40, 85, 248, 66, 239, 162, 15, 181, 24, 101, 200, 114, 223, 148, 57, 131, 46, 83, 254, 68, 233, 164, 9, 179, 30, 99, 206, 116, 217, 250, 87, 237, 64, 61, 144, 42, 135, 202, 103, 221, 112, 13, 160, 26, 183, 117, 216, 98, 207, 178, 31, 165, 8, 69, 232, 82, 255, 130, 47, 149, 56, 27, 182, 12, 161, 220, 113, 203, 102, 43, 134, 60, 145, 236, 65, 251, 86, 231, 74, 240, 93, 32, 141, 55, 154, 215, 122, 192, 109, 16, 189, 7, 170, 137, 36, 158, 51, 78, 227, 89, 244, 185, 20, 174, 3, 126, 211, 105, 196, 6, 171, 17, 188, 193, 108, 214, 123, 54, 155, 33, 140, 241, 92, 230, 75, 104, 197, 127, 210, 175, 2, 184, 21, 88, 245, 79, 226, 159, 50, 136, 37, 110, 195, 121, 212, 169, 4, 190, 19, 94, 243, 73, 228, 153, 52, 142, 35, 0, 173, 23, 186, 199, 106, 208, 125, 48, 157, 39, 138, 247, 90, 224, 77, 143, 34, 152, 53, 72, 229, 95, 242, 191, 18, 168, 5, 120, 213, 111, 194, 225, 76, 246, 91, 38, 139, 49, 156, 209, 124, 198, 107, 22, 187, 1, 172}, {205, 4, 129, 72, 98, 171, 46, 231, 106, 163, 38, 239, 197, 12, 137, 64, 8, 193, 68, 141, 167, 110, 235, 34, 175, 102, 227, 42, 0, 201, 76, 133, 6, 207, 74, 131, 169, 96, 229, 44, 161, 104, 237, 36, 14, 199, 66, 139, 195, 10, 143, 70, 108, 165, 32, 233, 100, 173, 40, 225, 203, 2, 135, 78, 7, 206, 75, 130, 168, 97, 228, 45, 160, 105, 236, 37, 15, 198, 67, 138, 194, 11, 142, 71, 109, 164, 33, 232, 101, 172, 41, 224, 202, 3, 134, 79, 204, 5, 128, 73, 99, 170, 47, 230, 107, 162, 39, 238, 196, 13, 136, 65, 9, 192, 69, 140, 166, 111, 234, 35, 174, 103, 226, 43, 1, 200, 77, 132, 209, 24, 157, 84, 126, 183, 50, 251, 118, 191, 58, 243, 217, 16, 149, 92, 20, 221, 88, 145, 187, 114, 247, 62, 179, 122, 255, 54, 28, 213, 80, 153, 26, 211, 86, 159, 181, 124, 249, 48, 189, 116, 241, 56, 18, 219, 94, 151, 223, 22, 147, 90, 112, 185, 60, 245, 120, 177, 52, 253, 215, 30, 155, 82, 27, 210, 87, 158, 180, 125, 248, 49, 188, 117, 240, 57, 19, 218, 95, 150, 222, 23, 146, 91, 113, 184, 61, 244, 121, 176, 53, 252, 214, 31, 154, 83, 208, 25, 156, 85, 127, 182, 51, 250, 119, 190, 59, 242, 216, 17, 148, 93, 21, 220, 89, 144, 186, 115, 246, 63, 178, 123, 254, 55, 29, 212, 81, 152}, {60, 1, 229, 216, 252, 193, 37, 24, 230, 219, 63, 2, 38, 27, 255, 194, 241, 204, 40, 21, 49, 12, 232, 213, 43, 22, 242, 207, 235, 214, 50, 15, 55, 10, 238, 211, 247, 202, 46, 19, 237, 208, 52, 9, 45, 16, 244, 201, 250, 199, 35, 30, 58, 7, 227, 222, 32, 29, 249, 196, 224, 221, 57, 4, 170, 151, 115, 78, 106, 87, 179, 142, 112, 77, 169, 148, 176, 141, 105, 84, 103, 90, 190, 131, 167, 154, 126, 67, 189, 128, 100, 89, 125, 64, 164, 153, 161, 156, 120, 69, 97, 92, 184, 133, 123, 70, 162, 159, 187, 134, 98, 95, 108, 81, 181, 136, 172, 145, 117, 72, 182, 139, 111, 82, 118, 75, 175, 146, 165, 152, 124, 65, 101, 88, 188, 129, 127, 66, 166, 155, 191, 130, 102, 91, 104, 85, 177, 140, 168, 149, 113, 76, 178, 143, 107, 86, 114, 79, 171, 150, 174, 147, 119, 74, 110, 83, 183, 138, 116, 73, 173, 144, 180, 137, 109, 80, 99, 94, 186, 135, 163, 158, 122, 71, 185, 132, 96, 93, 121, 68, 160, 157, 51, 14, 234, 215, 243, 206, 42, 23, 233, 212, 48, 13, 41, 20, 240, 205, 254, 195, 39, 26, 62, 3, 231, 218, 36, 25, 253, 192, 228, 217, 61, 0, 56, 5, 225, 220, 248, 197, 33, 28, 226, 223, 59, 6, 34, 31, 251, 198, 245, 200, 44, 17, 53, 8, 236, 209, 47, 18, 246, 203, 239, 210, 54, 11}, {133, 48, 96, 213, 28, 169, 249, 76, 231, 82, 2, 183, 126, 203, 155, 46, 149, 32, 112, 197, 12, 185, 233, 92, 247, 66, 18, 167, 110, 219, 139, 62, 35, 150, 198, 115, 186, 15, 95, 234, 65, 244, 164, 17, 216, 109, 61, 136, 51, 134, 214, 99, 170, 31, 79, 250, 81, 228, 180, 1, 200, 125, 45, 152, 154, 47, 127, 202, 3, 182, 230, 83, 248, 77, 29, 168, 97, 212, 132, 49, 138, 63, 111, 218, 19, 166, 246, 67, 232, 93, 13, 184, 113, 196, 148, 33, 60, 137, 217, 108, 165, 16, 64, 245, 94, 235, 187, 14, 199, 114, 34, 151, 44, 153, 201, 124, 181, 0, 80, 229, 78, 251, 171, 30, 215, 98, 50, 135, 70, 243, 163, 22, 223, 106, 58, 143, 36, 145, 193, 116, 189, 8, 88, 237, 86, 227, 179, 6, 207, 122, 42, 159, 52, 129, 209, 100, 173, 24, 72, 253, 224, 85, 5, 176, 121, 204, 156, 41, 130, 55, 103, 210, 27, 174, 254, 75, 240, 69, 21, 160, 105, 220, 140, 57, 146, 39, 119, 194, 11, 190, 238, 91, 89, 236, 188, 9, 192, 117, 37, 144, 59, 142, 222, 107, 162, 23, 71, 242, 73, 252, 172, 25, 208, 101, 53, 128, 43, 158, 206, 123, 178, 7, 87, 226, 255, 74, 26, 175, 102, 211, 131, 54, 157, 40, 120, 205, 4, 177, 225, 84, 239, 90, 10, 191, 118, 195, 147, 38, 141, 56, 104, 221, 20, 161, 241, 68}, {219, 153, 59, 121, 248, 186, 24, 90, 34, 96, 194, 128, 1, 67, 225, 163, 249, 187, 25, 91, 218, 152, 58, 120, 0, 66, 224, 162, 35, 97, 195, 129, 101, 39, 133, 199, 70, 4, 166, 228, 156, 222, 124, 62, 191, 253, 95, 29, 71, 5, 167, 229, 100, 38, 132, 198, 190, 252, 94, 28, 157, 223, 125, 63, 72, 10, 168, 234, 107, 41, 139, 201, 177, 243, 81, 19, 146, 208, 114, 48, 106, 40, 138, 200, 73, 11, 169, 235, 147, 209, 115, 49, 176, 242, 80, 18, 246, 180, 22, 84, 213, 151, 53, 119, 15, 77, 239, 173, 44, 110, 204, 142, 212, 150, 52, 118, 247, 181, 23, 85, 45, 111, 205, 143, 14, 76, 238, 172, 203, 137, 43, 105, 232, 170, 8, 74, 50, 112, 210, 144, 17, 83, 241, 179, 233, 171, 9, 75, 202, 136, 42, 104, 16, 82, 240, 178, 51, 113, 211, 145, 117, 55, 149, 215, 86, 20, 182, 244, 140, 206, 108, 46, 175, 237, 79, 13, 87, 21, 183, 245, 116, 54, 148, 214, 174, 236, 78, 12, 141, 207, 109, 47, 88, 26, 184, 250, 123, 57, 155, 217, 161, 227, 65, 3, 130, 192, 98, 32, 122, 56, 154, 216, 89, 27, 185, 251, 131, 193, 99, 33, 160, 226, 64, 2, 230, 164, 6, 68, 197, 135, 37, 103, 31, 93, 255, 189, 60, 126, 220, 158, 196, 134, 36, 102, 231, 165, 7, 69, 61, 127, 221, 159, 30, 92, 254, 188}, {68, 201, 164, 41, 9, 132, 233, 100, 249, 116, 25, 148, 180, 57, 84, 217, 28, 145, 252, 113, 81, 220, 177, 60, 161, 44, 65, 204, 236, 97, 12, 129, 83, 222, 179, 62, 30, 147, 254, 115, 238, 99, 14, 131, 163, 46, 67, 206, 11, 134, 235, 102, 70, 203, 166, 43, 182, 59, 86, 219, 251, 118, 27, 150, 146, 31, 114, 255, 223, 82, 63, 178, 47, 162, 207, 66, 98, 239, 130, 15, 202, 71, 42, 167, 135, 10, 103, 234, 119, 250, 151, 26, 58, 183, 218, 87, 133, 8, 101, 232, 200, 69, 40, 165, 56, 181, 216, 85, 117, 248, 149, 24, 221, 80, 61, 176, 144, 29, 112, 253, 96, 237, 128, 13, 45, 160, 205, 64, 244, 121, 20, 153, 185, 52, 89, 212, 73, 196, 169, 36, 4, 137, 228, 105, 172, 33, 76, 193, 225, 108, 1, 140, 17, 156, 241, 124, 92, 209, 188, 49, 227, 110, 3, 142, 174, 35, 78, 195, 94, 211, 190, 51, 19, 158, 243, 126, 187, 54, 91, 214, 246, 123, 22, 155, 6, 139, 230, 107, 75, 198, 171, 38, 34, 175, 194, 79, 111, 226, 143, 2, 159, 18, 127, 242, 210, 95, 50, 191, 122, 247, 154, 23, 55, 186, 215, 90, 199, 74, 39, 170, 138, 7, 106, 231, 53, 184, 213, 88, 120, 245, 152, 21, 136, 5, 104, 229, 197, 72, 37, 168, 109, 224, 141, 0, 32, 173, 192, 77, 208, 93, 48, 189, 157, 16, 125, 240}, {127, 156, 159, 124, 36, 199, 196, 39, 63, 220, 223, 60, 100, 135, 132, 103, 200, 43, 40, 203, 147, 112, 115, 144, 136, 107, 104, 139, 211, 48, 51, 208, 233, 10, 9, 234, 178, 81, 82, 177, 169, 74, 73, 170, 242, 17, 18, 241, 94, 189, 190, 93, 5, 230, 229, 6, 30, 253, 254, 29, 69, 166, 165, 70, 102, 133, 134, 101, 61, 222, 221, 62, 38, 197, 198, 37, 125, 158, 157, 126, 209, 50, 49, 210, 138, 105, 106, 137, 145, 114, 113, 146, 202, 41, 42, 201, 240, 19, 16, 243, 171, 72, 75, 168, 176, 83, 80, 179, 235, 8, 11, 232, 71, 164, 167, 68, 28, 255, 252, 31, 7, 228, 231, 4, 92, 191, 188, 95, 152, 123, 120, 155, 195, 32, 35, 192, 216, 59, 56, 219, 131, 96, 99, 128, 47, 204, 207, 44, 116, 151, 148, 119, 111, 140, 143, 108, 52, 215, 212, 55, 14, 237, 238, 13, 85, 182, 181, 86, 78, 173, 174, 77, 21, 246, 245, 22, 185, 90, 89, 186, 226, 1, 2, 225, 249, 26, 25, 250, 162, 65, 66, 161, 129, 98, 97, 130, 218, 57, 58, 217, 193, 34, 33, 194, 154, 121, 122, 153, 54, 213, 214, 53, 109, 142, 141, 110, 118, 149, 150, 117, 45, 206, 205, 46, 23, 244, 247, 20, 76, 175, 172, 79, 87, 180, 183, 84, 12, 239, 236, 15, 160, 67, 64, 163, 251, 24, 27, 248, 224, 3, 0, 227, 187, 88, 91, 184}, {170, 76, 86, 176, 69, 163, 185, 95, 67, 165, 191, 89, 172, 74, 80, 182, 97, 135, 157, 123, 142, 104, 114, 148, 136, 110, 116, 146, 103, 129, 155, 125, 7, 225, 251, 29, 232, 14, 20, 242, 238, 8, 18, 244, 1, 231, 253, 27, 204, 42, 48, 214, 35, 197, 223, 57, 37, 195, 217, 63, 202, 44, 54, 208, 166, 64, 90, 188, 73, 175, 181, 83, 79, 169, 179, 85, 160, 70, 92, 186, 109, 139, 145, 119, 130, 100, 126, 152, 132, 98, 120, 158, 107, 141, 151, 113, 11, 237, 247, 17, 228, 2, 24, 254, 226, 4, 30, 248, 13, 235, 241, 23, 192, 38, 60, 218, 47, 201, 211, 53, 41, 207, 213, 51, 198, 32, 58, 220, 16, 246, 236, 10, 255, 25, 3, 229, 249, 31, 5, 227, 22, 240, 234, 12, 219, 61, 39, 193, 52, 210, 200, 46, 50, 212, 206, 40, 221, 59, 33, 199, 189, 91, 65, 167, 82, 180, 174, 72, 84, 178, 168, 78, 187, 93, 71, 161, 118, 144, 138, 108, 153, 127, 101, 131, 159, 121, 99, 133, 112, 150, 140, 106, 28, 250, 224, 6, 243, 21, 15, 233, 245, 19, 9, 239, 26, 252, 230, 0, 215, 49, 43, 205, 56, 222, 196, 34, 62, 216, 194, 36, 209, 55, 45, 203, 177, 87, 77, 171, 94, 184, 162, 68, 88, 190, 164, 66, 183, 81, 75, 173, 122, 156, 134, 96, 149, 115, 105, 143, 147, 117, 111, 137, 124, 154, 128, 102}, {96, 171, 166, 109, 203, 0, 13, 198, 242, 57, 52, 255, 89, 146, 159, 84, 20, 223, 210, 25, 191, 116, 121, 178, 134, 77, 64, 139, 45, 230, 235, 32, 142, 69, 72, 131, 37, 238, 227, 40, 28, 215, 218, 17, 183, 124, 113, 186, 250, 49, 60, 247, 81, 154, 151, 92, 104, 163, 174, 101, 195, 8, 5, 206, 143, 68, 73, 130, 36, 239, 226, 41, 29, 214, 219, 16, 182, 125, 112, 187, 251, 48, 61, 246, 80, 155, 150, 93, 105, 162, 175, 100, 194, 9, 4, 207, 97, 170, 167, 108, 202, 1, 12, 199, 243, 56, 53, 254, 88, 147, 158, 85, 21, 222, 211, 24, 190, 117, 120, 179, 135, 76, 65, 138, 44, 231, 234, 33, 74, 129, 140, 71, 225, 42, 39, 236, 216, 19, 30, 213, 115, 184, 181, 126, 62, 245, 248, 51, 149, 94, 83, 152, 172, 103, 106, 161, 7, 204, 193, 10, 164, 111, 98, 169, 15, 196, 201, 2, 54, 253, 240, 59, 157, 86, 91, 144, 208, 27, 22, 221, 123, 176, 189, 118, 66, 137, 132, 79, 233, 34, 47, 228, 165, 110, 99, 168, 14, 197, 200, 3, 55, 252, 241, 58, 156, 87, 90, 145, 209, 26, 23, 220, 122, 177, 188, 119, 67, 136, 133, 78, 232, 35, 46, 229, 75, 128, 141, 70, 224, 43, 38, 237, 217, 18, 31, 212, 114, 185, 180, 127, 63, 244, 249, 50, 148, 95, 82, 153, 173, 102, 107, 160, 6, 205, 192, 11} };
    m2.readout = 0x1801eb7e0;
    m2.mpos = 0x1801d5e47;
    m2.slut = 91;
    m2.get_param = &get_1;
    m2.mbox_precreate = 0x1801e4e50;
    m2.mbox_create = 0x1801d13f0;

    ret.mbox_data.push_back(m2);
    ret.version = "AMZNKindle.AmazonKindleReadingApp_1.0.25218";
    ret.vernum = 8;

    ret.entry = 0;


    return ret;
}
#endif
struct IATRESULTS
{
    enum class FAILUREREASON
    {
        SUCCESS = 0,
        OTHER = 1,
        NOTFOUND = 2,
        CANNOTPATCH = 3,
    };
    struct FUNCTIONINFO
    {
        std::string name;
        size_t ord = 0;
        FAILUREREASON f = FAILUREREASON::SUCCESS;
    };
    struct MODULEINFO
    {
        std::string name;
        HINSTANCE handle = 0;
        FAILUREREASON f = FAILUREREASON::SUCCESS;
        std::vector<FUNCTIONINFO> functions;
    };

    std::vector<MODULEINFO> modules;
    std::vector<FUNCTIONINFO> functions;
};
wchar_t* main_path = nullptr;
std::string WcharToUtf8(const WCHAR* wideString, size_t length)
{
    if (length == 0)
        length = wcslen(wideString);

    if (length == 0)
        return std::string();

    std::string convertedString(WideCharToMultiByte(CP_UTF8, 0, wideString, (int)length, NULL, 0, NULL, NULL), 0);

    WideCharToMultiByte(
        CP_UTF8, 0, wideString, (int)length, &convertedString[0], (int)convertedString.size(), NULL, NULL);

    return convertedString;
}

typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
    PWSTR DllPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID* BaseAddress
    );

// Stores the original address/trampoline of LdrLoadDll to call it natively
LdrLoadDll_t OriginalLdrLoadDll = nullptr;
LdrLoadDll_t g_OriginalLdrLoadDllAddress = nullptr;
//typedef NTSTATUS(NTAPI* LdrLoadDll_t)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
//extern LdrLoadDll_t g_OriginalLdrLoadDllAddress;



// Typedef for your original function tracking (adjust as necessary)
void PrintWin32Error(const char* context)
{
    DWORD errorCode = GetLastError();
    LPSTR messageBuffer = nullptr;

    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );

    std::string message = size > 0 ? messageBuffer : "Unknown error.";
    if (messageBuffer) LocalFree(messageBuffer);

    // Strip trailing newlines from the system message
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
        message.pop_back();
    }

    std::cout << "[-] " << context << " failed. Error Code: 0x"
        << std::hex << errorCode << std::dec << " (" << message << ")" << std::endl;
}
bool OverwriteExportTable(LPCSTR module, const char* name, ULONG_PTR replacement)
{
    // 1. Get base handle of loaded module
    HMODULE hModule = GetModuleHandleA(module);
    if (!hModule) return false;

    BYTE* baseAddress = reinterpret_cast<BYTE*>(hModule);

    // 2. Parse PE Headers
    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    // 3. Architecture-independent Data Directory location lookup
    IMAGE_DATA_DIRECTORY exportDataDir;
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto pNtHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pNtHeaders);
        exportDataDir = pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto pNtHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pNtHeaders);
        exportDataDir = pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        return false;
    }

    if (exportDataDir.VirtualAddress == 0) return false;

    auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(baseAddress + exportDataDir.VirtualAddress);

    // 4. Resolve the lookup arrays
    DWORD* pAddressOfFunctions = reinterpret_cast<DWORD*>(baseAddress + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = reinterpret_cast<DWORD*>(baseAddress + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = reinterpret_cast<WORD*>(baseAddress + pExportDir->AddressOfNameOrdinals);

    // 5. Look for the target export name string
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        const char* exportName = reinterpret_cast<const char*>(baseAddress + pAddressOfNames[i]);

        if (strcmp(exportName, name) == 0)
        {
            printf("[+] Found export %s\n", name);

            WORD ordinalIndex = pAddressOfNameOrdinals[i];
            DWORD originalRVA = pAddressOfFunctions[ordinalIndex];

            // Save the absolute pointer for fallback use
            g_OriginalLdrLoadDllAddress = reinterpret_cast<LdrLoadDll_t>(baseAddress + originalRVA);

            ULONG_PTR hookAbsoluteAddress = replacement;
            ULONG_PTR baseAbsoluteAddress = reinterpret_cast<ULONG_PTR>(baseAddress);

            // 6. Check if target address exceeds 32-bit RVA limits
            int64_t distance = static_cast<int64_t>(hookAbsoluteAddress) - static_cast<int64_t>(baseAbsoluteAddress);

            // A 32-bit relative offset must fit between INT32_MIN and INT32_MAX
            if (distance < -2147483648LL || distance > 2147483647LL)
            {
                std::cout << "[!] Distance out of 32-bit RVA range. Generating a proximity trampoline stub..." << std::endl;

                // Configure strict address boundaries within 4GB downstream from target module base
                MEM_ADDRESS_REQUIREMENTS reqs = {};
                reqs.LowestStartingAddress = reinterpret_cast<PVOID>(baseAbsoluteAddress);
                const ULONG_PTR AllocationGranularity = 0x10000;

                // 2. Define the max 4GB downstream limit from the target DLL base address
                ULONG_PTR rawEndAddress = baseAbsoluteAddress + 0x7FFFFFFF;
                ULONG_PTR alignedEndAddress = (rawEndAddress & ~(AllocationGranularity - 1)) - 1;

                reqs.HighestEndingAddress = reinterpret_cast<PVOID>(alignedEndAddress);
                reqs.Alignment = 0;

                MEM_EXTENDED_PARAMETER param = {};
                param.Type = MemExtendedParameterAddressRequirements;
                param.Pointer = &reqs;

                // Allocate exactly 14 bytes for a 64-bit absolute jump stub
                const SIZE_T stubSize = 14;
                void* trampolineAlloc = VirtualAlloc2(
                    GetCurrentProcess(),
                    nullptr,
                    stubSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE, // Start as RW to safely write payload
                    &param,
                    1
                );

                // 14-byte 64-bit Absolute Jump Instruction Blueprint:
                // jmp [rip + 0]  -> FF 25 00 00 00 00
                // [8-byte Address placeholder]
                BYTE stubBytes[stubSize] = {
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [RIP+0]
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // Placeholder
                };
                // Copy real 64-bit absolute target address into placeholder
                *reinterpret_cast<ULONG_PTR*>(&stubBytes[6]) = hookAbsoluteAddress;
                if (!trampolineAlloc)
               // if(true)
                {
                    static ULONG_PTR g_NextFreeCaveAddress = 0;
                    static DWORD     g_RemainingCaveSize = 0;
                    PrintWin32Error("VirtualAlloc2");
                    std::cout << "[-] Error: Failed to allocate proximity trampoline stub via VirtualAlloc2! Error code: " << GetLastError() << std::endl;
                    std::cout << "[!] Attempting code-cave fallback within existing DLL executable pages..." << std::endl;
                    bool fallbackSuccess = false;
                    if (g_NextFreeCaveAddress != 0 && g_RemainingCaveSize >= stubSize)
                    {
                        trampolineAlloc = reinterpret_cast<void*>(g_NextFreeCaveAddress);

                        DWORD oldSecProtect = 0;
                        if (VirtualProtect(trampolineAlloc, stubSize, PAGE_READWRITE, &oldSecProtect))
                        {
                            RtlCopyMemory(trampolineAlloc, stubBytes, stubSize);
                            DWORD tempProtect = 0;
                            VirtualProtect(trampolineAlloc, stubSize, oldSecProtect | PAGE_EXECUTE_READ, &tempProtect);

                            // Move the pointer forward for the NEXT invocation
                            g_NextFreeCaveAddress += stubSize;
                            g_RemainingCaveSize -= stubSize;
                            fallbackSuccess = true;
                            std::cout << "[+] Reused existing code-cave slot. " << " (" << g_RemainingCaveSize << " bytes left)" <<std::endl;
                        }
                    }

                    // If not initialized yet, or previous cave ran out of space, scan the sections
                    if (!fallbackSuccess)
                    {
                        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
                        WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;

                        for (WORD s = 0; s < numberOfSections; s++)
                        {
                            if (pSectionHeader[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                            {
                                BYTE* sectionStart = baseAddress + pSectionHeader[s].VirtualAddress;
                                DWORD virtualSize = pSectionHeader[s].Misc.VirtualSize;
                                DWORD roundedSize = (virtualSize + 0xFFF) & ~0xFFF; // Align to 4KB page boundary

                                // Start looking immediately after the actual code ends
                                BYTE* potentialCave = sectionStart + virtualSize;
                                ULONG_PTR alignedCave = (reinterpret_cast<ULONG_PTR>(potentialCave) + 7) & ~7;
                                BYTE* targetCave = reinterpret_cast<BYTE*>(alignedCave);
                                BYTE* sectionEndPage = sectionStart + roundedSize;

                                if (targetCave + stubSize <= sectionEndPage)
                                {
                                    // Calculate total available bytes in this padding area
                                    DWORD totalPaddingAvailable = static_cast<DWORD>(sectionEndPage - targetCave);

                                    // Optional: Verify the padding actually contains trailing nulls/CCs 
                                    // to ensure we aren't overwriting valid compiler data/structures
                                    bool isCleanPadding = true;
                                    for (DWORD checkIdx = 0; checkIdx < stubSize; checkIdx++) {
                                        if (targetCave[checkIdx] != 0x00 && targetCave[checkIdx] != 0x90 && targetCave[checkIdx] != 0xCC) {
                                            isCleanPadding = false;
                                            break;
                                        }
                                    }

                                    if (!isCleanPadding) continue;

                                    DWORD oldSecProtect = 0;
                                    if (VirtualProtect(targetCave, stubSize, PAGE_READWRITE, &oldSecProtect))
                                    {
                                        RtlCopyMemory(targetCave, stubBytes, stubSize);
                                        DWORD tempProtect = 0;
                                        VirtualProtect(targetCave, stubSize, oldSecProtect | PAGE_EXECUTE_READ, &tempProtect);

                                        trampolineAlloc = targetCave;
                                        fallbackSuccess = true;

                                        // Set up global tracking data for future invocations
                                        g_NextFreeCaveAddress = reinterpret_cast<ULONG_PTR>(targetCave) + stubSize;
                                        g_RemainingCaveSize = totalPaddingAvailable - stubSize;

                                        std::cout << "[+] Fallback code-cave initialized inside section: "
                                            << pSectionHeader[s].Name << " (" << g_RemainingCaveSize << " bytes left)" << std::endl;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (!fallbackSuccess)
                    {
                        std::cout << "[-] Fallback failed: No usable code-cave found within executable segments." << std::endl;
                        return false;
                    }
                    hookAbsoluteAddress = reinterpret_cast<ULONG_PTR>(trampolineAlloc);
                }

                else 
               {

                // Write payload to allocated trampoline slot
                RtlCopyMemory(trampolineAlloc, stubBytes, stubSize);

                // Elevate memory permissions to Execute/Read-Only for security
                DWORD oldStubProtect = 0;
                VirtualProtect(trampolineAlloc, stubSize, PAGE_EXECUTE_READ, &oldStubProtect);

                // Update hook configuration to reference our new trampoline
                hookAbsoluteAddress = reinterpret_cast<ULONG_PTR>(trampolineAlloc);
                std::cout << "[+] Proximity stub deployed at: 0x" << std::hex << hookAbsoluteAddress << std::dec << std::endl;
                 }
            }

            DWORD targetHookRVA = static_cast<DWORD>(hookAbsoluteAddress - baseAbsoluteAddress);

            // 7. Swap the values safely in the EAT array page
            DWORD oldProtect = 0;
            DWORD* targetAddressSlot = &pAddressOfFunctions[ordinalIndex];

            if (VirtualProtect(targetAddressSlot, sizeof(DWORD), PAGE_READWRITE, &oldProtect))
            {
                *targetAddressSlot = targetHookRVA;
                printf("[+] Patched Export Table RVA: 0x%X\n", targetHookRVA);
                VirtualProtect(targetAddressSlot, sizeof(DWORD), oldProtect, &oldProtect);

                // Refresh execution alignment
                FlushInstructionCache(GetCurrentProcess(), targetAddressSlot, sizeof(DWORD));
                return true;
            }
            break;
        }
    }
    return false;
}


std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}
DWORD GetModuleFileNameWFake(
     HMODULE hModule,
              LPWSTR  lpFilename,
               DWORD   nSize)
{
    DWORD res = GetModuleFileNameW(hModule, lpFilename, nSize);
    std::wcout <<"GetModuleFileNameW " << lpFilename << std::endl;
    return res;
}

void PrintSimpleCallStack() {
    void* stackFrames[64];

    // Capture up to 64 parent call addresses
    // Skip 1 frame (this function itself) to avoid listing it in the trace
    USHORT framesCaptured = CaptureStackBackTrace(1, 64, stackFrames, NULL);

    std::cout << "--- RAW CALL STACK TRACE ---" << std::endl;
    for (USHORT i = 0; i < framesCaptured; i++) {
        std::cout << "Frame [" << i << "]: 0x" << std::hex << stackFrames[i] << "  " << (INT_PTR)stackFrames[i]-globoffs<< std::endl;
    }
}
#if defined(_WIN64)
int checkStackForLoc(CONTEXT* outContext) {
    if (curOffs.mbox_data.size() == 0) return -1;
    //printf("Checking... \n");
    // 1. Capture the current CPU context
    CONTEXT context;
    RtlCaptureContext(&context);

    // 2. Initialize variables needed for stack walking
    DWORD64 imageBase;
    PRUNTIME_FUNCTION runtimeFunction;
    void* handlerData;
    DWORD64 establisherFrame;

    // Skip the first frame (this function itself)
    bool skippedFirst = false;

    // 3. Walk the stack frames using virtual unwinding
    while (true) {
        // Look up function metadata for the current Instruction Pointer (Rip)
        runtimeFunction = RtlLookupFunctionEntry(context.Rip, &imageBase, NULL);

        if (runtimeFunction == NULL) {
            // Leaf function or reached the end of the stack (e.g., kernel boundary)
            // Just simulate a standard return by popping the stack pointer
            context.Rip = *(ULONG_PTR*)(context.Rsp);
            context.Rsp += 8;
        }
        else {
            // Unwind to the parent frame
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip,
                runtimeFunction, &context, &handlerData,
                &establisherFrame, NULL);
        }

        // Exit loop if we hit the bottom of the call stack (Rip becomes 0)
        if (context.Rip == 0) break;
        // 4. Check the return address against your data
        INT_PTR location = (INT_PTR)context.Rip - globoffs;
        //printf("Location: %08llx rip: %08llx\n",location,context.Rip);
        for (int l = 0; l < curOffs.mbox_data.size(); l++) {
            if (location == curOffs.mbox_data[l].mpos) {
                // If a match is found, copy the current frame's context back to the caller
                if (outContext != nullptr) {
                    *outContext = context;
                }
                return l;
            }
        }
    }

    return -1;
}
#endif
#if defined(_WIN32) && !defined(_WIN64)
int checkStackForLoc(CONTEXT* outContext) {
    if (curOffs.mbox_data.size() == 0) return -1;

    // 1. Capture the current CPU context
    CONTEXT context;
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context); // Works natively on x86, x64, and ARM

    // 2. Initialize the STACKFRAME64 structure required for StackWalk64
    STACKFRAME64 stackFrame;
    ZeroMemory(&stackFrame, sizeof(STACKFRAME64));

    // Populate architecture-specific register addresses for x86
    stackFrame.AddrPC.Offset = context.Eip; // Instruction Pointer
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context.Ebp; // Frame Pointer
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context.Esp; // Stack Pointer
    stackFrame.AddrStack.Mode = AddrModeFlat;

    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    // 3. Walk the stack frames
    while (true) {
        // Call StackWalk64 to advance to the parent stack frame
        BOOL result = StackWalk64(
            IMAGE_FILE_MACHINE_I386, // Explicitly target x86 32-bit machine type
            hProcess,
            hThread,
            &stackFrame,
            &context,                // The context record will be updated automatically
            NULL,
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            NULL
        );

        if (!result) {
            // Failed to walk further or reached the root of the call stack
            break;
        }

        // Exit loop if we hit the bottom of the stack (Program Counter becomes 0)
        if (stackFrame.AddrPC.Offset == 0) break;

        // 4. Check the return address against your data
        // Use stackFrame.AddrPC.Offset (equivalent to context.Eip)
        INT_PTR location = (INT_PTR)stackFrame.AddrPC.Offset - globoffs;

        for (int l = 0; l < curOffs.mbox_data.size(); l++) {
            if (location == curOffs.mbox_data[l].mpos) {
                // If a match is found, copy the current frame's context back to the caller
                if (outContext != nullptr) {
                    *outContext = context;
                }
                return l;
            }
        }
    }

    return -1;
}
#endif
/*int checkStackForLocBare() {
    void* stackFrames[64];
    if (curOffs.mbox_data.size() == 0) return -1;
    // Capture up to 64 parent call addresses
    // Skip 1 frame (this function itself) to avoid listing it in the trace
    USHORT framesCaptured = CaptureStackBackTrace(1, 64, stackFrames, NULL);
    for (USHORT i = 0; i < framesCaptured; i++) {
        INT_PTR location = (INT_PTR)stackFrames[i] - globoffs;
        for (int l = 0; l < curOffs.mbox_data.size(); l++)
        {
            if (location == curOffs.mbox_data[l].mpos)
            {
                printf("Loc: %llx", location);
                return l;
            }
               
        }
    }
    return -1;
}*/
#pragma intrinsic(_ReturnAddress)


// Helper function to write a byte buffer to a file
bool WriteBufferToFile(const fs::path& filePath, const BYTE* data, DWORD size) {
    std::ofstream file(filePath, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file.write(reinterpret_cast<const char*>(data), size);
    return true;
}
BYTE unjump[5];
bool InsertJump(void* targetAddress, void* destinationAddress) {
    // A relative jump consists of 1 byte (0xE9) + 4 bytes (32-bit offset)
    const size_t jumpSize = 5;
    DWORD oldProtect;

    // 1. Change memory permissions to Read/Write/Execute
    if (!VirtualProtect(targetAddress, jumpSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // 2. Calculate the 32-bit relative offset
    // Formula: Destination - Target - Size of the jump instruction
    uintptr_t offset = reinterpret_cast<uintptr_t>(destinationAddress) -
        reinterpret_cast<uintptr_t>(targetAddress) - jumpSize;

    // 3. Write the jump opcode (0xE9)
    unjump[0] = *reinterpret_cast<unsigned char*>(targetAddress);
    *reinterpret_cast<unsigned char*>(targetAddress) = 0xE9;

    // 4. Write the 4-byte offset right after the opcode
    *reinterpret_cast<uintptr_t*>(&unjump[1]) = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(targetAddress) + 1);
    *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(targetAddress) + 1) = offset;

    // 5. Restore the original memory permissions
    VirtualProtect(targetAddress, jumpSize, oldProtect, &oldProtect);

    return true;
}
bool Unjump(void* targetAddress)
{
    const size_t jumpSize = 5;
    DWORD oldProtect;

    if (!VirtualProtect(targetAddress, jumpSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return false;
    }
    memcpy(targetAddress, unjump, jumpSize);

    VirtualProtect(targetAddress, jumpSize, oldProtect, &oldProtect);
    return true;
}
typedef void* (__stdcall* vpcall)(void);
bool armed = false;
void* narm = nullptr;
std::map<void*, size_t> allocations;
void* memsetFake(void* dst, int val, size_t sz)
{
    
    return  memset(dst, val, sz);
}
#if defined(_WIN32) && !defined(_WIN64)
int gebp(void) {
    unsigned int ebp_value;
    __asm {
        mov ebp_value, ebp
    }
    return ebp_value;
}

unsigned int geax(void) {
    unsigned int eax_value;
    __asm {
        mov eax_value, eax
    }
    return eax_value;
}
#endif

bool PatchWithMovAxRet(INT_PTR offsetAddr, const std::vector<BYTE>& patch, std::vector<BYTE>& unpatch) {

    BYTE* targetAddress = reinterpret_cast<BYTE*>(offsetAddr + globoffs); //curoffs.spatch
    DWORD oldProtect;

    // Raw instruction bytes: 
    // 66 B8 01 00 = mov ax, 0x1
    // C3          = ret

    size_t patchSize = patch.size();
    unpatch.resize(patchSize);
    printf("Target address: %p size %d\n", targetAddress, (int)patchSize);
      // 2. Modify memory page rights to read/write/execute
    if (VirtualProtect(targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // 3. Apply the 5-byte instruction override sequence
        memcpy(unpatch.data(), targetAddress, patchSize);
        memcpy(targetAddress, patch.data(), patchSize);

        // 4. Restore original system memory protection states
        VirtualProtect(targetAddress, patchSize, oldProtect, &oldProtect);

        // 5. Clear CPU pipeline cache to prevent execution misalignment
        FlushInstructionCache(GetCurrentProcess(), targetAddress, patchSize);
        printf("%p\n", targetAddress);
        std::cout << "[+] Successfully patched addr with " << patchSize << " bytes " << hexStr((uint8_t*)&unpatch[0], patchSize) << " patch "<< hexStr((uint8_t*)&patch[0], patchSize) << std::endl;// with mov ax, 1; ret
        return true;
    }

    std::cout << "[-] VirtualProtect failed. Error code: " << GetLastError() << std::endl;
    return false;
}


bool UnpatchWithMovAxRet(INT_PTR offsetAddr, const std::vector<BYTE>& unpatch) {
    // 1. Identify target address location
    BYTE* targetAddress = reinterpret_cast<BYTE*>(offsetAddr + globoffs);
    DWORD oldProtect;
    size_t patchSize = unpatch.size();

    // 2. Modify memory page rights to read/write/execute
   // printf("Target address: %p size %d\n", targetAddress,(int)patchSize);
    if (VirtualProtect(targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // 3. Apply the 5-byte instruction override sequence

        memcpy(targetAddress, unpatch.data(), patchSize);

        // 4. Restore original system memory protection states
        VirtualProtect(targetAddress, patchSize, oldProtect, &oldProtect);

        // 5. Clear CPU pipeline cache to prevent execution misalignment
        FlushInstructionCache(GetCurrentProcess(), targetAddress, patchSize);
        printf("%p\n", targetAddress);

        std::cout << "[+] Successfully unpatched addr with " << patchSize << " bytes " << hexStr((uint8_t*)&unpatch[0], patchSize) << std::endl;// with mov ax, 1; ret

        return true;
    }

    std::cout << "[-] VirtualProtect failed. Error code: " << GetLastError() << std::endl;
    return false;
}
bool patchAMove()
{

    for (auto& a : curOffs.spatches)
    {
        if (!PatchWithMovAxRet(a.spatch, a.patch, a.unpatch)) return false;
    }
    printf("PDone\n");
    return true;

}
bool unpatchAMove()
{
    for (auto& a : curOffs.spatches)
    {
        if (!UnpatchWithMovAxRet(a.spatch, a.unpatch)) return false;
    }
    return true;
}

struct KeyData
{
    std::set<std::string> keys_128;
    std::set<std::string> keys_256;
    std::set<std::string> old_secrets;
    void reset()
    {
        keys_128.clear();
        keys_256.clear();
        old_secrets.clear();
    }
    void aggregate(KeyData* other)
    {
        if (other == nullptr) return;
        keys_128.insert(other->keys_128.begin(), other->keys_128.end());
        keys_256.insert(other->keys_256.begin(), other->keys_256.end());
        old_secrets.insert(other->old_secrets.begin(), other->old_secrets.end());
    }
};

std::vector<std::string> sn;
const int keysetIndex = 38;
const int secretKeyIndex = 44;
const int idIndex = 34;
const int algorithmIndex = 28;
const int formatIndex = 33;
const int encodedIndex = 29;
uint8_t* seccan = nullptr;
KeyData keydataAccumulator;

std::vector<uint8_t> buf2key(uint8_t* bfr, const std::vector<std::vector<uint8_t>>& subst)
{
    std::vector<uint8_t> repl(bfr + 0x2c * 4 - 16, bfr + 0x2c * 4);
    for (int i = 0; i < repl.size(); i++)
    {
        int offs = i % 16;
        repl[i] = subst[offs][repl[i]];
    }
    for (int i = 0; i < 4; i++)
    {
        uint8_t w0 = repl[i * 4 + 3];
        uint8_t w1 = repl[i * 4 + 2];
        uint8_t w2 = repl[i * 4 + 1];
        uint8_t w3 = repl[i * 4 + 0];
        repl[i * 4 + 0] = w0;
        repl[i * 4 + 1] = w1;
        repl[i * 4 + 2] = w2;
        repl[i * 4 + 3] = w3;

    }
    return repl;
}
std::vector<uint8_t> key2key(uint8_t* bfr, const std::vector<std::vector<uint8_t>>& subst)
{
    std::vector<uint8_t> repl(bfr, bfr + 16);
    for (int i = 0; i < repl.size(); i++)
    {
        int offs = i % 16;
        repl[i] = subst[offs][repl[i]];
    }
    for (int i = 0; i < 4; i++)
    {
        uint8_t w0 = repl[i * 4 + 3];
        uint8_t w1 = repl[i * 4 + 2];
        uint8_t w2 = repl[i * 4 + 1];
        uint8_t w3 = repl[i * 4 + 0];
        repl[i * 4 + 0] = w0;
        repl[i * 4 + 1] = w1;
        repl[i * 4 + 2] = w2;
        repl[i * 4 + 3] = w3;

    }
    return repl;
}

bool patchA(ppatch& p)
{

    if (!PatchWithMovAxRet(p.spatch, p.patch, p.unpatch)) return false;
    printf("PDone\n");
    return true;

}
bool unpatchA(ppatch& p)
{
    if (!UnpatchWithMovAxRet(p.spatch, p.unpatch)) return false;
    return true;
}

ppatch mbox_patch(0, std::vector<uint8_t>());
int mbox_offs = -1;


std::vector<uint8_t> barek;

bool patched = false;



void* mallocFake(size_t s)
{
    CONTEXT context;
    RtlCaptureContext(&context);

#ifdef _WIN64
    INT_PTR ledi = grsi();
#endif
#if  defined(_WIN32) && !defined(_WIN64)
    INT_PTR ledi = gedi();
#endif
    void* ret = malloc(s);
    if (armed)
    {
        //printf("Allocated %d at %p\n", s, ret);
        allocations[ret] = s;
        if (narm != nullptr)
        {
      
            if (!mbox_saved)
            {
                size_t sz = curOffs.mbox_size;
                if(mbox_bare) sz= curOffs.mbox_size_bare;
                mboxsave.resize(sz);
                memcpy(&mboxsave[0], (void*)((INT_PTR)narm+curOffs.allemaric_shift), sz);
                if (*(int*)&mboxsave[0] != 0)
                mbox_saved = true;
               // uint8_t* offmast = (uint8_t*)(globoffs + 0x13a62c30);
               // std::cout << "Hexsubst " << hexStr(offmast, 256 * 16) << std::endl;
               // exit(1);
            }
          // std::cout << hexStr((uint8_t*)narm, curOffs.mbox_size) << std::endl;
           if(*(int*)&mboxsave[0]!=0)
            narm = nullptr;
         
        }
        /*
        *    ppatch ptch(0,std::vector<uint8_t>());
            PatchX86Jump((void*)(globoffs + 0x101ad950), &adi,&ptch);
        */
        if (s == curOffs.mbox_size)
        {
            narm = ret;
            mbox_bare = false;
        }
        else
        {
            if (s == curOffs.mbox_size_bare&&!mbox_saved)
            {
              //  int edi=gedi();
                printf("EDI: %08llx \n",ledi);
                barek.resize(66 * 2);
                memcpy(&barek[0], (void*)ledi, barek.size());
                narm = nullptr;
                mbox_bare = true;
                printf("Bare mbox\n");
               // std::cout << "Barek " << hexStr(&barek[0], barek.size()) << std::endl;
               // PrintSimpleCallStack();
                mboxsave.resize(curOffs.mbox_size_bare);
                mbox_saved = true;

            }
        }
        if (s >= curOffs.mbox_size / 2&&!mbox_keyed) //grace
        {

           // PrintSimpleCallStack();
            //int maxmbox[256];
            CONTEXT ctx;
            int mbo = checkStackForLoc(&ctx);;
            //int 
            if (mbo >= 0)
            {

              //  PrintTrueStackLayout();
#if defined(_WIN32) &&!defined(_WIN64)
               printf("In-box %d EDI: %08x %08x\n", mbo,ctx.Edi,ledi);
#endif
#if defined (_WIN64)
               printf("In-box %d\n", mbo);
#endif
                INT_PTR par_addr = curOffs.mbox_data[mbo].get_param(&ctx); //due to register nature, order is important? ugh~~
             //  printf("Param: %08llx\n", par_addr);
                mbox_offs = mbo;
                std::vector<uint8_t> temp_mbox(0x1d1ac+200);
                std::vector<uint8_t> temp_par(0x42 * 2);
               
                memcpy(&temp_par[0], (void*)par_addr, temp_par.size());
               // std::cout << "Bparam " << hexStr(&temp_par[0], temp_par.size()) << std::endl;
                if(curOffs.mbox_data[mbo].mbox_precreate==0)
                {
                typedef void(__cdecl* mbi)(void* bk, unsigned char* out);
                mbi makemb = (mbi)(globoffs + curOffs.mbox_data[mbo].mbox_create);
                makemb(&temp_par[0], &temp_mbox[0]);
                }
                else
                {
                    typedef void(__cdecl* mbk)(void* bk, unsigned char* out);
                    typedef void(__cdecl* mbin)(void* bk,int num, unsigned char* out);
                    unsigned char pre[100];
                    mbk makek = (mbk)(globoffs + curOffs.mbox_data[mbo].mbox_precreate);
                    mbin makemb = (mbin)(globoffs + curOffs.mbox_data[mbo].mbox_create);
                    makek(&temp_par[0], pre);

                    makemb(pre,16, &temp_mbox[0]);
                }

                std::vector<uint8_t> key(16, 0);
                for (int i = 0; i < 16; i++)
                {
                    key[i] = temp_mbox[curOffs.mbox_data[mbo].slt_offs + i * 256] ^ curOffs.mbox_data[mbo].slut;
                }
                std::string  hkey = hexStr(&key[0], key.size());
                keydataAccumulator.keys_128.insert(hkey);
                std::cout << "Got key: " << hkey << std::endl;
                mbox_keyed = true;

            }
        }
    }
   
    return ret;
}






bool tryAssignKey(BinaryIonParser* drmkey)
{
    drmkey->stepin();
    if (drmkey->readerr) return  false;
    std::string key;
    std::string keyid;
    std::string algo;
    std::string form;
    while (drmkey->hasnext())
    {
        //std::cout << "Next" << std::endl;
        if (drmkey->readerr) return false;
        drmkey->next();
        //std::cout << drmkey->getAnnotType() << std::endl;
        if (drmkey->getAnnotType() != secretKeyIndex)
            continue;
        // std::cout << "Found index" << std::endl;
        drmkey->stepin();
        if (drmkey->readerr) return false;
        while (drmkey->hasnext())
        {
            drmkey->next();
            if (drmkey->readerr) return false;
            switch (drmkey->valuefieldid)
            {
            case idIndex: { keyid = drmkey->stringvalue(); }; break;
            case algorithmIndex: {
                algo = drmkey->stringvalue();
                if (algo != "AES")
                {
                    std::cout << "Found key with unknown algo: " << algo << std::endl;
                    return  false;
                }
            }; break;
            case formatIndex: {
                form = drmkey->stringvalue();
                if (form != "RAW")
                {
                    std::cout << "Found key with unknown format: " << form << std::endl;
                    return false;
                }
            }; break;
            case encodedIndex: {
                std::vector<uint8_t> ekey = drmkey->lobvalue();
                key = hexStr(&ekey[0], ekey.size());
            }; break;
            default:break;
            }

        }
        // drmkey->stepout(); -should not be needed
        break;
    }
    if (keyid != "" && !key.empty())
    {
        std::cout << keyid << "$secret_key:" << key << std::endl;
        if (key.size() == 32)
        {
            keydataAccumulator.keys_128.insert(key);
        }
        if (key.size() == 64)
        {
            keydataAccumulator.keys_256.insert(key);
        }
        return true;
    }
    return false;
}

bool afb = false;
void freeFake(void* p)
{
  
    if (armed && p != nullptr)
    {
        size_t fsize = allocations[p];
        if (seccan != nullptr)
        {
            //std::cout <<"Seccan " << hexStr((uint8_t*)seccan, allocations[seccan]) << "  "<<allhex(seccan,40)<<std::endl;
            if (allhex(seccan, 40))
            {
                std::string cand = std::string((char*)seccan, 40);
                if (keydataAccumulator.old_secrets.find(cand) == keydataAccumulator.old_secrets.end())
                {
                    std::cout << "Secret candidate: " << cand << std::endl;
                    keydataAccumulator.old_secrets.insert(cand);
                   // PrintSimpleCallStack();
                }

            }
        }
        if (afb)
        {
            for (const auto& a : allocations)
            {
                size_t sz = a.second;
                uint8_t* ptr = (uint8_t*)a.first;
                if (sz <= 64 && sz >= 41)
                {
                    if (allhex(ptr, 40)&&ptr[40]==0)
                    {
                        std::string cand = std::string((char*)ptr, 40);
                        if (keydataAccumulator.old_secrets.find(cand) == keydataAccumulator.old_secrets.end())
                        {
                            std::cout << "Secret candidate: " << cand << std::endl;
                            keydataAccumulator.old_secrets.insert(cand);
                           // PrintSimpleCallStack();
                        }
                    }
                }
            }
        }
        if (fsize > 0)
        {
           // printf("Freeing %d at %p\n", fsize,p);
           // std::cout << hexStr((uint8_t*)p, fsize) << std::endl;
            //PrintSimpleCallStack();
            //std::cout << "--------------" << std::endl;
        }
        if (p == seccan) seccan = nullptr;
        if (fsize >= 39)
        {
            uint8_t* pp = (uint8_t*)p;
            for (int poffs = 0; poffs < 30; poffs++)
            {
                BinaryIonParser bp(&pp[poffs], fsize - poffs, TID_TYPEDECL);
                if (bp.hasnext())
                {
                    int nxt = bp.next();
                    if (nxt == TID_LIST)
                    {
                        if (bp.annotations.size() > 0 && bp.annotations[0] == keysetIndex)
                        {
                            //valuefieldid
                            //std::cout << "Correct: " << hexStr((uint8_t*)&pp[16], 16) << std::endl;
                            if(tryAssignKey(&bp))
                            break;
                            // while (true) {}
                        }

                    }

                }
            }
            
           
        }
        allocations.erase(p);
    }
   free(p);
}

void* memcpyFake(void* dst, void* src,size_t sz)
{
    if (armed)
    {
        //std::cout << "Caught memcpy of " << sz << "("<<allocations[src]<<") bytes, from " << src << " to " << dst <<"("<<allocations[dst]<<")"<< std::endl;
        if (allhex((uint8_t*)src, sz)&&sz>10)
        {
           // std::cout << "Allhex!" << std::endl;
            if (sz == 31 && allocations[dst] == 48)
            {

               // std::cout << hexStr((uint8_t*)dst, 48) << std::endl;
                seccan =(uint8_t*) dst;
               // PrintSimpleCallStack();
            }
        }
     //   std::cout << hexStr((uint8_t*)src, sz) << std::endl;
    }
  
    void * ret = memcpy(dst, src, sz);
    return ret;
}

BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWFake(LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision,
    PSECURITY_DESCRIPTOR* SecurityDescriptor,
    PULONG               SecurityDescriptorSize)
{
   std::wcout << "ConvertStringSecurityDescriptorToSecurityDescriptorWFake " << StringSecurityDescriptor << " revision " << StringSDRevision << std::endl;
   return  ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize);
}
//std::vector<BYTE> unpatchBytes;

// Helper function to fetch raw property bytes from CNG
bool GetKeyProperty(NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, std::vector<BYTE>& buffer) {
    DWORD cbResult = 0;
    // Query required buffer size first
    SECURITY_STATUS status = NCryptGetProperty(hKey, pszProperty, nullptr, 0, &cbResult, 0);
    if (status != ERROR_SUCCESS || cbResult == 0) {
        return false;
    }

    buffer.resize(cbResult);
    // Fetch actual data into the buffer
    status = NCryptGetProperty(hKey, pszProperty, buffer.data(), cbResult, &cbResult, 0);
    return (status == ERROR_SUCCESS);
}

void ReadKeySddl(NCRYPT_KEY_HANDLE hKey) {
    DWORD cbSecurityDesc = 0;

    // 1. Determine buffer size for the binary security descriptor
    SECURITY_INFORMATION secInfo = DACL_SECURITY_INFORMATION;
    if (NCryptGetProperty(hKey, NCRYPT_SECURITY_DESCR_PROPERTY, NULL, 0, &cbSecurityDesc, secInfo) == ERROR_SUCCESS) {

        PSECURITY_DESCRIPTOR pSecDesc = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, cbSecurityDesc);

        // 2. Fetch the actual binary security descriptor
        if (NCryptGetProperty(hKey, NCRYPT_SECURITY_DESCR_PROPERTY, (PBYTE)pSecDesc, cbSecurityDesc, &cbSecurityDesc, secInfo) == ERROR_SUCCESS) {
            LPWSTR pszSddl = nullptr;

            // 3. Convert the binary structure to a readable SDDL string
            if (pSecDesc!=0&&ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecDesc, SDDL_REVISION_1, secInfo, &pszSddl, NULL)) {
                std::wcout << L"Key Permissions (SDDL): " << pszSddl << std::endl;
                LocalFree(pszSddl);
            }
        }
        LocalFree(pSecDesc);
    }
}
// Main function to print common NCrypt key properties
void PrintNCryptKeyProperties(NCRYPT_KEY_HANDLE hKey) {
    std::wcout << L"--- NCrypt Key Properties ---" << std::endl;
    std::vector<BYTE> buffer;

    // 1. Print Key Name (String)
    if (GetKeyProperty(hKey, NCRYPT_NAME_PROPERTY, buffer)) {
        std::wcout << L"Key Name: " << reinterpret_cast<LPCWSTR>(buffer.data()) << std::endl;
    }
    else {
        std::wcout << L"Key Name: [Not Available or Ephemeral]" << std::endl;
    }

    // 2. Print Algorithm Name (String)
    if (GetKeyProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, buffer)) {
        std::wcout << L"Algorithm: " << reinterpret_cast<LPCWSTR>(buffer.data()) << std::endl;
    }

    // 3. Print Key Length (DWORD)
    if (GetKeyProperty(hKey, NCRYPT_LENGTH_PROPERTY, buffer) && buffer.size() >= sizeof(DWORD)) {
        DWORD length = *reinterpret_cast<DWORD*>(buffer.data());
        std::wcout << L"Key Length: " << length << L" bits" << std::endl;
    }

    // 4. Print Key Usage Flags (DWORD bitmask)
    if (GetKeyProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, buffer) && buffer.size() >= sizeof(DWORD)) {
        DWORD usage = *reinterpret_cast<DWORD*>(buffer.data());
        std::wcout << L"Key Usage: ";
        if (usage == NCRYPT_ALLOW_ALL_USAGES) {
            std::wcout << L"All Usages";
        }
        else {
            std::wstring usages;
            if (usage & NCRYPT_ALLOW_DECRYPT_FLAG) usages += L"Decrypt ";
            if (usage & NCRYPT_ALLOW_SIGNING_FLAG) usages += L"Sign ";
            if (usage & NCRYPT_ALLOW_KEY_AGREEMENT_FLAG) usages += L"KeyAgreement ";
            std::wcout << (usages.empty() ? L"None" : usages);
        }
        std::wcout << L" (Raw: 0x" << std::hex << usage << std::dec << L")" << std::endl;
    }

    // 5. Print Export Policy Flags (DWORD bitmask)
    if (GetKeyProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, buffer) && buffer.size() >= sizeof(DWORD)) {
        DWORD policy = *reinterpret_cast<DWORD*>(buffer.data());
        std::wcout << L"Export Policy: ";
        std::wstring policies;
        if (policy & NCRYPT_ALLOW_EXPORT_FLAG) policies += L"AllowExport ";
        if (policy & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) policies += L"AllowPlaintextExport ";
        if (policy & NCRYPT_ALLOW_ARCHIVING_FLAG) policies += L"AllowArchiving ";
        if (policy & NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG) policies += L"AllowPlaintextArchiving ";
        std::wcout << (policies.empty() ? L"Export prohibited" : policies);
        std::wcout << L" (Raw: 0x" << std::hex << policy << std::dec << L")" << std::endl;
    }

    // 6. Check UI Policy Presence (Structure)
    if (GetKeyProperty(hKey, NCRYPT_UI_POLICY_PROPERTY, buffer)) {
        std::wcout << L"UI Policy: Configured" << std::endl;
    }
    else {
        std::wcout << L"UI Policy: None" << std::endl;
    }
    
    ReadKeySddl(hKey);
   
    std::wcout << L"-----------------------------" << std::endl;
}

SECURITY_STATUS NCryptOpenKeyFake(
    NCRYPT_PROV_HANDLE hProvider,
     NCRYPT_KEY_HANDLE* phKey,
    LPCWSTR            pszKeyName,
    DWORD              dwLegacyKeySpec,
      DWORD              dwFlags)
{
    std::wcout << "NCryptOpenKeyFake " << pszKeyName << std::endl;
    SECURITY_STATUS ret= NCryptOpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags);
   // std::wcout << "NCryptOpenKeyFake result: " << ret << std::endl;
   // SetKeySecurity(*phKey);
  //  PrintNCryptKeyProperties(*phKey);

    return ret;
}


SECURITY_STATUS NCryptDecryptFake(NCRYPT_KEY_HANDLE hKey,PBYTE pbInput,
         DWORD cbInput,VOID* pPaddingInfo,
        PBYTE pbOutput, DWORD cbOutput,
            DWORD* pcbResult, DWORD dwFlags)
{
   // printf("Decr key: %p cbinput %d\n", hKey, cbInput);
    //std::cout << "input " << hexStr(pbInput, cbInput) << std::endl;
    SECURITY_STATUS ret = NCryptDecrypt(hKey, pbInput,cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
       // std::wcout << "NCryptDecryptFake result: " << ret << " cboutput "<< cbOutput << std::endl;
        if (ret == 0&& cbOutput>0)
        {
            std::cout <<"Decrypted data (Probably TPM-backed secret) " << hexStr(pbOutput, cbOutput) << std::endl;
        }
    return ret;
}
SECURITY_STATUS NCryptSetPropertyFake(
   NCRYPT_HANDLE hObject,
    LPCWSTR       pszProperty,
     PBYTE         pbInput,
     DWORD         cbInput,
     DWORD         dwFlags
)
{
    std::wcout << "NCryptSetPropertyFake " << pszProperty<< std::endl;
    SECURITY_STATUS ret = NCryptSetProperty(hObject, pszProperty, pbInput, cbInput, dwFlags);
    std::cout << "result " << ret << std::endl;
    return ret;
}

SECURITY_STATUS NCryptCreatePersistedKeyFake(
               NCRYPT_PROV_HANDLE hProvider,
             NCRYPT_KEY_HANDLE* phKey,
              LPCWSTR            pszAlgId,
     LPCWSTR            pszKeyName,
              DWORD              dwLegacyKeySpec,
             DWORD              dwFlags
)
{
    std::wcout << "Alg " << pszAlgId << " name " << pszKeyName<<std::endl;
    SECURITY_STATUS ret = NCryptCreatePersistedKey(hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
    std::wcout << "NCryptCreatePersistedKeyFake result: " << ret << std::endl;
    return ret;
}
SECURITY_STATUS NCryptEncryptFake(
          NCRYPT_KEY_HANDLE hKey,
            PBYTE             pbInput,
             DWORD             cbInput,
     VOID* pPaddingInfo,
            PBYTE             pbOutput,
             DWORD             cbOutput,
             DWORD* pcbResult,
            DWORD             dwFlags
)
{
    printf("Enc key: %p cbinput %ul\n", (void*) hKey, cbInput);
    std::cout << "input " << hexStr(pbInput, cbInput) << std::endl;
    SECURITY_STATUS ret=NCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
    std::wcout << "NCryptEncryptFake result: " << ret << std::endl;
    return ret;
}
std::string GetOwnSid() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_USER pTokenUser = NULL;
    LPSTR szSid = NULL;
    std::string result = "";

    // 1. Open the access token associated with the current process
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return "Error: OpenProcessToken failed (" + std::to_string(GetLastError()) + ")";
    }

    // 2. Get the required buffer size for token information
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return "Error: GetTokenInformation size check failed (" + std::to_string(GetLastError()) + ")";
    }

    // 3. Allocate memory for the token information structure
    pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return "Error: HeapAlloc failed";
    }

    // 4. Retrieve the token information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        std::string err = "Error: GetTokenInformation failed (" + std::to_string(GetLastError()) + ")";
        HeapFree(GetProcessHeap(), 0, pTokenUser);
        CloseHandle(hToken);
        return err;
    }

    // 5. Convert the binary SID structure into a human-readable string format (S-1-5-...)
    if (ConvertSidToStringSidA(pTokenUser->User.Sid, &szSid)) {
        result = szSid;
        LocalFree(szSid); // Free memory allocated by ConvertSidToStringSidA
    }
    else {
        result = "Error: ConvertSidToStringSidA failed (" + std::to_string(GetLastError()) + ")";
    }

    // Clean up resources
    HeapFree(GetProcessHeap(), 0, pTokenUser);
    CloseHandle(hToken);

    return result;
}




typedef void* (__cdecl* toQString)(void* qstring, const std::string& input);
typedef void* (__thiscall* fromQString)(void* qstring, std::string& output);
typedef void* (__thiscall* getme)(void* map, void* qstring, void* output);
typedef void* (__thiscall* putme)(void* map, void* qstring, void* input);
typedef void* (__thiscall* unobfhash)(void* map, void* qhash);
typedef void* (__thiscall* fakeQLatin1)(void* str, void* qbtarray);
typedef void* (__thiscall* fakeQbyte)(void* qbtarray, void* other);
//void* __thiscall HookedFunction(void* v) {
fromQString fromQ;
fakeQLatin1 correctLatin1;
fakeQbyte correctQbyte;
struct QArrayData {
    int ref_count;
    int size;
    unsigned int alloc;
    INT_PTR offset; // Distance in bytes from this struct to the wchar_t array
};
struct QBArray {
    QArrayData* d;
};
class HookHandlerLatin1 {
public:
    // Explicit __thiscall hook function
    // The 'this' pointer is implicitly passed as the hidden first argument
    void* __thiscall HookedFunction(void* v) {
        std::cout << "Hooked Latin1, string " << this <<std::endl;
        std::string fq;
        //fromQ(this, fq);
       // std::cout << fq << std::endl;
         void *ret=correctLatin1((void*)this, v);
         QBArray* arr = (QBArray*)v;
         std::cout << arr->d->alloc<<std::endl;
         std::cout << hexStr((uint8_t*)((INT_PTR)arr->d+arr->d->offset), arr->d->size) << std::endl;
         std::string st((char*)((INT_PTR)arr->d + arr->d->offset), arr->d->size);
         std::cout << st << std::endl;
       //  PrintSimpleCallStack();
         return ret;
    }
    void* __thiscall HookedQByte(void* qb) {
        std::cout << "Hooked Qb1, string " << this << std::endl;
        void* ret = correctQbyte(this, qb);
        QBArray* arr = (QBArray*)ret;
        std::cout << "Hookv alloc " << arr->d->alloc <<" len " << arr->d->size << std::endl;
        std::cout << hexStr((uint8_t*)((INT_PTR)arr->d + arr->d->offset), arr->d->size) << std::endl;
        std::string st((char*)((INT_PTR)arr->d + arr->d->offset), arr->d->size);
        std::cout << st << std::endl;
        return ret;

    }
};

struct CustomString {
    int current_offset;         // offset +0
    int length;                 // offset +4
    uintptr_t* control_block;   // offset +8 -> points to buffer metadata
};
void PrintResultingString(void* thisPtr) {
    if (!thisPtr) return;

    // 1. Cast the raw 'this' pointer to our structured layout
    CustomString* strObj = reinterpret_cast<CustomString*>(thisPtr);
    //std::wcout << "Lengthb " << strObj->length << std::endl;
    //std::wcout << "Curoffs " << strObj->current_offset << std::endl;
   // std::wcout << L"Intercepted String: " << (wchar_t*)strObj->control_block << std::endl;
    // 2. Replicate the address lookup logic from the decompiled code
    int iVar4 = 0;
    if (strObj->control_block != nullptr) {
        // iVar4 = *(int *)(*(int *)((int)this + 8) + 8) + *this * 2;
        INT_PTR base_heap_ptr = strObj->control_block[2];
        iVar4 = ((int)base_heap_ptr + (int)(strObj->current_offset * 2));
       // printf("Ivar4 %x\n", iVar4);
    }
    // *(int *)((int)this->nxt + 8) + this->field0_0x0 * 2;
    // iVar2 is the string length offset before addition
    uintptr_t iVar2 = strObj->length;

    // 3. This is the exact destination formula used in the memcpy: (iVar4 + iVar2 * 2)
    wchar_t* rawWideString = reinterpret_cast<wchar_t*>(iVar4 );
   // std::cout << hexStr((uint8_t*)rawWideString, strObj->length * 2) << std::endl;
    wchar_t buffer[256];
    memset(buffer,0, sizeof(buffer));
    if (rawWideString!=nullptr)
      memcpy(buffer, rawWideString, strObj->length * 2);
    // 4. Print the wide string to the console
    if (rawWideString) {
        // Set console output mode to UTF-16 to display Unicode properly if needed
      //  _setmode(_fileno(stdout), _O_U16TEXT);

        std::wcout << L"Intercepted String: " << buffer << std::endl;
    }

    
}
class HookHandler {
public:
    // Explicit __thiscall hook function
    // The 'this' pointer is implicitly passed as the hidden first argument
    void __thiscall HookedFunction(CustomString*v ) {
        // 'this' points to the original object that called the function
       // std::cout << "Original object pointer (ECX): " << this << std::endl;
       // std::cout << "String: " << v << std::endl;
        void* qstr = (void*)this;
        std::wstring *gv=(std::wstring*)this;
        //fromQ(qstr, gv);
       // PrintResultingString((void*)this);
        CustomString* cs = (CustomString*)this;
        *cs = *v;
        PrintResultingString((void*)this);
        //std::cout << "Arguments received: " << firstParam << ", " << secondParam << std::endl;
    }
};

int getqlen(void* qstr)
{
  //  int* qcont = *(int**)qstr;
    QBArray* cont = (QBArray*)qstr;
    return cont->d->size;
}
struct QHashData {
    struct Node {
        Node* next;        // Pointer to the next node colliding in this index chain
        unsigned int h;    // The precalculated, salted 32-bit hash value of the key
    };

    Node* fakeNext;        // Hardcoded safety terminator (0x00000000)
    Node** buckets;        // Array of pointer entries targeting bucket heads
    int ref_count;         // Tracks shared instances via assignments (Snippet 2 mechanics)
    int size;              // Number of active key-value elements currently inside the map
    int nodeSize;          // Combined size footprint of the key + value + node header
    short userNumBits;     // Requested configuration allocation bounds
    short numBits;         // Log base 2 of the bucket count allocation bounds
    int numBuckets;        // Active size length of the buckets allocation array pointer
    unsigned int seed;     // Runtime salt randomized to mitigate algorithmic collision exploits
};
// 1. Qt 5 Memory Block String Layout

struct QString_Qt5 {
    QArrayData* d;

    // Helper method to safely pull string out of raw Qt memory
    const wchar_t* GetText() const {
        if (!d || d->size == 0) return L"";
        std::cout << "String " << d->ref_count << "  " << d->size << " " << d->alloc << std::endl;
        // Pointer arithmetic used across your string snippets: Header + Offset
        return reinterpret_cast<const wchar_t*>(reinterpret_cast<char*>(d) + d->offset);
    }
};

struct QHashNode_QString_QString {
    QHashData::Node* next;   // Offset +0
    unsigned int h;        // Offset +4
    QString_Qt5 key;       // Offset +8
    QString_Qt5 value;     // Offset +12
};
std::map<std::string,std::string> QHashToMD5Map(QHashData* hashData) 
   {
    std::map<std::string, std::string> ret;
    if (!hashData)
    {
        return ret;
    }
    if (hashData->size == 0 || !hashData->buckets) 
    {
        return ret;
    }

    int discoveredCount = 0;

    // 2. Iterate sequentially through the Bucket pointer array
    for (int i = 0; i < hashData->numBuckets; ++i) 
    {
        QHashData::Node* currentNode = hashData->buckets[i];
        //printf("Current node: %p \n", currentNode);
       // printf("Current node n: %p \n", currentNode->next);
        while (currentNode != nullptr) 
        {
            // Cast the generic DataNode to our specific QString-pair Node layout
            QHashNode_QString_QString* dataNode = reinterpret_cast<QHashNode_QString_QString*>(currentNode);
            if (currentNode->next != nullptr)
            {
                QBArray* arr = (QBArray*)&dataNode->key;
                std::string md5 = hexStr((uint8_t*)((INT_PTR)arr->d + arr->d->offset), arr->d->size);

                arr = (QBArray*)&dataNode->value;
                std::string st((char*)((INT_PTR)arr->d + arr->d->offset), arr->d->size);
                std::cout << "Md5: " << md5 << " Value: " << st << std::endl;
                ret[md5] = st;
                discoveredCount++;
            }
            currentNode = currentNode->next;
        }
    }
    return ret;
}


using nlohmann::json;
std::string ParseDecryptedTextBlob(DATA_BLOB& decryptedBlob) 
{
    std::string DSN="";
    // Safety check for null pointers or empty buffer returns
    if (decryptedBlob.pbData == nullptr || decryptedBlob.cbData == 0) 
    {
        std::cerr << "Invalid or empty decryption blob." << std::endl;
        return DSN;
    }

    try {
        // Pass the raw byte pointer and size boundary directly
        // Cast BYTE* to const char* for the json engine parser
        const char* rawJsonStr = reinterpret_cast<const char*>(decryptedBlob.pbData);

        json data = json::parse(rawJsonStr, rawJsonStr + decryptedBlob.cbData);

        // Access properties safely
        std::cout << "JSON successfully parsed!" << std::endl;
        if (data.contains("dsn")) 
        {
            DSN = data["dsn"];
            std::cout << "DSN: " << data["dsn"] << std::endl;
        }

    }
    catch (const json::parse_error& e) 
    {
        std::cerr << "Malformed text inside decrypted payload: " << e.what() << std::endl;
    }
    return DSN;
}
typedef void* (__thiscall* makeaccsec)(void* as, void* k_11, const std::string& tname);
typedef int(__thiscall* getint)(void* as);
typedef void(__thiscall* getbyIndex)(void* as, int index, void*);
typedef void* (__thiscall* KRFError)(void*);
typedef void* (__cdecl* getBookFactory)();
typedef void(__thiscall* openBook)(void* factory, void* bk, const std::string& name, const void* drmprovider, void* error, const std::list<std::string>& mayberes);
typedef void* (__thiscall* drmDataProv)(void*, const std::string& dsn, const std::list<std::string>& secrets, const std::list<std::string>& vouchers);
typedef void* (__thiscall* getPluginManager)();
typedef void(__thiscall* loadAllStaticModules)(void*);

struct KrfAccessFunctions
{
    getPluginManager GetPluginManager = nullptr;
    loadAllStaticModules LoadAllStaticModules = nullptr;
    drmDataProv DrmDataProvider = nullptr;
    getBookFactory GetBookFactory = nullptr;
    openBook OpenBook = nullptr;
};

KrfAccessFunctions globalKRFContext;

struct krfErr
{
    int code = -1;
    std::string msg;
    char padding[28] = { 0 };
};


std::wstring GetExternalInstallPath(const wchar_t* packageFullName)
{
    UINT32 length = 0;

    // First call determines the required buffer size
    LONG rc = GetPackagePathByFullName(packageFullName, &length, nullptr);
    if (rc == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<wchar_t> path(length);
        rc = GetPackagePathByFullName(packageFullName, &length, path.data());

        if (rc == ERROR_SUCCESS) {
            std::wcout << L"Install Path: " << path.data() << std::endl;
            return std::wstring(path.data());
        }
    }
    std::cout << "Failed to find package path. Error code: " << rc << std::endl;
    return L"";
}

std::wstring GetFamilyNameFromFullName(const std::wstring& packageFullName) {
    UINT32 length = 0;

    // Pass 1: Determine the required size of the buffer (including null terminator)
    LONG rc = PackageFamilyNameFromFullName(packageFullName.c_str(), &length, nullptr);

    if (rc == ERROR_INSUFFICIENT_BUFFER) {
        // Allocate a buffer of the required size
        std::vector<wchar_t> buffer(length);

        // Pass 2: Retrieve the actual Package Family Name string
        rc = PackageFamilyNameFromFullName(packageFullName.c_str(), &length, buffer.data());

        if (rc == ERROR_SUCCESS) {
            return std::wstring(buffer.data());
        }
    }

    // Return an empty string if the input format was invalid or lookup failed
    std::wcerr << L"Failed to convert. Error code: " << rc << std::endl;
    return L"";
}


void CopyFolderContents(const fs::path& src, const fs::path& dest) 
  {
    std::error_code ec;

    fs::create_directories(dest, ec);
    if (ec) {
        std::cerr << "Failed to create target directory: " << ec.message() << "\n";
        return;
    }

    // 2. Configure options: deep copy subfolders and overwrite existing files
    fs::copy_options options = fs::copy_options::recursive
        | fs::copy_options::overwrite_existing;

    // 3. Loop through individual files/folders *inside* the source directory
    for (const auto& entry : fs::directory_iterator(src, ec)) {
        // Combine the destination path with the current item's filename
        fs::path targetPath = dest / entry.path().filename();
        std::cout << " copying " << entry.path().filename() << " to " << targetPath << std::endl;;
        // Copy the specific item
        fs::copy(entry.path(), targetPath, options, ec);

        if (ec) {
            std::cerr << "Error copying " << entry.path().filename()
                << ": " << ec.message() << "\n";
            ec.clear(); // Reset error state to continue loop
        }
    }
}
std::string decrypt_get_dsn(const fs::path& input, const fs::path& output)
{
    std::string base64Str = ReadFileToString(input);
    if (base64Str.empty())
    {
        std::cout << "[-] Error: Could not read input file or file is empty.\n";
        return "";
    }

    // 2. Calculate required buffer size for Base64 decoding
    DWORD decodedSize = 0;
    if (!CryptStringToBinaryA(base64Str.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL)) 
    {
        std::cout << "[-] Error: Failed to calculate Base64 decode size.\n";
        return "";
    }

    // Allocate memory for the decoded data blob
    std::vector<BYTE> decodedBytes(decodedSize);

    // Perform actual Base64 decoding
    if (!CryptStringToBinaryA(base64Str.c_str(), 0, CRYPT_STRING_BASE64, decodedBytes.data(), &decodedSize, NULL, NULL)) 
    {
        std::cout << "[-] Error: Base64 decoding failed.\n";
        return "";
    }

    // 3. Prepare data blobs for DPAPI CryptUnprotectData
    DATA_BLOB encryptedBlob;
    encryptedBlob.pbData = decodedBytes.data();
    encryptedBlob.cbData = decodedSize;

    DATA_BLOB decryptedBlob;
    decryptedBlob.pbData = NULL;
    decryptedBlob.cbData = 0;

    // Call CryptUnprotectData with flags matching your specification (1 = CRYPTPROTECT_UI_FORBIDDEN)
    // local_48 corresponds to &encryptedBlob, and local_40 corresponds to &decryptedBlob
    BOOL result = CryptUnprotectData(
        &encryptedBlob,      // local_48 input data
        nullptr,             // Optional description string output
        nullptr,             // Optional entropy blob
        nullptr,             // Reserved
        nullptr,             // Prompt structure
        1,                   // Flags: CRYPTPROTECT_UI_FORBIDDEN
        &decryptedBlob       // local_40 output data
    );

    if (!result) {
        std::cout << "[-] Error: CryptUnprotectData failed. Error code: " << GetLastError() << "\n";
        std::cout << "[!] Note: DPAPI decryption must run under the same user account context that encrypted it.\n";
        return "";
    }
    std::string ret = ParseDecryptedTextBlob(decryptedBlob);
    // 4. Save the decrypted plaintext to the output file
    if (!WriteBufferToFile(output, decryptedBlob.pbData, decryptedBlob.cbData))
    {
        std::cerr << "[-] Error: Failed to write decrypted data to output file.\n";
        LocalFree(decryptedBlob.pbData); // Ensure memory cleanup on failure
        return "";
    }

    std::cout << "[+] Success: Decrypted data saved to " << output << "\n";

    // 5. Clean up allocated DPAPI buffers
    LocalFree(decryptedBlob.pbData);
    return ret;
}

class BasicDecryptor
{
public:
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out) = 0;
    virtual bool has_key() { return false; }
    virtual std::string  get_key() { return ""; }
};
void rev(std::vector<uint8_t>& out, uint8_t* lut, uint8_t o)
{
    for (size_t a = 0; a < out.size(); a++)
    {
        for (int i = 0; i < 256; i++)
        {
            if (lut[i] == out[a])
            {
                out[a] = ((uint8_t)i) ^ o;
                break;
            }
        }
    }
}
uint8_t rev1(uint8_t srch,uint8_t* lut)
{
    for (int i = 0; i < 256; i++)
    {
        if (lut[i] == srch)
        {
            return i;
        }
    }
    printf("%d not found in lut\n", (int)srch);
    return 0;
}
class MboxDecryptor : public BasicDecryptor
{
public:
    bool checkAes(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out, std::vector<uint8_t>& key)
    {
       if (iv.size() != 16)
       {
       printf("Unsupported IV size %zu\n", iv.size());
       return false;
       }
            unsigned long padded_size = 0;
            plusaes::Error e = plusaes::decrypt_cbc(&ciphertext[0], ciphertext.size(), &key[0], key.size(), (unsigned char (*)[16]) & iv[0], &out[0], out.size(), &padded_size);
            if (e != plusaes::kErrorOk)
            {
                return false;
            }
            //printf("Padding %ld",padded_size);
         //   out.resize(out.size() - padded_size);
            if (padded_size <= 16) return true;
            return false;

    }
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out)
    {
  
        if (!mbox_saved)
        {
            printf("Mbox not saved, decryption failed!");
            return;
        }
        char* mbox_address = &mboxsave[0];
        if (mbox_bare)
        {
            if (curOffs.decr_offset_bare == 0)
            {
                printf("Bare mbox not set for this version, decryption failed!\n");
                return;
            }
            printf("Using Bare/alternate mbox\n");
    
           
            typedef void(__cdecl* aes_decrypt_call_bore)(void* bk, unsigned char* iv, void* chunk, int len, unsigned char* out);
            aes_decrypt_call_bore callme = (aes_decrypt_call_bore)(globoffs + curOffs.decr_offset_bare);
            // printf("Cipher size %zu \n",ciphertext.size());
            out.resize(ciphertext.size());         
           // std::cout << "Barek " << hexStr(&barek[0], barek.size()) << std::endl;

            callme(&barek[0], &iv[0], &ciphertext[0], ciphertext.size(), &out[0]);
            uint8_t* lut = (uint8_t*)(globoffs + curOffs.t_bare);
            rev(out, lut, curOffs.o_bare);
            //std::cout << "Decoded data " << hexStr(&out[0], out.size()) << std::endl;
            if (out[out.size() - 1] >= out.size() || out[out.size() - 1] > 16)
            {
                printf("Invalid padding length: %d\n", (int)out[out.size() - 1]);
                out.resize(0);
                return;
            }
            // printf("Padding length: %d\n", (int)out[out.size() - 1]);
            out.resize(out.size() - out[out.size() - 1]);

        }
        else
        {

            typedef void(__cdecl* aes_decrypt_call)(void* mbbox_1, unsigned char* input_ciphertext_2, unsigned int chunk_len_3, unsigned char* output_4, size_t* alllocated_len_ptr_5);
            aes_decrypt_call callme = (aes_decrypt_call)(globoffs + curOffs.decr_offset);
            //set iv
            memcpy(mbox_address + curOffs.mbox_iv_offset, &iv[0], iv.size());
           
            out.resize(ciphertext.size());
            size_t sz = out.size();
            callme(mbox_address, &ciphertext[0], ciphertext.size(), &out[0], &sz);
            // std::cout << "Decr data " << hexStr(&out[0], out.size()) << std::endl;
            out.resize(sz);

            if (sz == 0)
            {
                printf("Plaintext size is 0 \n");
                return;
            }
            if (out[out.size() - 1] >= out.size() || out[out.size() - 1] > 16)
            {
                printf("Invalid padding length: %d\n", (int)out[out.size() - 1]);
                out.resize(0);
                return;
            }
            out.resize(sz - out[out.size() - 1]);
        }


        //while (1) {}
    }
};


class AesDecryptor : public BasicDecryptor
{
public:
    std::vector<uint8_t> key;
    AesDecryptor(const std::vector<uint8_t>& k) :key(k) {}
    virtual bool has_key() { return true; }
    virtual std::string  get_key() { return hexStr(&key[0],key.size()); }
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out)
    {
        if (iv.size() != 16)
        {
            printf("Unsupported IV size %zd\n", iv.size());
            out.resize(0);
            return;
        }
        out.resize(ciphertext.size());
        unsigned long padded_size = 0;
        plusaes::Error e=plusaes::decrypt_cbc(&ciphertext[0], ciphertext.size(), &key[0], key.size(), (unsigned char (*)[16]) & iv[0], &out[0], out.size(), &padded_size);
        if (e != plusaes::kErrorOk)
        {
            printf("Aes error %d\n", e);
            if (mbox_saved)
            {
                printf("Trying mbox instead\n");
                MboxDecryptor temp;
                temp.decrypt(ciphertext, iv, out);
                return;
            }
        }
        //printf("Padding %ld",padded_size);
        out.resize(out.size() - padded_size);
    }
};

std::vector<uint8_t> drmionHeader = HexToBytes("ea44524d494f4eee");

std::vector<uint8_t> fake = HexToBytes("e00100eaee9e8183de9a86be97de95848d50726f74656374656444617461852101882180ee03c4820189de03bea4eec981a7dec5a3be9a8e8e4143434f554e545f53454352455489434c49454e545f49449e834145538f8e944145532f4342432f504b43533550616464696e679f8a486d6163534841323536c0aea0ccbc90f3ac6e4a1a1f0352e9870a2801c287d651f942337aef0a21dfa95ae49cc1ae02cbe00100eaee9e8183de9a86be97de95848d50726f74656374656444617461852101882180ee02a481adde029fa28eb9616d7a6e312e64726d2d766f75636865722e76312e30303030303030302d303030302d303030302d303030302d30303030303030303030303096ae903992d248da68e4d3371739cf3711623295a87465737464617461f8aec0a2eddd1bd68d5fc98e60c2c915fe9b4bec38e23d98d41f10068ec3afe38002173facf2260318cdb8726b1b3a274ec529d000724d29a04bfc399848041eda5711b6eea781badea3b5885075726368617365b78e966174763a6b696e3a323a6447567a644752686447453dbdeed681bebed2ded0bb8e93636c69656e745f7265737472696374696f6e73bcbeb7de95b88d436c697070696e674c696d6974b98431353030de9eb88e9454657874546f53706565636844697361626c6564b98566616c7365");
bool write_vector_to_file(const fs::path& target_path, const std::vector<uint8_t>& data) 
{
    if (target_path.has_parent_path() && !fs::exists(target_path.parent_path())) {
        fs::create_directories(target_path.parent_path());
    }

    std::ofstream file(target_path, std::ios::out | std::ios::binary);

    if (!file) {
        std::cerr << "Error: Failed to open path for writing: " << target_path << "\n";
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());

    return file.good();
}
void  processPage(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, BasicDecryptor* decr, bool decompress, bool decrypt, std::vector<uint8_t>& out)
{

    std::vector<uint8_t> msg;
    if (decrypt)
    {
        decr->decrypt(ciphertext, iv, msg);
    }
    else
    {
        msg = ciphertext;
    }
    if (!decompress)
    {
        out = msg;
        return;
    }
    if (msg[0] != 0)
    {
        printf("Unsupported compression type %d\n", (int)msg[0]);
    }
    plz::PocketLzma p;
    std::vector<uint8_t> decompressed;
    //std::cout << "Lzma hex " << hexStr(&msg[0], msg.size()) << std::endl;
    plz::StatusCode  status = p.decompress(&msg[1], msg.size() - 1, decompressed);
    if (status == plz::StatusCode::Ok)
    {
        out = decompressed;
        return;
    }
    printf("LZMA decompression failed!\n"); //maybe throw? 
}
bool processDRMION(char* buf, size_t size, BasicDecryptor* decr, std::vector<uint8_t>& out)
{
    //std::cout << hexStr((unsigned char*)buf,size) << std::endl;
    BinaryIonParser bp((unsigned char*)buf, size, -1);
    addprottable(&bp);
    if (!bp.hasnext())
    {
        printf("Invalid DRMION? \n");
        return false;
    }
    out.clear();
    int nxt = bp.next();
    if (nxt != TID_SYMBOL)
    {
        printf("Symbol not detected in DRMION \n");
        return false;
    }
    if (bp.next() != TID_LIST)
    {
        printf("List not detected in drmion\n");
        return false;
    }
    std::string current_keyid="";
    std::string current_voucherid="";
    while (true)
    {
        if (bp.gettypename() == "enddoc") break;

        bp.stepin();

        while (bp.hasnext())
        {
            bp.next();
            std::string nm = bp.gettypename();
            // printf("Typename %s\n",nm.c_str());
            if (nm == "com.amazon.drm.EnvelopeMetadata@2.0" || nm == "com.amazon.drm.EnvelopeMetadata@1.0")
            {
                bp.stepin();
                while (bp.hasnext())
                {
                    bp.next();
                    if (bp.getfieldname() == "encryption_key") current_keyid = bp.stringvalue();
                    if (bp.getfieldname() == "encryption_voucher") current_voucherid = bp.stringvalue();

                }
                bp.stepout();
            }
            if (nm == "com.amazon.drm.EncryptedPage@1.0" || nm == "com.amazon.drm.EncryptedPage@2.0")
            {
               // printf("Encrypted page...\n");
                bool decompress = false;
                bool decrypt = true;
                std::vector<uint8_t> ct;
                std::vector<uint8_t> civ;
                //std::vector<uint8_t> data(buffer, buffer + size);
                bp.stepin();
                while (bp.hasnext())
                {
                    bp.next();
                    if (bp.gettypename() == "com.amazon.drm.Compressed@1.0")    decompress = true;
                    if (bp.getfieldname() == "cipher_text") ct = bp.lobvalue();
                    if (bp.getfieldname() == "cipher_iv") civ = bp.lobvalue();

                }
                if (!ct.empty() && !civ.empty())
                {
                    std::vector<uint8_t> page;
                   // printf("Encrypted page... processing\n");
                    processPage(ct, civ, decr, decompress, decrypt, page);
                    //printf("Got page of size %ld\n", page.size());
                    out.insert(out.end(), page.begin(), page.end());

                }
                bp.stepout();

            }
            else
            {
                if (nm == "com.amazon.drm.PlainText@1.0" || nm == "com.amazon.drm.PlainText@2.0")
                {
                    bool decrypt = false;
                    bool decompress = false;
                    std::vector<uint8_t> plaintext;
                    bp.stepin();
                    while (bp.hasnext())
                    {
                        bp.next();
                        if (bp.gettypename() == "com.amazon.drm.Compressed@1.0")    decompress = true;
                        if (bp.getfieldname() == "data") plaintext = bp.lobvalue();

                    }
                    if (!plaintext.empty())
                    {
                        std::vector<uint8_t> page;
                        processPage(plaintext, plaintext, decr, decompress, decrypt, page);
                        out.insert(out.end(), page.begin(), page.end());

                    }
                    bp.stepout();
                }
            }
        }
        bp.stepout();
        if (!bp.hasnext()) break;
        bp.next();
    }
    if (decr->has_key())
    {
        std::string pkey = decr->get_key();

        if (current_keyid != "")
            currentKeymaps.keyid_to_key[current_keyid] = pkey;
        std::cout << "Current keyid " << current_keyid << std::endl;
        if (current_voucherid != "")
            currentKeymaps.voucherid_to_key[current_voucherid] = pkey;
    }


    return true;
}





void initKrfFunctions(KrfAccessFunctions* out)
{
    out->GetPluginManager = (getPluginManager)(globoffs + curOffs.get_plugin_man);
    out->LoadAllStaticModules = (loadAllStaticModules)(globoffs + curOffs.load_all);
    out->DrmDataProvider = (drmDataProv)(globoffs + curOffs.drm_provider);
    out->GetBookFactory = (getBookFactory)(globoffs + curOffs.get_factory);
    out->OpenBook = (openBook)(globoffs + curOffs.open_book);

}

static bool ends_with(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool starts_with(const std::string& str, const std::string& prefix)
{
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}


static bool ends_with(const std::string& str, const char* suffix, size_t suffixLen)
{
    return str.size() >= suffixLen && str.compare(str.size() - suffixLen, suffixLen, suffix, suffixLen) == 0;
}

static bool ends_with(const std::string& str, const char* suffix)
{
    return ends_with(str, suffix, std::string::traits_type::length(suffix));
}

static bool starts_with(const std::string& str, const char* prefix, unsigned prefixLen)
{
    return str.size() >= prefixLen && str.compare(0, prefixLen, prefix, prefixLen) == 0;
}

static bool starts_with(const std::string& str, const char* prefix)
{
    return starts_with(str, prefix, std::string::traits_type::length(prefix));
}

struct DrmParameters
{
    fs::path bookFile;
    fs::path shortBookFile;

    std::list<fs::path> resources;
    std::list<fs::path> shortResources;

    std::list<fs::path> vouchers;
};

bool enumerateKindleFolder(const TCHAR* path, DrmParameters* out)
{
    if (out == nullptr) return false;
    WIN32_FIND_DATA ffd;
    //LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg = 0;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    std::basic_string<TCHAR> conv = path;// std::basic_string<TCHAR>(path.begin(), path.end());
    fs::path shortPath = fs::path(path);
    //std::string shortPath = std::string(conv.begin(), conv.end());
    StringCchCopy(szDir, MAX_PATH, path);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
    hFind = FindFirstFile(szDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    do
    {
        fs::path wfname = fs::path(ffd.cFileName);
        //std::string fname = std::string(wfname.begin(), wfname.end());
        const fs::path fullname = shortPath / wfname;
        const std::wstring ext = fullname.extension().wstring();
        if (ext==L".azw")
        {
            out->bookFile = fullname;
            out->shortBookFile = wfname;
            //std::cout << "Bookname " << fullname << std::endl;
            continue;
        }
        if (ext == L".voucher")
        {
            out->vouchers.push_back(fullname);
            continue;
        }
        if (ext == L".res" || ext == L".md")
        {
            out->resources.push_back(fullname);
            out->shortResources.push_back(fs::path(wfname));
            //std::cout << "Resource " << fullname << std::endl;
            continue;
        }

    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);
  
    return !out->bookFile.empty();

}


int  tryOpeningBook(KrfAccessFunctions* ctx, const std::string& serial, const std::string& secret, DrmParameters* params, KeyData* out)
{
    keydataAccumulator.reset();
    unsigned int sub[3000];
    memset((void*)sub, 0, sizeof(sub));
    std::list<std::string> secrets;
    secrets.push_back(secret);
    std::list<std::string> cvouchers;
    std::list<std::string> cres;
    for (const auto& v : params->vouchers)
    {
        cvouchers.push_back(v.u8string());
    }
    for (const auto& v : params->resources)
    {
        cres.push_back(v.u8string());
    }
    ctx->DrmDataProvider((void*)sub, serial, secrets, cvouchers);
    void* bookFactory = ctx->GetBookFactory();
    std::shared_ptr<void*> rebook;
    krfErr err;
    err.code = 0;
    armed = true;
    ctx->OpenBook(bookFactory, &rebook, params->bookFile.u8string(), sub, &err, cres);
    armed = false;
    if (err.code != 0)
    {
        std::cout << "BookOpen error " << err.code << " " << err.msg << std::endl;
    }
    else
    {
        std::cout << "Succesfully opened book " << params->bookFile << std::endl;
        //   while (true) {};
    }

    if (err.code == 0)
    {
        std::cout << "Old secrets cnt " << keydataAccumulator.old_secrets.size() << std::endl;
        out->aggregate(&keydataAccumulator);
        //return true;
    }
    else
    { //even failed book sometimes generates secrets.

        out->old_secrets.insert(keydataAccumulator.old_secrets.begin(), keydataAccumulator.old_secrets.end());
    }
    if (rebook != nullptr)
    {
        rebook.reset();
    }
    return err.code;
}
bool IsDotOrDotDot(const TCHAR* s)
{
    if (s[0] == TCHAR('.'))
    {
        if (s[1] == TCHAR('\0')) return true; // .
        if (s[1] == TCHAR('.') && s[2] == TCHAR('\0')) return true; // ..
    }
    return false;
}


//stolen from StackOverflow
template<class T>
T base_name(T const& path, T const& delims = "/\\")
{
    return path.substr(path.find_last_of(delims) + 1);
}
template<class T>
T remove_extension(T const& filename)
{
    typename T::size_type const p(filename.find_last_of('.'));
    return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}
bool oldSecretsAccumulated = false;
void accumulateOldSecrets(KrfAccessFunctions* ctx, const std::string& serial, std::set<std::string>* secret_candidates, DrmParameters* params, KeyData* out)
{
    if (oldSecretsAccumulated) return;
    std::cout << "Found KFX book that uses secrets, trying to accumulate older secrets" << std::endl;
    std::list<std::string> cvouchers;
    std::list<std::string> cres;
    for (const auto& v : params->vouchers)
    {
        cvouchers.push_back(v.u8string());
    }
    for (const auto& v : params->resources)
    {
        cres.push_back(v.u8string());
    }

    for (auto& secret : *secret_candidates)
    {
        keydataAccumulator.reset();
        unsigned int sub[3000];
        memset((void*)sub, 0, sizeof(sub));
        std::list<std::string> secrets;
        secrets.push_back(secret);
        ctx->DrmDataProvider((void*)sub, serial, secrets,cvouchers);
        void* bookFactory = ctx->GetBookFactory();
        std::shared_ptr<void*> rebook;
        krfErr err;
        err.code = 0;
        armed = true;
        ctx->OpenBook(bookFactory, &rebook, params->bookFile.u8string(), sub, &err, cres);
        armed = false;

        if (keydataAccumulator.old_secrets.size() > 0)
        {
            out->aggregate(&keydataAccumulator);
            oldSecretsAccumulated = true;
        }
        if (rebook != nullptr)
        {
            rebook.reset();
        }
    }

}
std::string hexhex(const std::string& st)
{
    return hexStr((uint8_t*)st.c_str(), st.size());
}
std::wstring utf8_to_widechar(const char* str)
{
    int reqChars = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    //WCHAR* wStr = (WCHAR*)malloc(reqChars * sizeof(WCHAR));
    std::wstring ret(reqChars, 0);
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &ret[0], reqChars);
    return ret;
}
std::string widechar_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) 
    {
        return std::string();
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)(wstr.length()), nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) 
    {
       std::cout<< ("WideCharToMultiByte failed to calculate size.")<<std::endl;
       return std::string();
    }
    std::string result(size_needed, 0);

    int result_size = WideCharToMultiByte(CP_UTF8, 0,wstr.c_str(),(int)(wstr.length()), &result[0], size_needed,nullptr, nullptr);

    if (result_size <= 0) 
    {
        std::cout << "WideCharToMultiByte failed to convert string." << std::endl;
        return std::string();
    }

    return result;
}

int rmz_stat64(const wchar_t* path, struct __stat64* buffer)
{
    int res = _wstat64(path, buffer);
    return res;
}
mz_bool mz_open(mz_zip_archive* archive, const fs::path& filename, mz_uint level_and_flags, mz_zip_error* pErr)
{

    if (!archive) 
    {
        if (pErr) *pErr = MZ_ZIP_BUF_TOO_SMALL;
        return false;
    }
    mz_zip_zero_struct(archive);
    mz_bool status;
    status = mz_zip_writer_init_file_v2(archive, filename.u8string().c_str(), 0, level_and_flags);
    if (!status)
    {
        if (pErr) *pErr = archive->m_last_error;
    }
    return status;
}
mz_bool mz_add(mz_zip_archive* archive, const char* pArchive_name, const void* pBuf, size_t buf_size, mz_uint level_and_flags, mz_zip_error* pErr)
{
    mz_bool status;
    status = mz_zip_writer_add_mem_ex(archive, pArchive_name, pBuf, buf_size, NULL, 0, level_and_flags, 0, 0);
    if (pErr != NULL)
    {
        *pErr = archive->m_last_error;
    }
    return status;
}
mz_bool mz_close(mz_zip_archive* archive, mz_zip_error* pErr)
{
    mz_bool status=MZ_TRUE;
    if (!archive)
    {
        if (pErr) *pErr = MZ_ZIP_BUF_TOO_SMALL;
        return false;
    }
    /* Always finalize, even if adding failed for some reason, so we have a valid central directory. (This may not always succeed, but we can try.) */
    if (!mz_zip_writer_finalize_archive(archive))
    {
        if (pErr) *pErr =archive->m_last_error;

        status = MZ_FALSE;
    }

    if (!mz_zip_writer_end(archive))
    {
        if (pErr) *pErr = archive->m_last_error;

        status = MZ_FALSE;
    }
    return status;
}

int checkDRMIONMeta( const fs::path& fname,  std::string& keyName, std::string& voucherName)
{

    size_t bl = 0;
    //char* buf =  /// read_file(fname.c_str(), bl);
    std::vector<char> buf = ReadFileToVector(fname);
    bl = buf.size();
    printf("Read file of %zu bytes\n", bl);
    if (bl == 0)
    {
        return 0;
    }

    if (bl > drmionHeader.size() && memcmp(&drmionHeader[0], &buf[0], drmionHeader.size()) == 0)
    {
        std::vector<uint8_t> outme;
        printf("Checking DRMION... \n");
        //std::cout << hexStr((unsigned char*)buf,size) << std::endl;..&buf[8], bl - 16
        bool got_key=false;
        bool got_voucher=false;
        BinaryIonParser bp((unsigned char*)&buf[8], bl - 16, -1);
        addprottable(&bp);
        if (!bp.hasnext())
        {
            printf("Invalid DRMION? \n");
            return -2;
        }
        int nxt = bp.next();
        if (nxt != TID_SYMBOL)
        {
            printf("Symbol not detected in DRMION \n");
            return false;
        }
        if (bp.next() != TID_LIST)
        {
            printf("List not detected in drmion\n");
            return false;
        }

        while (true)
        {
            if (bp.gettypename() == "enddoc") break;

            bp.stepin();

            while (bp.hasnext())
            {
                bp.next();
                std::string nm = bp.gettypename();
                if (nm == "com.amazon.drm.EnvelopeMetadata@2.0" || nm == "com.amazon.drm.EnvelopeMetadata@1.0")
                {
                    bp.stepin();
                    while (bp.hasnext())
                    {
                        bp.next();
                        if (bp.getfieldname() == "encryption_key") { keyName = bp.stringvalue(); got_key = true; }
                        if (bp.getfieldname() == "encryption_voucher") { voucherName = bp.stringvalue(); got_voucher = true; }
                    }
                    if (got_key && got_voucher)
                    {
                        //assume 1
                        return 0;
                    }
                }
                
            }
            bp.stepout();
            if (!bp.hasnext()) break;
            bp.next();
        }
        if (!got_key)
        {
            keyName = "";
        }
        if (!got_voucher)
        {
            voucherName = "";
        }
        if (got_key || got_voucher)
        {
            return 0;
        }
   
    }
    else
    {
        return -1; //not drmion
    }
    return -2; //not present
}


int processFile(mz_zip_archive* archive, const fs::path& fname, const std::string& archivedName, BasicDecryptor* decr)
{

    size_t bl = 0;
    //char* buf =  /// read_file(fname.c_str(), bl);
    std::vector<char> buf = ReadFileToVector(fname);
    bl = buf.size();
    printf("Read file of %zu bytes\n", bl);
    if (bl == 0)
    {
        return 0;
    }
 
    if (bl > drmionHeader.size() && memcmp(&drmionHeader[0], &buf[0], drmionHeader.size()) == 0)
    {
        std::vector<uint8_t> outme;
        printf("Decrypting DRMION... \n");
        if (processDRMION(&buf[8], bl - 16, decr, outme))
        {
            mz_zip_error err=MZ_ZIP_NO_ERROR;
            mz_bool status = mz_add(archive, archivedName.c_str(), outme.data(), outme.size(), MZ_BEST_COMPRESSION,&err);
            if (!status)
            {
                printf("mz_add of DRMION file  failed! Error: %s \n", mz_zip_get_error_string(err));
                return EXIT_FAILURE;
            }
            printf("DRMION decrypted and saved.\n");
        }
        else
        {
            printf("Could not decrypt DRMION? \n");
            return 2;
        }
    }
    else
    {
      //  mz_zip_add_mem_to_archive_file_in_place_v2(pZip_filename, pArchive_name, pBuf, buf_size, pComment, comment_size, level_and_flags, NULL);
        mz_zip_error err;
        mz_bool status = mz_add(archive, archivedName.c_str(), &buf[0], bl, MZ_BEST_COMPRESSION, &err);
        if (!status)
        {
            printf("mz_add of non-DRM file failed for %s! Error: %s \n", archivedName.c_str(), mz_zip_get_error_string(err));
            return EXIT_FAILURE;
        }
    }
    return 0;
}



// taken from old alfcrypto... https://github.com/apprenticeharper/DeDRM_tools/blob/776f146ca00d11b24575f4fd6e8202df30a2b7ea/DeDRM_plugin/

/// I am not touching Topaz format, on consideration...



BookInterface* GetDecryptedBook(
    const std::string& infile,
    const std::vector<std::string>& kDatabases,
    std::vector<std::string>& androidFiles,
    std::vector<std::string>& serials,
    std::vector<std::string>& pids,
    std::chrono::time_point<std::chrono::steady_clock> starttime = std::chrono::steady_clock::now(),
    const std::string& skeyfile = "",
    bool remove_watermarks = true)
{
    // Check if file exists
    std::ifstream f(infile.c_str(), std::ios::binary);
    if (!f.good()) {
        throw DrmException("Input file does not exist.");
    }
  
    // Read first 8 bytes
    char magic8[8] = { 0 };
    f.read(magic8, 8);
    std::string magic8_str(magic8, 8);
    std::string compare((char*) & drmionHeader[0], 8);
    if (magic8_str == compare) {
        throw DrmException("The .kfx DRMION file cannot be decrypted by itself. A .kfx-zip archive containing a DRM voucher is required.");
    }

    bool mobi = true;
    if (magic8_str.substr(0, 3) == "TPZ") {
        mobi = false;
    }
    //uint16_t value = (static_cast<uint16_t>(self_sect[0x8]) << 8) | self_sect[0x9];
    BookInterface* mb = nullptr;

    if (magic8_str.substr(0, 4) == "PK\x03\x04") {
        // mb = new KFXZipBook(infile, skeyfile);
    }
    else if (mobi) {
        // mb = new MobiBook(infile, remove_watermarks);
    }
    else {
        // mb = new TopazBook(infile);
    }

    // Fallback instantiation for compiling/testing placeholder
    if (!mb) mb = new BookInterface();

    
        std::cout << "Decrypting " << mb->getBookType() << " ebook.\n";
    
    // Copy pids list
    std::vector<std::string> totalpids = pids;

    // Simulate getting android serials
    for (const auto& aFile : androidFiles) {
        // serials.insert(serials.end(), androidkindlekey::get_serials(aFile).begin(), androidkindlekey::get_serials(aFile).end());
    }

    std::pair<std::vector<char>, std::vector<char>> mdp = mb->getPIDMetaInfo();
    // Simulate extending PID list
    // auto extra_pids = kgenpids::getPidList(md1, md2, serials, kDatabases);
    // totalpids.insert(totalpids.end(), extra_pids.begin(), extra_pids.end());

    // Remove duplicates (simulate Python's list(set(totalpids)))
    std::sort(totalpids.begin(), totalpids.end());
    totalpids.erase(std::unique(totalpids.begin(), totalpids.end()), totalpids.end());

    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - starttime;
    std::cout << "Found " << totalpids.size() << " keys to try after " << elapsed.count() << " seconds\n";

    try {
        mb->processBook(totalpids);
    }
    catch (...) {
        mb->cleanup();
        delete mb; // Prevent memory leak on throw
        throw;
    }

    now = std::chrono::steady_clock::now();
    elapsed = now - starttime;
    std::cout << "Decryption succeeded after " << elapsed.count() << " seconds\n";

    return mb;
}

void enumerateKindleDir(const TCHAR* path, const std::string& outdir, std::set<std::string>* serial_candidates, std::set<std::string>* secret_candidates, std::string* k4ifile,const fs::path& fbook, const fs::path& out_keyfile)
{
    WIN32_FIND_DATA ffd;
    //  LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    TCHAR temp[MAX_PATH];
    //size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    StringCchCopy(szDir, MAX_PATH, path);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
    hFind = FindFirstFile(szDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        std::cout << "Could not open book directory : " << err << std::endl;
        return;
    }
    std::set<std::string> working_serials;
    std::set<std::string> working_secrets;
    std::set<std::string> old_secrets;
    for (auto secr : *secret_candidates)
    {
        if (secr.size() == 40)
        { //add already decrypted secrets just in case
            old_secrets.insert(secr);
        }
    }
    {
        afb = true;
        fs::path fb_path_v = fbook / "fake.voucher";
        fs::path fb_path_a = fbook / "fake.azw";
        write_vector_to_file(fb_path_v, fake);
        write_vector_to_file(fb_path_a, drmionHeader);
        DrmParameters params;
        std::cout << "Opening fake book..." << std::endl;
        if (enumerateKindleFolder(fbook.wstring().c_str(), &params))
        {
            KeyData discard;
            for(auto dsn:*serial_candidates)
            {
            accumulateOldSecrets(&globalKRFContext, dsn, secret_candidates, &params, &discard);
            if (discard.old_secrets.size() > 0)
            {
                std::cout << "Got " << discard.old_secrets.size() << " secret(s) from fake book" << std::endl;
                old_secrets.insert(discard.old_secrets.begin(), discard.old_secrets.end());
            }
            }

        }
        else
        {
            std::cout << "Did not manage to work with fake book?" << std::endl;
        }
        afb = false;
    }
    do
    {

        if (IsDotOrDotDot(ffd.cFileName)) continue;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            _tprintf(TEXT("Trying to open  %s \n"), ffd.cFileName);
     
            //if (fs::path(ffd.cFileName) != fs::path(L""))
           // {
           //     printf("Skip...\n");
          //      continue;
           // }

            DrmParameters params;
            StringCchCopy(temp, MAX_PATH, path);
            StringCchCat(temp, MAX_PATH, TEXT("\\"));
            StringCchCat(temp, MAX_PATH, ffd.cFileName);
            if (enumerateKindleFolder(temp, &params))
            {
                // params.vouchers;
                KeyData acc;
                bool opened = false;
                bool invalid = false;
                bool mobiProc = false;
                mbox_saved = false;
                mbox_keyed = false;
                // a silly optimization
                for (auto& serial : working_serials)
                {
                    for (auto& secret : working_secrets)
                    {
                        int code = tryOpeningBook(&globalKRFContext, serial, secret, &params, &acc);
                        if (acc.old_secrets.size() > 0)
                        {
                            working_serials.insert(serial);
                            accumulateOldSecrets(&globalKRFContext, serial, secret_candidates, &params, &acc);
                            if (acc.old_secrets.size() > 0)
                            {
                                old_secrets.insert(acc.old_secrets.begin(), acc.old_secrets.end());
                            }
                        }
                        if (code == 0)
                        {
                            opened = true;
                            if (acc.old_secrets.size() > 0)
                            {
                                std::cout << "Opened book with reused secret: " << secret << std::endl;
                            }
                            else
                            {
                                std::cout << "This book does not seem to use account secrets" << std::endl;
                            }
                            break;
                        }
                        if (code == 14)
                        {
                            invalid = true;
                            std::cout << "Checking if the book is MOBI" << std::endl;
                            fs::path mobipath = fs::path(params.bookFile);
                            MobiBook mb(mobipath);
                            if (!mb.init_done)
                            {
                                std::cout << "Seems like it is not, cannot decrypt. Might be Topaz?" << std::endl;
                            }
                            else
                            {
                                try
                                {
                                    fs::path oname = params.shortBookFile;
                                    oname.replace_extension(mb.getBookExtension());
                                    fs::path out_path = fs::path(outdir) / oname;
                                    if (fs::exists(out_path))
                                    {
                                        std::cout << "File " << oname << " already exists in the output folder" << std::endl;
                                        std::cout << "Skipping" << std::endl;
                                        mobiProc = true;
                                    }
                                    else 
                                    {                                    
                                    auto pdd = mb.getPIDMetaInfo();
                                    invalid = false;
                                    std::vector<std::string> sec;
                                    for (auto osc : old_secrets)
                                    {
                                        sec.push_back(osc);
                                    }
                                    std::vector<std::string> pidz = getK4Pids(pdd.first, pdd.second, serial, sec);
                                    mb.processBook(pidz);
                                   
                                    std::cout << "Looks like it processed... Saving to " << out_path << std::endl;

                                    mb.writeFile(out_path);
                                    mobiProc = true;
                                    }

                                }
                                catch (DrmException e)
                                {
                                    std::cout << "Failed MOBI processing: " << e.what() << std::endl;
                                }

                            }

                            break;
                        }
                    }
                    if (opened || invalid)break;
                }
                if (!opened && !invalid && !mobiProc)
                {
                    for (auto& serial : *serial_candidates)
                    {
                        for (auto& secret : *secret_candidates)
                        {

                            int code = tryOpeningBook(&globalKRFContext, serial, secret, &params, &acc);
                            if (acc.old_secrets.size() > 0)
                            {
                                working_serials.insert(serial);
                                accumulateOldSecrets(&globalKRFContext, serial, secret_candidates, &params, &acc);
                                if (acc.old_secrets.size() > 0)
                                {
                                    old_secrets.insert(acc.old_secrets.begin(), acc.old_secrets.end());
                                }
                            }
                            if (code == 0)
                            {
                                opened = true;
                                working_serials.insert(serial);
                                if (acc.old_secrets.size() > 0)
                                {
                                    working_secrets.insert(secret);
                                    std::cout << "Opened book with secret: " << secret << std::endl;
                                }
                                else
                                {
                                    std::cout << "This book does not use account secrets" << std::endl;
                                }
                                break;
                            }
                            if (code == 14)
                            {
                                invalid = true;
                                std::cout << "Checking if the book is MOBI" << std::endl;
                                fs::path mobipath = fs::path(params.bookFile);
                                MobiBook mb(mobipath);
                                if (!mb.init_done)
                                {
                                    std::cout << "Seems like it is not, cannot decrypt. Might be Topaz?" << std::endl;
                                }
                                else
                                {
                                    try
                                    {
                                        fs::path oname = params.shortBookFile;
                                        oname.replace_extension(mb.getBookExtension());
                                        fs::path out_path = fs::path(outdir) /oname;
                                        if (fs::exists(out_path))
                                        {
                                            std::cout << "File " << oname << " already exists in the output folder" << std::endl;
                                            std::cout << "Skipping" << std::endl;
                                            mobiProc = true;
                                        }
                                        else 
                                        {
                                        invalid = false;
                                        auto pdd = mb.getPIDMetaInfo();
                                        std::vector<std::string> sec;
                                        for (auto osc : old_secrets)
                                        {
                                            sec.push_back(osc);
                                        }
                                        std::vector<std::string> pidz = getK4Pids(pdd.first, pdd.second, serial, sec);
                                        mb.processBook(pidz);
                                        
                                        std::cout << "Looks like it processed... Saving to " << out_path << std::endl;

                                        mb.writeFile(out_path);
                                        mobiProc = true;
                                        }
                                        
                                    }
                                    catch (DrmException e)
                                    {
                                        std::cout << "Failed MOBI processing: " << e.what() << std::endl;
                                    }

                                }
                                break;
                            }
                        }
                        if (opened || invalid) break;
                    }
                }
                if (invalid&&!mobiProc)
                {
                    std::cout << "Invalid book format, maybe older format?" << std::endl;
                }
                if (mobiProc)
                {
                    std::cout << "Seemingly processed as MOBI " << std::endl;
                }
                std::string kname, vname;
                bool got_meta = false;
                
                if (!invalid && !mobiProc)
                {

                    if (checkDRMIONMeta(params.bookFile, kname, vname) == 0)
                    {
                        got_meta = true;
                    }
                    else
                    {
                        for (const auto& par : params.resources)
                        {
                            if (checkDRMIONMeta(par, kname, vname) == 0)
                            {
                                got_meta = true;
                                break;
                            }
                        }
                    } 
                    if (got_meta)
                    {
                        std::string pkey="";
                        auto f1 = currentKeymaps.keyid_to_key.find(kname);
                        if (f1 != currentKeymaps.keyid_to_key.end())
                        {
                            pkey = f1->second;
                        }
                        auto f2 = currentKeymaps.voucherid_to_key.find(vname);
                        if (f2 != currentKeymaps.voucherid_to_key.end())
                        {
                            pkey = f2->second;
                        }
                        if (!pkey.empty())
                        {
                            currentKeymaps.keyid_to_key[kname] = pkey;
                           // std::cout << "keyid " << kname << std::endl;
                            currentKeymaps.voucherid_to_key[vname] = pkey;
                            acc.keys_128.insert(pkey);
                        }
                    }
                }
                if (!opened && !invalid && !mobiProc)
                {
                    std::cout << "Could not open " << params.bookFile << std::endl;
                   
                }
                if (opened)
                {
                    //std::string output_name = outdir + std::string("\\") + remove_extension(base_name(params.shortBookFile)) + ".kfx-zip";
                    fs::path oname = params.shortBookFile;
                    oname.replace_extension(".kfx-zip");
                    //fs::path(params.shortBookFile.replace_extension(mb.getBookExtension()))
                    fs::path output_path = fs::path(outdir) / oname ;
                    if (fs::exists(output_path))
                    {
                        std::cout << "File " << oname << " already exists in the output folder" << std::endl;
                        std::cout << "Skipping" << std::endl;
                    }
                    else 
                    {
                        BasicDecryptor* decr = nullptr;
                        if (!mbox_saved && params.vouchers.size() == 0)
                        {
                            std::cout << "Found keyless book, packing it for completion" << std::endl;
                            std::vector < uint8_t> key(16);//dummy key

                            decr = (BasicDecryptor*)new AesDecryptor(key);
                        }
                        else 
                        {
                        if (acc.keys_128.size() == 0)
                        {
                            std::cout << "Book opened, but no book keys detected... Trying to use mbox" << std::endl;
                            if (!mbox_saved)
                            {
                                std::cout << "Mbox not saved either... Looks like opening actually failed? " << std::endl;
                                opened = false;
                            }
                            else
                            {
                                if (mbox_bare)
                                {
                                    std::cout << "Using bare/alternate mbox" << std::endl;
                                }
                                else
                                {
                                    std::cout << "Using normal mbox" << std::endl;
                                }
                            }
                            std::cout << "Key will probably not be saved" << std::endl;
                            decr = new MboxDecryptor();
                        }
                        else
                        {
                            std::cout << "Found ("<< acc.keys_128.size() <<") key " << *acc.keys_128.begin() << ", trying to use clear AES" << std::endl;
                            std::vector < uint8_t> key = HexToBytes(*acc.keys_128.begin());

                            decr = (BasicDecryptor*)new AesDecryptor(key);
                        }
                        }
                        if (opened)
                        {
                            std::cout << "Removal result " << std::remove(output_path.string().c_str()) << std::endl; //clear if exists
                            mz_zip_archive arch;
                            mz_zip_error err;
                            if (!mz_open(&arch, output_path, MZ_BEST_COMPRESSION, &err))
                            {
                                std::wcout << output_path << std::endl;
                                printf("Could not open zip file for output: %s \n", mz_zip_get_error_string(err));
                            }
                            else
                            {
                                processFile(&arch, params.bookFile, params.shortBookFile.u8string(), decr);
                                auto it1 = params.resources.begin();
                                auto it2 = params.shortResources.begin();
                                while (it1 != params.resources.end() && it2 != params.shortResources.end())
                                {
                                    processFile(&arch, *it1, it2->u8string(), decr);
                                    ++it1;
                                    ++it2;
                                }
                                if (!mz_close(&arch, &err))
                                {
                                    printf("Could not close  zip file: %s \n", mz_zip_get_error_string(err));
                                }

                            }
                           
                            
                            delete decr;
                        }
                    }

                }

            }

        }

    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);
    //\"device_serial_number\":\"
    std::cout << "Writing keys to file " << out_keyfile << std::endl;
    currentKeymaps.write_file(out_keyfile);
    for (auto& serial : working_serials)
    {
        std::cout << "\"device_serial_number\":\"" << serial << "\"" << std::endl;
    }
    for (auto& secret : working_secrets)
    {
        std::cout << "Working secret: \"" << secret << "\"" << std::endl;
    }

    if (k4ifile)
    {
        std::ofstream k4i(*k4ifile);
        if (k4i)
        {
            std::cout << "Writing DSN and secrets into " << *k4ifile << std::endl;
            nlohmann::json jsn = nlohmann::json();
            int cnt = 0;

            for (auto& serial : working_serials)
            {
                if (cnt < 1)
                {
                    jsn["DSN"] = hexhex(serial);
                    jsn["DSN_clear"] = serial;
                }
                else
                {
                    if (!jsn.contains("extra.dsns"))
                    {
                        jsn["extra.dsns"] = nlohmann::json::array();
                        jsn["extra.dsns_clear"] = nlohmann::json::array();
                    }
                    jsn["extra.dsns"].push_back(hexhex(serial));
                    jsn["extra.dsns_clear"].push_back(serial);
                }
                cnt++;
            }
            cnt = 0;
            for (auto& secret : old_secrets)
            {
                if (cnt < 1)
                {
                    jsn["kindle.account.tokens"] = hexhex(secret);
                }
                else
                {

                    if (!jsn.contains("kindle.account.secrets"))
                    {
                        jsn["kindle.account.secrets"] = nlohmann::json::array();
                    }
                    jsn["kindle.account.secrets"].push_back(hexhex(secret));
                }
                cnt++;
            }
            jsn["kindle.account.new_secrets"] = nlohmann::json::array();
            for (auto s : *secret_candidates)
            {
                jsn["kindle.account.new_secrets"].push_back(s);
            }
            jsn["kindle.account.clear_old_secrets"] = nlohmann::json::array();
            for (auto s : old_secrets)
            {
                jsn["kindle.account.clear_old_secrets"].push_back(s);
            }
            k4i << jsn;
        }

    }

    return;
}


void degenerateCopyFile(const fs::path& f1, const fs::path& f2)
{
    if (f1 == f2) return;
    //std::cout << "Trying to copy " << f1 << " to " << f2 << std::endl;
    std::vector<char> vc = ReadFileToVector(f1);
   // std::cout << "File size  " << vc.size()<< std::endl;
    writeFileBasic(f2, vc);
}
void degenerateCopyNeededFiles(const fs::path& from, const std::vector<std::string>& files, const fs::path& to)
{
    fs::create_directories(to);
    for (auto fl : files)
    {
        //if (!fs::exists(fl))
        //{
         //   std::cout << "File " << fl << " does not exist, skipping?" << std::endl;
        //    continue;
        //}
        degenerateCopyFile(from/fs::path(fl),to/fs::path(fl));
    }
}
std::vector<fs::path> find_valid_subfolders(const fs::path& dir_path) 
{
    std::vector<fs::path> subfolders;

    // Check if the path exists and is actually a directory
    if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
        return subfolders;
    }

    // directory_iterator loops through the top level only (non-recursive)
    for (const auto& entry : fs::directory_iterator(dir_path)) {
        if (entry.is_directory()) {
            if (fs::exists(entry.path()/L"KatxopoApp"/L"dsx120.dll"))
            {
                subfolders.push_back(entry.path());
            }
           
        }
    }

    return subfolders;
}
int wmain(int argc, wchar_t * argv[])
{
    std::map<std::string, ExecOffsets> supportMap;
#if defined(_WIN32) &&!defined(_WIN64)
    supportMap["a03451fe70e83bee2a0e8979667cc2a6"] = KindleReader1_0_15230();
    supportMap["8aa58a484f79ab467ae2a4d2999cc21f"] = KindleReader1_0_16034();
    supportMap["db8035b8f8673ec4c3247161b5f57ded"] = KindleReader1_0_16118();
    supportMap["2b13ee9cf40ebf26f3d14f4987b9b329"] = KindleReader1_0_18320();
    supportMap["a5af62fd27d6cf599575ba0c1c112985"] = KindleReader1_0_18632();
    supportMap["7a7f3827c80e19a4ebda38c2853eb590"] = KindleReader1_0_22326();
    supportMap["5deec17cc97e250f1954a0c4b2c86005"] = KindleReader1_0_22920();
    supportMap["f21b5ad7e1d05d3430cf2eb80cec6c97"] = KindleReader1_0_23514();
    supportMap["c19569a98e72d4e1109e6cfa37db47cf"] = KindleReader1_0_23620();
#endif
#if defined(_WIN64)
    supportMap["e8d7579f15e15451be300021306ef2af"] = KindleReader1_0_25218();
#endif
    
   /*
   * 
                        for (auto& voucher : params.vouchers)
                        {
                            out << remove_extension(base_name(voucher));

                            for (auto& key_128 : acc.keys_128)
                            {
                                out << "$" << "secret_key:" << key_128;
                            }
                            for (auto& key_256 : acc.keys_256)
                            {
                                out << "$" << "shared_key:" << key_256;
                            }
                            out << std::endl;
                        }

   */
    if (argc < 4)
    {
        std::cout << "Usage: executable [kindle documents path (with _EBOK folders)] [output folder] [output k4i file] [folder with dlls(KatxopoApp)] [k4i/keyfile file, k4i/keyfile file...]-> all parameters optional" << std::endl;
        std::cout << "Defaults are, in order, contents folder of the app in %APPDATA%/Local/Packages..etc, archived_kfx for folder and oldbooks.k4i, and books.keyfile for keyfile. Files with keyfile extensions are considered keyfiles, other ones k4i" << std::endl;
        std::cout << "Defaults for folder with dll does not exist/ is installed dir" << std::endl;
        std::cout << "One can use \"default\" to fall back to default value, so don't name your file default, I guess." << std::endl;
        std::cout << "Output folder will be created. Output folder will contain kfx-zips after running, hopefully. Those can be imported with KFX Input plugin into calibre" << std::endl;
        std::cout << "This program searches for Kindle executable in registry, run it from wherever, and it should work. Probably." << std::endl;
        std::cout << "Please ensure that KindleReader UWP app is of the appropriate version (currently KindleReader1_0_15230)" << std::endl;
        std::cout << "In case Kindle version does not match, it would exit, probably" << std::endl;
        std::cout << "Note: to get proper values into k4i file, at least one KFX book that uses account secrets should be downloaded. If resulting k4i has no tokens set, try downloading some free books." << std::endl;
        std::cout << "Note 2: this utility creates a temporary C:\\Data folder, where it copies all the files necessary for its function, including large portion of of the KindleReader app, so about 400MB of space is needed. Folder can be deleted after use." << std::endl;
        std::cout << "As usual, no guarantee, and provide its output if you ask for support." << std::endl;
       // return -1;
    }
    fs::path out_keyfile = fs::path("./books.keyfile");
    bool is_external_folder = false;
    fs::path external_load;
    if (argc >= 5)
    {  
        if(std::wstring(argv[4])!=L"default")
        {
        external_load = fs::path(argv[4]);

        if (!fs::is_regular_file(external_load / L"dsx120.dll"))
        {
            std::cout << "External dll folder given, but it does not have core DLL, aborting: " << (external_load / L"dsx120.dll").string() << " does not exist" <<std::endl;
            return -1;
        }
        is_external_folder = true;
        }
    }
    std::vector<fs::path> extra_k4i;
    std::vector<fs::path> extra_keyfile;
    bool keyfile_res = false;
    if (argc >= 6)
    {
        for (int a = 5; a < argc; a++)
        {
            fs::path ex = fs::path(argv[a]);
            if (ex.extension() == ".keyfile")
            {
                if (!keyfile_res)
                {
                    out_keyfile = ex;
                    keyfile_res = true;
                }
                extra_keyfile.push_back(ex);
            }
            else
            {
                if (fs::is_regular_file(ex))
                {
                    std::cout << "Adding k4i with additional credentials to test " << ex << std::endl;
                    extra_k4i.push_back(ex);
                }
            }

            
        }
    }
    if (extra_keyfile.size() > 0)
    {
        for (const auto& f : extra_keyfile)
        {
            currentKeymaps.read_file(f);
        }
    }
    else
    {
        currentKeymaps.read_file(out_keyfile);
    }
    std::vector<basic_package_data> dat = FindPackagesViaRegistry(L"AmazonKindleReadingApp");
    if (dat.size() == 0&&!is_external_folder)
    {
        std::cout << "No AmazonKindleReadingApp installation found, aborting..." << std::endl;
        return -1;
    }
    for (auto& s : dat)
    {
        if (s.family_name.empty()) s.family_name = GetFamilyNameFromFullName(s.full_name);
        s.install_folder = GetExternalInstallPath(s.full_name.c_str());
        std::wcout << s.full_name << " --> " << s.install_folder << std::endl;
    }
    if (dat.size() >1 )
    {
        std::cout << "Several AmazonKindleReadingApp installations found! Aborting." << std::endl;
        return -1;
    }
    if (dat.size() == 0 && is_external_folder)
    {
        basic_package_data fake_data;
        fake_data.family_name = L"AMZNKindle.AmazonKindleReadingApp_m1sc522ngdk36";
        fake_data.install_folder = external_load.parent_path();
        fake_data.full_name = L"AMZNKindle.AmazonKindleReadingApp_m1sc522ngdk36";
        dat.push_back(fake_data);
         
    }

    PWSTR localcappdata = NULL;
    PWSTR programfiles = NULL;
    const wchar_t* key_suffix = L"LocalCache\\Local\\Microsoft\\Crypto\\PCPKSP\\";
    const wchar_t* amazon_storage = L"LocalState\\Classic\\Data\\storage\\";


    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localcappdata);
    wchar_t old_cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, old_cwd);
    fs::path current_dir = fs::path(old_cwd);
    std::vector<std::string> storage_files = { ".kinf2024", "main_shared.blob", "main_shared.salt","main_shared.blob.sha256"};
    std::vector<std::string> dll_files = { "CFLite.dll", "concrt140_app.dll", "d3dcompiler_47.dll", "dsx120.dll", "hermes.dll", "icudt46.dll", "icudt65.dll", "icuin46.dll", "icuin65.dll", "icuio65.dll", "icuuc46.dll", "icuuc65.dll", "JavaScriptCore.dll", "libcrypto-1_1.dll", "libEGL.dll", "libfsdk_win32.dll", "libGLESv2.dll", "libjpeg.dll", "libpngKRF.dll", "libssl-1_1.dll", "LibWebCore.dll", "libxml2.dll", "Microsoft.ReactNative.dll", "Microsoft.Web.WebView2.Core.dll", "msvcp100.dll", "msvcp120.dll", "msvcp140.dll", "msvcp140_1_app.dll", "msvcp140_2_app.dll", "msvcp140_app.dll", "msvcr100.dll", "msvcr120.dll", "opengl32sw.dll", "Picker.dll", "pthreadVC2.dll", "Qt5Core.dll", "Qt5Gui.dll", 
                                           "Qt5Multimedia.dll", "Qt5MultimediaWidgets.dll", "Qt5Network.dll", "Qt5OpenGL.dll", "Qt5Positioning.dll", "Qt5PrintSupport.dll", 
                                           "Qt5Qml.dll", "Qt5Script.dll", "Qt5Sensors.dll", "Qt5Sql.dll", "Qt5Svg.dll", "Qt5WebChannel.dll", "Qt5WebSockets.dll", "Qt5Widgets.dll", "Qt5WinExtras.dll", "Qt5Xml.dll", "ReactNativeAsyncStorage.dll", "RNSVG.dll", "vcamp140_app.dll", "vccorlib120.dll", "vccorlib140.dll", "vccorlib140_app.dll", "vcomp140_app.dll", "vcruntime140.dll", "vcruntime140_app.dll", "WebCoreViewer.dll", "WebView2Loader.dll", "xrm120.dll", 
                                           "zlib.dll", "zlib1.dll","libpng16.dll","libcrypto-1_1-x64.dll","libfsdk_win64.dll","libssl-1_1-x64.dll","vcruntime140_1_app.dll"};


    // Check if the function call was successful.
    if (!SUCCEEDED(hr))
    {
        std::cerr << "Failed to get the LocalAppData folder path. HRESULT: " << hr << std::endl;
        return 1;
    }
   // SetCurrentDirectoryW(fs::path(localcappdata).root_name().wstring().);
    fs::path data_folder = fs::path(old_cwd).root_name() / L"\\Data";
    fs::path storage = fs::path(localcappdata)  / L"Packages" / dat[0].family_name / fs::path(amazon_storage);
    fs::path reg_data = fs::path(localcappdata) / L"Packages" / dat[0].family_name / L"LocalState\\registration_data";
    fs::path keys_path = fs::path(localcappdata) / L"Packages" / dat[0].family_name / fs::path(key_suffix);
    if (!fs::exists(storage))
    {
        std::cout<<"Kindle storage folder " << storage.string() << " does not appear to exist. Ensure you are logged in. "<<std::endl;
        return -2;
    }
    if (!fs::exists(reg_data))
    {
        std::cout << "Kindle registration_data " << reg_data.string() << " does not appear to exist. Ensure you are logged in. " << std::endl;
        return -2;
    }

    fs::path key_target= fs::path(localcappdata) / fs::path(L"Microsoft\\Crypto\\PCPKSP\\");
    if (!fs::exists(keys_path))
    {
        std::cout << "Kindle keys folder " << keys_path.string() << " does not appear to exist. Ensure that you are logged in. It may also happen if you don't have TPM, so continuing." << std::endl;
    }
    else
    {
        std::cout << "Making key(s) accessible" << std::endl;
        //just in case
       degenerateCopyFile(keys_path / L"d8c37e00045ea5de98d93811f777d227040edd50" / L"4111704e63913bc011faadfaf420c7573b17ac83.PCPKEY", key_target / L"d8c37e00045ea5de98d93811f777d227040edd50" / L"4111704e63913bc011faadfaf420c7573b17ac83.PCPKEY");
        CopyFolderContents(keys_path, key_target);
    }
    std::cout <<"Storage at: " << storage.string() << std::endl;
    std::cout << "Reg data at: " << reg_data.string() << std::endl;
    //CopyFolderContents(storage, data_folder/L"storage");
    degenerateCopyNeededFiles(storage, storage_files, data_folder / L"storage");
    //return 3;
    fs::path output_reg = data_folder / "decrypted_registration_data.dat";
    std::string dsn = decrypt_get_dsn(reg_data,output_reg);

    OverwriteExportTable("ucrtbase.dll", "malloc", (ULONG_PTR)&mallocFake);
    OverwriteExportTable("ucrtbase.dll", "free", (ULONG_PTR)&freeFake);
    OverwriteExportTable("VCRUNTIME140.DLL", "memcpy", (ULONG_PTR)&memcpyFake);
    OverwriteExportTable("ncrypt.dll", "NCryptOpenKey", (ULONG_PTR)&NCryptOpenKeyFake);
    OverwriteExportTable("ncrypt.dll", "NCryptDecrypt", (ULONG_PTR)&NCryptDecryptFake);
    OverwriteExportTable("ncrypt.dll", "NCryptCreatePersistedKey", (ULONG_PTR)&NCryptCreatePersistedKeyFake);
    OverwriteExportTable("ncrypt.dll", "NCryptEncrypt", (ULONG_PTR)&NCryptEncryptFake);
   
    std::wcout << "Copying folder to make it accessible: " << dat[0].install_folder << " --> " << data_folder.wstring() << std::endl;
    if(!is_external_folder)
    {
    degenerateCopyNeededFiles(fs::path(dat[0].install_folder)/ L"KatxopoApp", dll_files, data_folder / dat[0].full_name / L"KatxopoApp");
    }
    else
    {
        std::cout << "Using external folder, not copying" << std::endl;
    }
  //  CopyFolderLegacy(dat[0].install_folder.c_str(), data_folder.wstring().c_str());
    fs::path load_path = data_folder / dat[0].full_name / L"KatxopoApp";
    if (is_external_folder)
    {
        load_path = external_load;
     
    }
    std::wcout << "Trying to move to " << load_path << std::endl;
    BOOL res = SetCurrentDirectoryW(load_path.wstring().c_str());
    if (!res)
    {
        std::wcout << "Move failed..." << std::endl;
        return -3;
    }
    SetDllDirectoryW(load_path.wstring().c_str());
    std::wcout << "Success"  << std::endl;
    
    //debug...

    std::string dllmd5 = CalculateMD5(L"dsx120.dll");
    auto fnd = supportMap.find(dllmd5);
    if (fnd == supportMap.end())
    {
        std::cout << "MD5 of dsx120.dll not in supported map, check your App version (md5:" << dllmd5 << std::endl;
        std::cout << "WARNING:: Attempting to find an older (newest supported) version in " << data_folder << " ::WARNING" << std::endl;
        std::vector<fs::path> vpaths = find_valid_subfolders(data_folder);
        fs::path vp;
        int best = -1;
        for (auto pth : vpaths)
        {
            std::string candidate  = CalculateMD5((pth/ L"KatxopoApp" / L"dsx120.dll").wstring());
            auto fndc = supportMap.find(candidate);
            if (fndc != supportMap.end())
            {
                if (fndc->second.vernum > best)
                {
                    fnd = fndc;
                    best = fndc->second.vernum;
                    vp = pth / L"KatxopoApp";
                }
            }
        }
        if (best < 0)
        {
            std::cout << "Did not find replacement version " << std::endl;
            return -4;
        }
        BOOL res = SetCurrentDirectoryW(vp.wstring().c_str());
        if (!res)
        {
            std::wcout << "Could not move to found dir " <<vp<< std::endl;
            return -3;
        }
        SetDllDirectoryW(vp.wstring().c_str());
        std::wcout << "Moved to " << vp << std::endl;
        std::cout << "WARNING:: Using older version  " << fnd->second.version << " , some books may not decrypt ::WARNING" <<std::endl;
    }
    else
    {
        std::cout << "Detected installed Kindle version " << fnd->second.version << std::endl;
    }
    curOffs = fnd->second;
    HINSTANCE hlq = LoadLibraryA("Qt5Core.dll");
    if (hlq == NULL)
    {
        std::wcout << "Could not load QTCore dll, error " << GetLastError() << std::endl;
        return -3;
    }
    std::vector<char> buffer(MAX_PATH + 1);
    GetModuleFileNameA(hlq, &buffer[0], buffer.size());
    std::cout << "Loaded QT lib from: " << std::string(&buffer[0]) << std::endl;
    HINSTANCE hl = LoadLibraryA("dsx120.dll");
    if (hl == NULL) 
    {
        DWORD errorCode = GetLastError();
        std::cerr << "LoadLibrary of dsx120 failed with error code: " << errorCode << std::endl;
        return -3;
    }
    
    
   
   
    GetModuleFileNameA(hl, &buffer[0], buffer.size());
    std::cout << "Loaded dsx120 lib from: " << std::string(&buffer[0]) <<  std::endl;
    std::wcout << "Trying to move to " << data_folder << std::endl;
    res = SetCurrentDirectoryW(data_folder.wstring().c_str());
    if (!res)
    {
        std::wcout << "Move to data folder failed..." << std::endl;
        return -3;
    }
    void* plucene = GetProcAddress(hl, "?addFontDir@FontSetup@fontaccess@yj@@SAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z");
    printf("Lucene %p\n", plucene);
    if (plucene == NULL)
    {
        std::cout << "Could not find Lucene, aborting." << std::endl;
        return -4;
    }
    INT_PTR  stoffset = (INT_PTR)plucene - curOffs.luceneaddr;
    globoffs = stoffset;
    vpcall MakeKindleInfoStorage = (vpcall)(stoffset + curOffs.make_storage);

    patchAMove();

    void* kinfo = MakeKindleInfoStorage();


    printf("Kindle storage is %p\n", (void*)kinfo);
    if (kinfo == nullptr)
    {
        std::cout << "Could not get storage" << std::endl;
        return -4;
    }
    ///1009c820
    unobfhash uno = (unobfhash)(stoffset + curOffs.deobfuscate_storage);
    QHashData* hdata;
    uno(kinfo, &hdata);
    std::cout << "Storage hdata: "  << hdata->numBuckets << " nodesize: " << hdata->nodeSize <<" amount: "<< hdata->size << std::endl;
    std::map<std::string, std::string> strmap = QHashToMD5Map(hdata);
    std::string strtokens = strmap["495631f2946141093a7e333b85fa1a3d"];
    std::cout << "Going back to cwd " << SetCurrentDirectoryW(current_dir.wstring().c_str()) << std::endl;
    /*toQString toQ = (toQString)GetProcAddress(hlq, "?fromStdString@QString@@SA?AV1@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z");
    fromQString fromQ = (fromQString)GetProcAddress(hlq, "?toStdString@QString@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ");
    if (strtokens.empty())
    {
        std::string tokens = std::string("kindle.metrics.checksum");
        getme getVal = (getme)(stoffset + curOffs.get_storage_value);
        char qtokens[256];
        void* tknz = toQ(qtokens, tokens); //std::string("kindle.account.tokens"));
        char qstbufout[256];
        void* nretout = toQ(qstbufout, std::string(""));
        getVal(kinfo, nretout, tknz);
        fromQ(nretout, strtokens);
        
    }*/
    std::cout << "Secret tokens: "<< strtokens << std::endl;
    if (strtokens.empty())
    {
        std::cout << "Could not get any secrets... Check TPM messages" << std::endl;
        return -5;
    }
    std::vector<std::string> secrets = splitStringBySubstring(strtokens, ",");
    unpatchAMove();

    getPluginManager get_pm = (getPluginManager)(stoffset + curOffs.get_plugin_man);
    loadAllStaticModules load_pm = (loadAllStaticModules)(stoffset + curOffs.load_all);
    void* pm = get_pm();
    std::cout << "PluginManager: " << pm << std::endl;
    load_pm(pm);
    initKrfFunctions(&globalKRFContext);
    fs::path default_book_dir = fs::path(localcappdata) / L"Packages" / dat[0].family_name / L"LocalState" / L"Classic" / L"Content";
    if (argc >= 2)
    {
        if(std::wstring(argv[1])!=L"default")  default_book_dir = current_dir / fs::path(argv[1]);
    }
    fs::path default_output = current_dir / "archived_kfx";
    if (argc >= 3)
    {
        if (std::wstring(argv[2]) != L"default")  default_output = current_dir / fs::path(argv[2]);
    }
    std::cout <<"Book folder "<< default_book_dir << std::endl;

    std::set<std::string> serial_candidates;
    std::set<std::string> secret_candidates;
    serial_candidates.insert(dsn);
    for (auto val : secrets)
    {
        secret_candidates.insert(val);
    }
  
    fs::create_directories(default_output);
    std::cout << "Target output folder: " << default_output << std::endl;
    fs::path k4path = current_dir / "oldbooks.k4i";
  
    if (argc >= 4)
    {
        if (std::wstring(argv[3]) != L"default") k4path = current_dir / fs::path(argv[3]);
    }
    std::string kfile = k4path.string();
    std::cout << "Target k4i file " << kfile << std::endl;
    //Add fake book enumm for secrets
    fs::path fb_path = data_folder / "fb";
    if (extra_k4i.size() > 0)
    {
        for (auto fl : extra_k4i)
        {
            std::vector<char> dat = ReadFileToVector(fl);
            if (dat.size() < 3) continue;
            std::cout << "Parsing " << fl << std::endl;
            try {
                const char* rawJsonStr = reinterpret_cast<const char*>(&dat[0]);

                json data = json::parse(dat.begin(), dat.end());

                // Access properties safely
                std::cout << "k4i JSON successfully parsed!" << std::endl;
                if (data.contains("DSN"))
                {
                    std::string hexdsn = data["DSN"];
                    std::vector<char> deh = HexToBytesC(hexdsn);
                    std::string ldsn(deh.begin(),deh.end());
                    serial_candidates.insert(ldsn);
                    std::cout << "Adding serial candidate " << ldsn << std::endl;
                }
                if (data.contains("DSN_clear"))
                {
                    std::string ldsn = data["DSN_clear"];
                    serial_candidates.insert(ldsn);
                    std::cout << "Adding serial candidate " << ldsn << std::endl;
                }
                if (data.contains("extra.dsns"))
                {
                    for (auto obj : data["extra.dsns"])
                    {
                        std::string hexdsn = obj;
                        std::vector<char> deh = HexToBytesC(hexdsn);
                        std::string ldsn(deh.begin(), deh.end());
                        serial_candidates.insert(ldsn);
                        std::cout << "Adding serial candidate " << ldsn << std::endl;
                    }
                }
                if (data.contains("extra.dsns_clear"))
                {
                    for (auto obj : data["extra.dsns_clear"])
                    {
                        std::string ldsn=obj;
                        serial_candidates.insert(ldsn);
                        std::cout << "Adding serial candidate " << ldsn << std::endl;
                    }
                }
                if (data.contains("kindle.account.tokens"))
                {
                    std::string hextok = data["kindle.account.tokens"];
                    std::vector<char> deh = HexToBytesC(hextok);
                    std::string ltok(deh.begin(), deh.end());
                    secret_candidates.insert(ltok);
                    std::cout << "Adding secret candidate " << ltok << std::endl;
                }
                if (data.contains("kindle.account.secrets"))
                {
                    for (auto obj : data["kindle.account.secrets"])
                    {
                        std::string hextok = obj;
                        std::vector<char> deh = HexToBytesC(hextok);
                        std::string ltok(deh.begin(), deh.end());
                        secret_candidates.insert(ltok);
                        std::cout << "Adding secret candidate " << ltok << std::endl;
                    }
                }
                if (data.contains("kindle.account.new_secrets"))
                {
                    for (auto obj : data["kindle.account.new_secrets"])
                    {
                        std::string ltok=obj;
                        secret_candidates.insert(ltok);
                        std::cout << "Adding secret candidate " << ltok << std::endl;
                    }
                }
                if (data.contains("kindle.account.clear_old_secrets"))
                {
                    for (auto obj : data["kindle.account.clear_old_secrets"])
                    {
                        std::string ltok = obj;
                        secret_candidates.insert(ltok);
                        std::cout << "Adding secret candidate " << ltok << std::endl;
                    }
                }
                
            }
            catch (const json::parse_error& e)
            {
                std::cerr << "Malformed text inside k4i file  " << e.what() << "  " << fl << std::endl;
            }
        }
    }
    enumerateKindleDir(default_book_dir.wstring().c_str(), default_output.string(), &serial_candidates, &secret_candidates, &kfile,fb_path, out_keyfile);
 
    return 0;
}
