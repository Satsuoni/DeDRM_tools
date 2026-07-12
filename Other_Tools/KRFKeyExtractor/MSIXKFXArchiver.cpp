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


#include <cstdint>


int globoffs = 0;
std::vector<char> mboxsave(150000);//119424
bool mbox_saved = false;
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

static std::string hexStr(const uint8_t* data, int len)
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
    if (BCryptHashData(hHash, (PUCHAR)data.data(), data.size(), 0) != 0)
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


std::wstring utf8_to_wide(const std::string& value)
{
    if (value.empty())
    {
        return L"";
    }

    const int size_needed = MultiByteToWideChar(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0
    );

    if (size_needed <= 0)
    {
        return L"";
    }

    std::wstring result(size_needed, L'\0');

    MultiByteToWideChar(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        &result[0],
        size_needed
    );

    return result;
}

std::string wide_to_utf8(const std::wstring& value)
{
    if (value.empty())
    {
        return "";
    }

    const int size_needed = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (size_needed <= 0)
    {
        return "";
    }

    std::string result(size_needed, '\0');

    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        &result[0],
        size_needed,
        nullptr,
        nullptr
    );

    return result;
}

std::string ReadFileToString(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

std::string ReadFileToString(const std::string& filePath) {
    return ReadFileToString(fs::path(filePath));
}

std::vector<char> ReadFileToVector(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cout<<"Could not open" << strerror(errno) << std::endl;
        return std::vector<char>();
    }
    return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}
std::vector<char> ReadFileToVector(const fs::path& filePath) 
{

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Could not open" << strerror(errno) << std::endl;
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
        result |= (v & 0x7F) << bitpos;
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

unsigned char* PC1(const unsigned char* key, unsigned int klen, const unsigned char* src,
    unsigned char* dest, unsigned int len, int decryption)
{
    unsigned int sum1 = 0;
    unsigned int sum2 = 0;
    unsigned int keyXorVal = 0;
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
        int endoff = 0;
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
        int endoff = 0;
        if (section + 1 == num_sections)
        {
            endoff = data_file.size();
        }
        else
        {
            endoff = sections[section + 1].offset;
        }
        int off = sections[section].offset;
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
                            char b = 144;
                            patchSection(0, &b, 1, 16 + mobi_length + pos + 8);
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
            for (int i = 0; i < rec209.size(); i+=5)
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
            b[0] = 0xff;
            b[1] = 0xff;
            b[2] = 0xff;
            b[3] = 0xff;
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

int finIndexIn(const std::vector<std::string>& p, const std::string& val)
{
    for (size_t i = 0; i < p.size(); i++)
    {
        if (p[i] == val) return i;
    }
    return -1;
}

//--------------------------------------------------end ION



struct ExecOffsets
{
    int luceneaddr = 0;
    int make_storage = 0;
    int get_storage_value = 0; 
    int deobfuscate_storage = 0;
    int get_plugin_man = 0;
    int load_all = 0;
    int get_factory = 0;
    int open_book = 0;
    int drm_provider = 0;
    //int mem_offset = 0;
    int decr_offset = 0;
   // int mbox_capture = 0;
    int entry = 0;
    int mbox_size = 0;
    int mbox_iv_offset = 0;
    int allemaric_shift=0;
    int spatch = 0;
    std::string version = "unk ";
    int vernum = -1;
};

ExecOffsets curOffs;
ExecOffsets KindleReader1_0_15230()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x11046bb0;
    ret.entry = 0;

    ret.make_storage = 0x10dbf3c0;
    ret.deobfuscate_storage= 0x1009b8d0;

    ret.get_storage_value = 0x1009c820;

    ret.spatch= 0x10065a60;
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
    ret.spatch = 0x10065a60;
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
    ret.spatch = 0x10065a60;
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
    ret.spatch = 0x10065a60;
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
    ret.spatch = 0x10065a60;
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


bool OverwriteExportTable(LPCSTR module,const char* name, ULONG_PTR replacement)
{
    // 1. Get base handle of loaded ntdll
    HMODULE hNtdll = GetModuleHandleA(module);
    if (!hNtdll) return false;

    BYTE* baseAddress = reinterpret_cast<BYTE*>(hNtdll);

    // 2. Parse PE Headers
    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    // 3. Locate Export Directory
    IMAGE_DATA_DIRECTORY exportDataDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
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

        if (strcmp(exportName, name ) == 0)
        {
            printf("Found %s \n",name);
            // Resolve the function index via its Name Ordinal array slot
            WORD ordinalIndex = pAddressOfNameOrdinals[i];

            // Extract the original Relative Virtual Address (RVA)
            DWORD originalRVA = pAddressOfFunctions[ordinalIndex];

            // Save the absolute pointer so our detour function can call it natively later
            g_OriginalLdrLoadDllAddress = reinterpret_cast<LdrLoadDll_t>(baseAddress + originalRVA);

            // 6. Calculate the custom target hook RVA
            // RVA = (Target Absolute Address) - (Module Base Address)
            ULONG_PTR hookAbsoluteAddress = (replacement);
            ULONG_PTR baseAbsoluteAddress = reinterpret_cast<ULONG_PTR>(baseAddress);

            ULONG_PTR targetHookRVA = hookAbsoluteAddress - baseAbsoluteAddress;

            // 7. Verify the RVA safely fits within standard 32-bit offset limits
            if (targetHookRVA > 0xFFFFFFFF) {
                // If your module hook is allocated too far away from ntdll memory space,
                // a 32-bit RVA calculation will overflow.
                std::cout << "[-] Error: Hook function is too far away from ntdll address space." << std::endl;
                return false;
            }

            // 8. Swap the values safely in the EAT array page
            DWORD oldProtect = 0;
            DWORD* targetAddressSlot = &pAddressOfFunctions[ordinalIndex];

            if (VirtualProtect(targetAddressSlot, sizeof(DWORD), PAGE_READWRITE, &oldProtect))
            {
                *targetAddressSlot = static_cast<DWORD>(targetHookRVA);
                printf("TargetHookRVA %x\n", targetHookRVA);
                VirtualProtect(targetAddressSlot, sizeof(DWORD), oldProtect, &oldProtect);

                // Refresh execution sync
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
        std::cout << "Frame [" << i << "]: 0x" << std::hex << stackFrames[i] << "  " << (int)stackFrames[i]-globoffs<< std::endl;
    }
}

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
void* memsetFake(void* dst, int val,size_t sz)
{
   // std::cout << "Badnaughty " <<sz<< "  "<<dst<< std::endl;
    if (dst == narm||sz== curOffs.mbox_size)
    {
        std::cout << "Extrabad " << std::endl;
        PrintSimpleCallStack();
        if (!mbox_saved)
        {
            mboxsave.resize(curOffs.mbox_size);
            memcpy(&mboxsave[0], (void*)((int)dst + curOffs.allemaric_shift), curOffs.mbox_size);
            mbox_saved = true;
        }
        std::cout << hexStr((uint8_t*)dst, 119212) << std::endl;
    }
   return  memset(dst, val, sz);
}


void* mallocFake(size_t s)
{
    void* ret = malloc(s);
    if (armed)
    {
       // printf("Allocated %d at %p\n", s, ret);
        allocations[ret] = s;
        if (narm != nullptr)
        {
      
            if (!mbox_saved)
            {
                mboxsave.resize(curOffs.mbox_size);
                memcpy(&mboxsave[0], (void*)((int)narm+curOffs.allemaric_shift), curOffs.mbox_size);
                mbox_saved = true;
            }
           //std::cout << hexStr((uint8_t*)narm, curOffs.mbox_size) << std::endl;
            narm = nullptr;
         
        }

        if (s == curOffs.mbox_size)
        {
            narm = ret;
        }
    }
   
    return ret;
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
                }

            }
        }
        if (fsize > 0)
        {
          //  printf("Freeing %d at %p\n", fsize,p);
          //  std::cout << hexStr((uint8_t*)p, fsize) << std::endl;
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
       // std::cout << "Caught memcpy of " << sz << "("<<allocations[src]<<") bytes, from " << src << " to " << dst <<"("<<allocations[dst]<<")"<< std::endl;
        if (allhex((uint8_t*)src, sz)&&sz>10)
        {
            //std::cout << "Allhex!" << std::endl;
            if (sz == 31 && allocations[dst] == 48)
            {

               // std::cout << hexStr((uint8_t*)dst, 48) << std::endl;
                seccan =(uint8_t*) dst;
               // PrintSimpleCallStack();
            }
        }
        //std::cout << hexStr((uint8_t*)src, sz) << std::endl;
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
BYTE unpatchBytes[5];
bool PatchWithMovAxRet() {

    BYTE* targetAddress = reinterpret_cast<BYTE*>(curOffs.spatch+globoffs);
    DWORD oldProtect;

    // Raw instruction bytes: 
    // 66 B8 01 00 = mov ax, 0x1
    // C3          = ret
    BYTE patchBytes[5] = {0x66, 0xB8, 0x01, 0x00, 0xC3};
    size_t patchSize = sizeof(patchBytes);

    // 2. Modify memory page rights to read/write/execute
    if (VirtualProtect(targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // 3. Apply the 5-byte instruction override sequence
        memcpy(unpatchBytes, targetAddress, patchSize);
        memcpy(targetAddress, patchBytes, patchSize);

        // 4. Restore original system memory protection states
        VirtualProtect(targetAddress, patchSize, oldProtect, &oldProtect);

        // 5. Clear CPU pipeline cache to prevent execution misalignment
        FlushInstructionCache(GetCurrentProcess(), targetAddress, patchSize);

        std::cout << "[+] Successfully patched spatch" << std::endl;// with mov ax, 1; ret
        return true;
    }

    std::cout << "[-] VirtualProtect failed. Error code: " << GetLastError() << std::endl;
    return false;
}

bool UnpatchWithMovAxRet() {
    // 1. Identify target address location
    BYTE* targetAddress = reinterpret_cast<BYTE*>(curOffs.spatch + globoffs);
    DWORD oldProtect;
    size_t patchSize = sizeof(unpatchBytes);

    // 2. Modify memory page rights to read/write/execute
    if (VirtualProtect(targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {

        // 3. Apply the 5-byte instruction override sequence
 
        memcpy(targetAddress, unpatchBytes, patchSize);

        // 4. Restore original system memory protection states
        VirtualProtect(targetAddress, patchSize, oldProtect, &oldProtect);

        // 5. Clear CPU pipeline cache to prevent execution misalignment
        FlushInstructionCache(GetCurrentProcess(), targetAddress, patchSize);

        std::cout << "[+] Successfully unpatched spatch" << std::endl;
        return true;
    }

    std::cout << "[-] VirtualProtect failed. Error code: " << GetLastError() << std::endl;
    return false;
}

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
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(pSecDesc, SDDL_REVISION_1, secInfo, &pszSddl, NULL)) {
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
    printf("Enc key: %p cbinput %d\n", hKey, cbInput);
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
    int offset; // Distance in bytes from this struct to the wchar_t array
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
         std::cout << hexStr((uint8_t*)((int)arr->d+arr->d->offset), arr->d->size) << std::endl;
         std::string st((char*)((int)arr->d + arr->d->offset), arr->d->size);
         std::cout << st << std::endl;
       //  PrintSimpleCallStack();
         return ret;
    }
    void* __thiscall HookedQByte(void* qb) {
        std::cout << "Hooked Qb1, string " << this << std::endl;
        void* ret = correctQbyte(this, qb);
        QBArray* arr = (QBArray*)ret;
        std::cout << "Hookv alloc " << arr->d->alloc <<" len " << arr->d->size << std::endl;
        std::cout << hexStr((uint8_t*)((int)arr->d + arr->d->offset), arr->d->size) << std::endl;
        std::string st((char*)((int)arr->d + arr->d->offset), arr->d->size);
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
        int base_heap_ptr = strObj->control_block[2];
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
        while (currentNode != nullptr) 
        {
            // Cast the generic DataNode to our specific QString-pair Node layout
            QHashNode_QString_QString* dataNode = reinterpret_cast<QHashNode_QString_QString*>(currentNode);
            if (currentNode->next != nullptr)
            {
                QBArray* arr = (QBArray*)&dataNode->key;
                std::string md5 = hexStr((uint8_t*)((int)arr->d + arr->d->offset), arr->d->size);

                arr = (QBArray*)&dataNode->value;
                std::string st((char*)((int)arr->d + arr->d->offset), arr->d->size);
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

std::list<std::string> splitStringBySubstring(const std::string& str, const std::string& delimiter)
{
    std::list<std::string> result;
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

#pragma comment(lib, "userenv.lib")

void GetExternalDataPath(const wchar_t* packageFamilyName) {
    PWSTR pathString = nullptr;

    // Retrieves the Local AppData root path for the specified package container
    HRESULT hr = GetAppContainerFolderPath(packageFamilyName, &pathString);

    if (SUCCEEDED(hr)) {
        std::wstring baseDataPath(pathString);
        CoTaskMemFree(pathString); // Clean up allocated buffer

        // Append target subfolder where app data files live
        std::wstring localStatePath = baseDataPath + L"\\LocalState";
        std::wcout << L"AppData Path: " << localStatePath << std::endl;
    }
    else {
        std::cout << "Failed to resolve AppContainer data path. HRESULT: " << hr << std::endl;
    }
}

bool CopyFolderLegacy(const wchar_t* srcPath, const wchar_t* destPath) {
    // Paths must be double-null terminated
    wchar_t fromPath[MAX_PATH + 2] = { 0 };
    wchar_t toPath[MAX_PATH + 2] = { 0 };

    wcscpy_s(fromPath, MAX_PATH, srcPath);
    wcscpy_s(toPath, MAX_PATH, destPath);

    SHFILEOPSTRUCT fileOp = { 0 };
    fileOp.wFunc = FO_COPY;
    fileOp.pFrom = fromPath; // Source folder path
    fileOp.pTo = toPath;     // Destination folder path
    fileOp.fFlags = FOF_NOCONFIRMMKDIR| FOF_NOCONFIRMATION; // Automatically create destination folder

    int result = SHFileOperation(&fileOp);
    return (result == 0);
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
    std::string ret=ParseDecryptedTextBlob(decryptedBlob);
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


char* read_file(const std::string& filename, size_t& size)
{
    const std::wstring wide_filename = utf8_to_wide(filename);
    FILE* fp = _wfopen(wide_filename.c_str(), L"rb");
    if (fp == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    if (fseek(fp, 0L, SEEK_END) != 0)
    {
        fclose(fp);
        perror("Error seeking file end");
        return NULL;
    }

    long long bufsize = _ftelli64(fp);
    if (bufsize == -1)
    {
        fclose(fp);
        perror("Error getting file size");
        return NULL;
    }
    if (bufsize == 0)
    {
        return nullptr;
    }
    fseek(fp, 0L, SEEK_SET);
    char* buffer = (char*)malloc(bufsize);
    if (buffer == nullptr)
    {
        return NULL;
    }
    size_t len = fread(buffer, 1, bufsize, fp);
    if (len == 0 || ferror(fp) != 0)
    {
        fclose(fp);
        free(buffer);
        perror("Error reading file");
        return NULL;
    }
    fclose(fp);
    size = len;
    return buffer;
}

class BasicDecryptor
{
public:
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out) = 0;
};
class MboxDecryptor : public BasicDecryptor
{
public:
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out)
    {
        if (!mbox_saved)
        {
            printf("Mbox not saved, decryption failed!");
        }
        char* mbox_address = &mboxsave[0];
        typedef void(__cdecl* aes_decrypt_call)(void* mbbox_1, unsigned char* input_ciphertext_2, unsigned int chunk_len_3, unsigned char* output_4, unsigned int* alllocated_len_ptr_5);
        aes_decrypt_call callme = (aes_decrypt_call)(globoffs + curOffs.decr_offset);
        //set iv
       //memcpy(mbox_address + 0x749c * 4, &iv[0], iv.size());
        memcpy(mbox_address + curOffs.mbox_iv_offset, &iv[0], iv.size());

        out.resize(ciphertext.size());
        unsigned int sz = out.size();
        callme(mbox_address, &ciphertext[0], ciphertext.size(), &out[0], &sz);
       // std::cout << "Decr data " << hexStr(&out[0], out.size()) << std::endl;
       // exit(0);
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
        //while (1) {}
    }
};
class AesDecryptor : public BasicDecryptor
{
public:
    std::vector<uint8_t> key;
    AesDecryptor(const std::vector<uint8_t>& k) :key(k) {}
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out)
    {
        if (iv.size() != 16)
        {
            printf("Unsupported IV size %ld\n", iv.size());
            out.resize(0);
            return;
        }
        out.resize(ciphertext.size());
        unsigned long padded_size = 0;
        plusaes::decrypt_cbc(&ciphertext[0], ciphertext.size(), &key[0], key.size(), (unsigned char (*)[16]) & iv[0], &out[0], out.size(), &padded_size);
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
    while (true)
    {
        if (bp.gettypename() == "enddoc") break;

        bp.stepin();

        while (bp.hasnext())
        {
            bp.next();
            std::string nm = bp.gettypename();
            // printf("Typename %s\n",nm.c_str());
            if (nm == "com.amazon.drm.EncryptedPage@1.0" || nm == "com.amazon.drm.EncryptedPage@2.0")
            {
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


static bool ends_with(const std::string& str, const char* suffix, unsigned suffixLen)
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
    std::string bookFile;
    std::string shortBookFile;

    std::list<std::string> resources;
    std::list<std::string> shortResources;

    std::list<std::string> vouchers;
};

bool enumerateKindleFolder(const TCHAR* path, DrmParameters* out)
{
    if (out == nullptr)
    {
        return false;
    }

    WIN32_FIND_DATA ffd;
    TCHAR szDir[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;

    const fs::path folder_path(path);

    StringCchCopy(szDir, MAX_PATH, path);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

    hFind = FindFirstFile(szDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    do
    {
        const fs::path file_name(ffd.cFileName);
        const fs::path full_path = folder_path / file_name;

        const std::string file_name_utf8 =
            wide_to_utf8(file_name.wstring());

        const std::string full_path_utf8 =
            wide_to_utf8(full_path.wstring());

        if (ends_with(file_name_utf8, ".azw"))
        {
            out->bookFile = full_path_utf8;
            out->shortBookFile = file_name_utf8;
            continue;
        }

        if (ends_with(file_name_utf8, ".voucher"))
        {
            out->vouchers.push_back(full_path_utf8);
            continue;
        }

        if (ends_with(file_name_utf8, ".res") ||
            ends_with(file_name_utf8, ".md"))
        {
            out->resources.push_back(full_path_utf8);
            out->shortResources.push_back(file_name_utf8);
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
    ctx->DrmDataProvider((void*)sub, serial, secrets, params->vouchers);
    void* bookFactory = ctx->GetBookFactory();
    std::shared_ptr<void*> rebook;
    krfErr err;
    err.code = 0;
    armed = true;
    ctx->OpenBook(bookFactory, &rebook, params->bookFile, sub, &err, params->resources);
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
    for (auto& secret : *secret_candidates)
    {
        keydataAccumulator.reset();
        unsigned int sub[3000];
        memset((void*)sub, 0, sizeof(sub));
        std::list<std::string> secrets;
        secrets.push_back(secret);
        ctx->DrmDataProvider((void*)sub, serial, secrets, params->vouchers);
        void* bookFactory = ctx->GetBookFactory();
        std::shared_ptr<void*> rebook;
        krfErr err;
        err.code = 0;
        armed = true;
        ctx->OpenBook(bookFactory, &rebook, params->bookFile, sub, &err, params->resources);
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

int processFile(const char* outputFile, const std::string& fname, const std::string& archivedName, BasicDecryptor* decr)
{

    size_t bl = 0;
    char* buf = read_file(fname, bl);
    printf("Read file of %lu bytes\n", bl);
    if (bl == 0)
    {
        return 0;
    }
    if (buf == nullptr)
    {
        printf("Could not read file? \n");
        return 1;
    }
    if (bl > drmionHeader.size() && memcmp(&drmionHeader[0], buf, drmionHeader.size()) == 0)
    {
        std::vector<uint8_t> outme;
        printf("Decrypting DRMION... \n");
        if (processDRMION(&buf[8], bl - 16, decr, outme))
        {
            mz_bool status = mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), outme.data(), outme.size(), NULL, 0, MZ_BEST_COMPRESSION);
            if (!status)
            {
                printf("mz_zip_add_mem_to_archive_file_in_place of DRMION file  failed!\n");
                free(buf);
                return EXIT_FAILURE;
            }
            printf("DRMION decrypted and saved.\n");
        }
        else
        {
            printf("Could not decrypt DRMION? \n");
            free(buf);
            return 2;
        }
    }
    else
    {
      //  mz_zip_add_mem_to_archive_file_in_place_v2(pZip_filename, pArchive_name, pBuf, buf_size, pComment, comment_size, level_and_flags, NULL);
        mz_zip_error err;
        mz_bool status = mz_zip_add_mem_to_archive_file_in_place_v2(outputFile, archivedName.c_str(), buf, bl, NULL, 0, MZ_BEST_COMPRESSION,&err);
        if (!status)
        {
            printf("mz_zip_add_mem_to_archive_file_in_place of non-DRM file failed for %s! Error: %s \n", archivedName.c_str(), mz_zip_get_error_string(err));
            free(buf);
            return EXIT_FAILURE;
        }
    }

    free(buf);
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

void enumerateKindleDir(const TCHAR* path, const std::string& outdir, std::set<std::string>* serial_candidates, std::set<std::string>* secret_candidates, std::string* k4ifile,const fs::path& fbook)
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
        fs::path fb_path_v = fbook / "fake.voucher";
        fs::path fb_path_a = fbook / "fake.azw";
        write_vector_to_file(fb_path_v, fake);
        write_vector_to_file(fb_path_a, drmionHeader);
        DrmParameters params;
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
    }
    do
    {

        if (IsDotOrDotDot(ffd.cFileName)) continue;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            _tprintf(TEXT("Trying to open  %s \n"), ffd.cFileName);
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
                                    fs::path out_path = fs::path(outdir) / fs::path(remove_extension(base_name(params.shortBookFile)) + mb.getBookExtension());
                                    if (fs::exists(out_path))
                                    {
                                        std::cout << "File " << fs::path(remove_extension(base_name(params.shortBookFile)) + mb.getBookExtension()) << " already exists in the output folder" << std::endl;
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
                                        fs::path out_path = fs::path(outdir) / fs::path(remove_extension(base_name(params.shortBookFile)) + mb.getBookExtension());
                                        if (fs::exists(out_path))
                                        {
                                            std::cout << "File " << fs::path(remove_extension(base_name(params.shortBookFile)) + mb.getBookExtension()) << " already exists in the output folder" << std::endl;
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
                if (!opened && !invalid && !mobiProc)
                {
                    std::cout << "Could not open " << params.bookFile << std::endl;

                }
                if (opened)
                {
                    //std::string output_name = outdir + std::string("\\") + remove_extension(base_name(params.shortBookFile)) + ".kfx-zip";
                    fs::path oname = fs::path(remove_extension(base_name(params.shortBookFile)) + ".kfx-zip");
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
                            decr = new MboxDecryptor();
                        }
                        else
                        {
                            std::cout << "Found key " << *acc.keys_128.begin() << ", trying to use clear AES" << std::endl;
                            std::vector < uint8_t> key = HexToBytes(*acc.keys_128.begin());

                            decr = (BasicDecryptor*)new AesDecryptor(key);
                        }
                        }
                        if (opened)
                        {
                            std::cout << "Removal result " << std::remove(output_path.string().c_str()) << std::endl; //clear if exists
                            processFile(output_path.string().c_str(), params.bookFile, params.shortBookFile, decr);
                            auto it1 = params.resources.begin();
                            auto it2 = params.shortResources.begin();
                            while (it1 != params.resources.end() && it2 != params.shortResources.end())
                            {
                                processFile(output_path.string().c_str(), *it1, *it2, decr);
                                ++it1;
                                ++it2;
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
int main(int argc, char* argv[])
{
    std::map<std::string, ExecOffsets> supportMap;
    supportMap["a03451fe70e83bee2a0e8979667cc2a6"] = KindleReader1_0_15230();
    supportMap["8aa58a484f79ab467ae2a4d2999cc21f"] = KindleReader1_0_16034();
    supportMap["db8035b8f8673ec4c3247161b5f57ded"] = KindleReader1_0_16118();
    supportMap["2b13ee9cf40ebf26f3d14f4987b9b329"] = KindleReader1_0_18320();
    supportMap["a5af62fd27d6cf599575ba0c1c112985"] = KindleReader1_0_18632();


    if (argc < 4)
    {
        std::cout << "Usage: executable [kindle documents path (with _EBOK folders)] [output folder] [output k4i file] [folder with dlls(KatxopoApp)] [k4i file, k4i file...]-> all parameters optional" << std::endl;
        std::cout << "Defaults are, in order, contents folder of the app in %APPDATA%/Local/Packages..etc, archived_kfx for folder and oldbooks.k4i" << std::endl;
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
    bool is_external_folder = false;
    fs::path external_load;
    if (argc >= 5)
    {  
        if(std::string(argv[4])!="default")
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
    if (argc >= 6)
    {
        for (int a = 5; a < argc; a++)
        {
            fs::path ex = fs::path(argv[a]);
            if (fs::is_regular_file(ex))
            {
                std::cout << "Adding k4i with additional credentials to test " << ex << std::endl;
                extra_k4i.push_back(ex);
            }
            
        }
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
    std::vector<std::string> dll_files = { "CFLite.dll", "concrt140_app.dll", "d3dcompiler_47.dll", "dsx120.dll", "hermes.dll", "icudt46.dll", "icudt65.dll", "icuin46.dll", "icuin65.dll", "icuio65.dll", "icuuc46.dll", "icuuc65.dll", "JavaScriptCore.dll", "libcrypto-1_1.dll", "libEGL.dll", "libfsdk_win32.dll", "libGLESv2.dll", "libjpeg.dll", "libpngKRF.dll", "libssl-1_1.dll", "LibWebCore.dll", "libxml2.dll", "Microsoft.ReactNative.dll", "Microsoft.Web.WebView2.Core.dll", "msvcp100.dll", "msvcp120.dll", "msvcp140.dll", "msvcp140_1_app.dll", "msvcp140_2_app.dll", "msvcp140_app.dll", "msvcr100.dll", "msvcr120.dll", "opengl32sw.dll", "Picker.dll", "pthreadVC2.dll", "Qt5Core.dll", "Qt5Gui.dll", "Qt5Multimedia.dll", "Qt5MultimediaWidgets.dll", "Qt5Network.dll", "Qt5OpenGL.dll", "Qt5Positioning.dll", "Qt5PrintSupport.dll", "Qt5Qml.dll", "Qt5Script.dll", "Qt5Sensors.dll", "Qt5Sql.dll", "Qt5Svg.dll", "Qt5WebChannel.dll", "Qt5WebSockets.dll", "Qt5Widgets.dll", "Qt5WinExtras.dll", "Qt5Xml.dll", "ReactNativeAsyncStorage.dll", "RNSVG.dll", "vcamp140_app.dll", "vccorlib120.dll", "vccorlib140.dll", "vccorlib140_app.dll", "vcomp140_app.dll", "vcruntime140.dll", "vcruntime140_app.dll", "WebCoreViewer.dll", "WebView2Loader.dll", "xrm120.dll", "zlib.dll", "zlib1.dll" };

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
    /*
    correctLatin1 = (fakeQLatin1)GetProcAddress(hlq, "?toLatin1@QString@@QGBE?AVQByteArray@@XZ");
    correctQbyte = (fakeQbyte)GetProcAddress(hlq, "??0QByteArray@@QAE@ABV0@@Z");
    union {
        void* (HookHandlerLatin1::* memberFn)(void*);

        void* rawAddress;
    } converterl;

    // 2. Assign the member function pointer
    converterl.memberFn = &HookHandlerLatin1::HookedFunction;
    // 3. Extract the raw memory address
    void* newHook = converterl.rawAddress;
    OverwriteExportTable("Qt5Core.dll", "?toLatin1@QString@@QGBE?AVQByteArray@@XZ", (ULONG_PTR)newHook);*/
    /// end debug

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
    std::cout << "Going back to cwd " << SetCurrentDirectoryW(current_dir.wstring().c_str())<<std::endl;
    void* plucene = GetProcAddress(hl, "?addFontDir@FontSetup@fontaccess@yj@@SAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z");
    printf("Lucene %p\n", plucene);
    if (plucene == NULL)
    {
        std::cout << "Could not find Lucene, aborting." << std::endl;
        return -4;
    }
    int stoffset = (int)plucene - curOffs.luceneaddr;
    globoffs = stoffset;
    vpcall MakeKindleInfoStorage = (vpcall)(stoffset + curOffs.make_storage);
    PatchWithMovAxRet();
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
    std::list<std::string> secrets = splitStringBySubstring(strtokens, ",");
    UnpatchWithMovAxRet();
    getPluginManager get_pm = (getPluginManager)(stoffset + curOffs.get_plugin_man);
    loadAllStaticModules load_pm = (loadAllStaticModules)(stoffset + curOffs.load_all);
    void* pm = get_pm();
    std::cout << "PluginManager: " << pm << std::endl;
    load_pm(pm);
    initKrfFunctions(&globalKRFContext);
    fs::path default_book_dir = fs::path(localcappdata) / L"Packages" / dat[0].family_name / L"LocalState" / L"Classic" / L"Content";
    if (argc >= 2)
    {
        if(std::string(argv[1])!="default")  default_book_dir = current_dir / fs::path(argv[1]);
    }
    fs::path default_output = current_dir / "archived_kfx";
    if (argc >= 3)
    {
        if (std::string(argv[2]) != "default")  default_output = current_dir / fs::path(argv[2]);
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
        if (std::string(argv[3]) != "default") k4path = current_dir / fs::path(argv[3]);
    }
    std::string kfile = k4path.string();
    std::cout << "Target k4i file" << kfile << std::endl;
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
    enumerateKindleDir(default_book_dir.wstring().c_str(), default_output.string(), &serial_candidates, &secret_candidates, &kfile,fb_path);
 
    return 0;
}
