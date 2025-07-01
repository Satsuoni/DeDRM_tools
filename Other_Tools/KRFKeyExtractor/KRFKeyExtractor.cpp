///this file must be compiled for 32bit release
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>
#include <functional>
#include <set>
#include <list>
#include <strsafe.h>
#pragma comment(lib, "User32.lib")


/*
* to find Cipher_Init, search for "assertion failed: ctx->cipher->block_size == 1 || ctx->cipher->block_size ==  8 || ctx->cipher->block_size == 16
* and                            "assertion failed: EVP_CIPHER_CTX_iv_length(ctx) <= (int)sizeof(ctx->iv)"
*
* to find evp_EncryptDecryptUpdate, search for assertion failed: bl <= (int)sizeof(ctx->buf)
* 
* Another potential hook is rewriting the handlers of struct evp_cipher_st:
* 
* struct evp_cipher_st {
    int nid;

    int block_size;
    int key_len;
    int iv_len;

    unsigned long flags;
    int origin; //origin might not be present in Kindle version, it is older
    int (*init) (EVP_CIPHER_CTX* ctx, const unsigned char* key,
        const unsigned char* iv, int enc); //should be the replaced function, offset #5 in Kindle
    int (*do_cipher) (EVP_CIPHER_CTX* ctx, unsigned char* out,
        const unsigned char* in, size_t inl);
* 
* to do that, modifying the function that references structure in memory seems to work. Structures, so far, are hardcoded. Modifying structs directly triggers antitampering checks
* ab 01 00 00 10 00 00 00 20 00 00 00 10 00 00 00 for aes256
* a3 01 00 00 10 00 00 00 10 00 00 00 10 00 00 00 for aes128 
* Handler function is shared for both
*/


//addresses extracted from Ghidra, md5 of dll is 22ccc712f186e3f03567e2bec2189d6a
const int getPluginManagerAddress = 0x10029523;
const int evp_Cipher_Init_thunk_address = 0x11637916;// 0x10015cb2;



std::string hexStr(const uint8_t* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}

std::vector<char> HexToBytes(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

typedef void* (__thiscall* drmDataProv)(void*, const std::string& book, const std::list<std::string>& resources, const std::list<std::string>& vouchers);
typedef void(__thiscall* openBook)(void* factory, void* bk, const std::string& name, const void* drmprovider, void* error, const std::list<std::string>& mayberes);
typedef void* (__thiscall* KRFError)(void*);
typedef void* (__cdecl* getBookFactory)();
typedef void* (__thiscall* getPluginManager)();
typedef void(__thiscall* loadAllStaticModules)(void*);

struct krfErr
{
    int code;
    std::string msg;
    char padding[28];
};

int  setThunk(int thunkAddr, int funcaddr)
{
    int* offsetAddr = (int*)(thunkAddr + 1);
    printf("offsetaddr %lx\n", *offsetAddr);
    int oldThunk = *(offsetAddr);
    oldThunk = oldThunk + (thunkAddr + 5);
    int thunkOffset = funcaddr - (thunkAddr + 5);
    DWORD vp = 0;
    VirtualProtect(offsetAddr, 4, PAGE_EXECUTE_READWRITE, &vp);
    *offsetAddr = thunkOffset;
    VirtualProtect(offsetAddr, 4, vp, &vp);
    return oldThunk;
}

struct KrfAccessFunctions
{
    getPluginManager GetPluginManager;
    loadAllStaticModules LoadAllStaticModules;
    drmDataProv DrmDataProvider;
    getBookFactory GetBookFactory;
    openBook OpenBook;

    int base_offset;
    int oldSSLCipherInit = 0;
    int sslThunkAddr = 0;
};

KrfAccessFunctions globalKRFContext;

typedef int(__cdecl* ssl_init)(void* ctx, void* ciper, void* engine, const unsigned char* key, const unsigned char* iv, int enc, uint8_t is_pipeline, const void* p);

struct KeyData
{
    std::set<std::string> keys_128;
    std::set<std::string> keys_256;
    void reset()
    {
        keys_128.clear();
        keys_256.clear();
    }
    void aggregate(KeyData* other)
    {
        if (other == nullptr) return;
        keys_128.insert(other->keys_128.begin(), other->keys_128.end());
        keys_256.insert(other->keys_256.begin(), other->keys_256.end());
    }
};
KeyData keydataAccumulator;
int __cdecl  fakessl_init(int* ctx, int* cipher, void* engine, const unsigned char* key, const unsigned char* iv, int enc, uint8_t is_pipeline, const void* p)
{
    printf("Calling openSSL hook\n");
    int bytes = cipher[2];
    std::string keystr = hexStr(key, bytes);
    std::cout << "Key: (" << bytes*8 <<" bits) "<< keystr << std::endl;
    if (bytes == 16)
    {
        keydataAccumulator.keys_128.insert(keystr);
    }
    if (bytes == 32)
    {
        keydataAccumulator.keys_256.insert(keystr);
    }
    std::cout << "Iv: " << hexStr(iv, 16) << std::endl;
    ssl_init t_init = (ssl_init)globalKRFContext.oldSSLCipherInit;

    int ret = t_init(ctx, cipher, engine, key, iv, enc, is_pipeline, p);
    return ret;
}


void initKrfFunctions(HINSTANCE hinstLib, KrfAccessFunctions* out)
{
    const char* getpluginmanager = "?getPluginManager@PluginManager@Core@KRF@@SAAAV123@XZ";
    const char* loadallstaticmodules = "?loadAllStaticModules@PluginManager@Core@KRF@@QAEXXZ";
    const char* getbookfactory = "?getInstance@BookFactory@Core@KRF@@SAAAV123@XZ";
    const char* openbook = "?openBook@BookFactory@Core@KRF@@QBE?AV?$shared_ptr@VBook@Core@KRF@@@std@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@5@ABVDRMDataProvider@23@AAVError@23@ABV?$list@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@5@@Z";
    const char* drmdataprovider = "??0DRMDataProvider@Core@KRF@@QAE@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV?$list@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@4@1@Z";
    out->GetPluginManager = (getPluginManager)GetProcAddress(hinstLib, getpluginmanager);
    out->LoadAllStaticModules = (loadAllStaticModules)GetProcAddress(hinstLib, loadallstaticmodules);
    out->DrmDataProvider = (drmDataProv)GetProcAddress(hinstLib, drmdataprovider);
    out->GetBookFactory = (getBookFactory)GetProcAddress(hinstLib, getbookfactory);
    out->OpenBook = (openBook)GetProcAddress(hinstLib, openbook);
    out->base_offset = (int)out->GetPluginManager - getPluginManagerAddress;
    
}
void substituteThunk(KrfAccessFunctions* out)
{
    int thunkAddr = out->base_offset + evp_Cipher_Init_thunk_address;
    out->oldSSLCipherInit = setThunk(thunkAddr, (int)&fakessl_init);
    out->sslThunkAddr = thunkAddr;
}
struct DrmParameters
{
    std::string bookFile;
    std::list<std::string> resources;
    std::list<std::string> vouchers;
};

static bool ends_with(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool starts_with(const std::string& str, const std::string& prefix)
{
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

// some extra helper overloads:

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


bool enumerateKindleFolder(TCHAR *path, DrmParameters * out)
{
    if (out == nullptr) return false;
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    std::basic_string<TCHAR> conv = path;// std::basic_string<TCHAR>(path.begin(), path.end());
    std::string shortPath = std::string(conv.begin(),conv.end());
    StringCchCopy(szDir, MAX_PATH, path);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
    hFind = FindFirstFile(szDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    do
    {
        std::basic_string<TCHAR> wfname = ffd.cFileName;
        std::string fname=std::string(wfname.begin(), wfname.end());
        std::string fullname= shortPath + "\\" + fname;
        if (ends_with(fname, ".azw"))
        {
            out->bookFile = fullname;
            std::cout << "Bookname " << fullname << std::endl;
            continue;
        }
        if (ends_with(fname, ".voucher"))
        {
            out->vouchers.push_back(fullname);
            continue;
        }
        if (ends_with(fname, ".res"))
        {
            out->resources.push_back(fullname);
            std::cout << "Resource " << fullname << std::endl;
            continue;
        }
      
    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);
    if (out->bookFile.empty()) return false;
    //if (out->vouchers.size() == 0) return false;
    return true;
    
}


int  tryOpeningBook(KrfAccessFunctions* ctx, const std::string& serial, const std::string& secret, DrmParameters* params,KeyData* out)
{
    keydataAccumulator.reset();
    unsigned int sub[3000];
    memset((void*)sub, 0, sizeof(sub));
    std::list<std::string> secrets;
    secrets.push_back(secret);
    ctx->DrmDataProvider((void*)sub, serial, secrets, params->vouchers);
    void* bookFactory = ctx->GetBookFactory();
    //int rebook[2] = { 0 };
    std::shared_ptr<void*> rebook;
    krfErr err;
    err.code = 0;
    ctx->OpenBook(bookFactory, &rebook, params->bookFile, sub, &err, params->resources);
    std::cout << "BookOpen error " << err.code << " " << err.msg << std::endl;
    if (err.code == 0)
    {
        out->aggregate( &keydataAccumulator);
        //return true;
    }
    //std::cout << rebook[0]<< std::endl;
    if (rebook != nullptr)
    {
        rebook.reset();
    }

    return err.code;
}

void initKRFContext(KrfAccessFunctions* ctx)
{
    void* pluginmanager = ctx->GetPluginManager();
    ctx->LoadAllStaticModules(pluginmanager);
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
std::string hexhex(const std::string& st)
{
    return hexStr((uint8_t*)st.c_str(), st.size());
}
void enumerateKindleDir(const TCHAR* path,const std::string& outfile,std::set<std::string>* serial_candidates, std::set<std::string>* secret_candidates,std::string* k4ifile)
{
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    TCHAR temp[MAX_PATH];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    StringCchCopy(szDir, MAX_PATH, path);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
    hFind = FindFirstFile(szDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        std::cout << "Could not open directory" << std::endl;
        return ;
    }
    std::ofstream out(outfile);
    std::set<std::string> working_serials;
    std::set<std::string> working_secrets;

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
                // a silly optimization
                for (auto& serial : working_serials)
                {
                    for (auto& secret : working_secrets)
                    {
                        int code = tryOpeningBook(&globalKRFContext, serial, secret, &params, &acc);

                        if (code==0)
                        {
                            opened = true;
                            std::cout << "Opened book with reused secret: " << secret << std::endl;
                            break;
                        }
                        if (code == 14)
                        {
                            invalid = true;
                            break;
                        }
                    }
                    if (opened||invalid)break;
                }
                if (!opened&&!invalid)
                {
                    for (auto& serial : *serial_candidates)
                    {
                        for (auto& secret : *secret_candidates)
                        {

                            int code = tryOpeningBook(&globalKRFContext, serial, secret, &params, &acc);
                            if (code == 0)
                            {
                                opened = true;
                                working_serials.insert(serial);
                                working_secrets.insert(secret);
                                std::cout << "Opened book with secret: " << secret<<std::endl;
                                break;
                            }
                            if (code == 14)
                            {
                                invalid = true;
                                break;
                            }
                        }
                        if (opened||invalid)break;
                    }
                }
                if (invalid)
                {
                    std::cout << "Invalid book format, maybe MOBI?" << std::endl;
                }
                if (!opened&&!invalid)
                {
                    std::cout << "Could not open " << params.bookFile<< std::endl;

                }
                if (opened)
                {
                    if (acc.keys_128.size() + acc.keys_256.size() == 0)
                    {
                        std::cout << "Book opened, but no keys detected..." << std::endl;
                    }
                    else
                    {
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
                    }
                }
            }
           
        }
       
    } while (FindNextFile(hFind, &ffd) != 0);
    out.close();
    FindClose(hFind);
    //\"device_serial_number\":\"
    // DSN extra.dsns kindle.account.tokens kindle.account.secrets
    if (k4ifile)
    {
        std::ofstream k4i(*k4ifile);
        if (k4i)
        {
            std::cout << "Writing DSN and secrets into " << *k4ifile << std::endl;
            int nst  = 0;
            k4i << "{";
            for (auto& serial : working_serials)
            {
                switch (nst)
                {
                case 0: {
                    k4i << "\"DSN\": \"" << hexhex(serial) << "\"";
                    nst = 1;
                    }; break;
                case 1: {
                    k4i <<", \"extra.dsns\": [\""<< hexhex(serial)<< "\"";
                    nst = 2;
                }; break;
                default: {
                    k4i << ", \"" << hexhex(serial) << "\"";
                }; break;
                }
              
            }
            if (nst >= 2)
            {

                k4i << "]";
            }
            int kst = 0;
            for (auto& secret : working_secrets)
            {
                if (nst > 0)
                {
                    k4i << ", ";
                    nst = 0;
                }
                switch (kst)
                {
                case 0: {
                    k4i << "\"kindle.account.tokens\": \"" << hexhex(secret) << "\"";
                    kst = 1;
                }; break;
                case 1: {
                    k4i << ", \"kindle.account.secrets\": [\"" << hexhex(secret) << "\"";
                    kst = 2;
                }; break;
                default: {
                    k4i << ", \"" << hexhex(secret) << "\"";
                }; break;
                }
            }
            if (kst > 1)
            {
                k4i << "]";
            }
            k4i << "}";
        }
         
    }
    std::cout << "Note: the below can be copied into text file and used instead of full memory dump. At least one of the secrets is likely to be spurious/incorrect. " << std::endl;
    for (auto& serial : working_serials)
    {
        std::cout << "\"device_serial_number\":\"" << serial <<"\""<< std::endl;
    }
    for (auto& secret : working_secrets)
    {
        std::cout << "Working secret: \"" << secret << "\""<<std::endl;
    }
    
    
    return;
}

class basicSearchPattern
{
public:
    virtual void ingest(char c) = 0;
    virtual bool canStartPattern(char c) = 0;
    virtual  std::set<std::string>* result() = 0;
};
class hexSearchPatternSingle : public basicSearchPattern
{
public:
    struct Index
    {
        bool complete = false;
        bool failed = false;
        bool isReset = true;
        std::vector<char> acc;
        virtual void reset()
        {
            complete = false;
            failed = false;
            isReset = true;
            acc.clear();
        }
    };
    hexSearchPatternSingle(size_t len) :elen(len) { index.isReset = false; };
    virtual bool canStartPattern(char c)
    {
        return isxdigit((int)(unsigned char)c);
    }
    virtual void ingestByIndex(Index* index, char c)
    {
        if (index->isReset || index->complete || index->failed)
        {
            return;
        }
        if (index->acc.size() == elen)
        {
            index->complete = true;
            return;
        }
        if (isxdigit((int)(unsigned char)c))
        {
            index->acc.push_back(c);
            if (index->acc.size() == elen)
            {
                index->complete = true;
            }
            return;
        }
        index->failed = true;
    };
    virtual void ingest(char c)
    {
        ingestByIndex(&index, c);
        if (index.complete)
        {
            results.insert(std::string(index.acc.begin(), index.acc.end()));
            index.reset();
            index.isReset = false;
            return;
        }
        if (index.failed)
        {
            index.reset();
            index.isReset = false;
            return;
        }

    };
    virtual  std::set<std::string>* result()
    {
        return &results;
    };
private:
    Index index;
    size_t elen;
    std::set<std::string> results;
};

class prePostPatternSingle :public  basicSearchPattern
{
public:
    struct Index
    {
        size_t compIndex = 0;
        bool inPrefix = true;
        bool complete = false;
        bool failed = false;
        bool isReset = true;
        std::vector<char> acc;
        void reset()
        {
            compIndex = 0;
            inPrefix = true;
            complete = false;
            failed = false;
            isReset = true;
            acc.clear();
        }
    };

    prePostPatternSingle(const std::string& pre, const std::string& post, size_t maxlen, bool isAlphanum) :pre(pre), post(post), maxLen(maxlen), isAlphanum(isAlphanum)
    {
        if (!pre.empty())
        {
            fr = pre[0];
        }
        index.isReset = false;
    };
    virtual bool canStartPattern(char c)
    {
        if (pre.empty()) return true;
        return c == fr;
    }
    void ingestByIndex(Index* index, char c)
    {
        if (index->isReset || index->complete || index->failed)
        {
            return;
        }
        if (index->inPrefix)
        {
            if (pre.empty())
            {
                index->inPrefix = false;
            }
            else
            {
                if (pre[index->compIndex] == c)
                {
                    index->compIndex++;
                    if (index->compIndex >= pre.size())
                    {
                        index->inPrefix = false;
                        index->compIndex = 0;
                    }
                    return;
                }
                else
                {
                    index->failed = true;
                    return;
                }
            }
        }
        if (post.size() > 0)
        {
            if (index->compIndex > 0) //already in postfix
            {
                if (c != post[index->compIndex])
                {
                    index->failed = true;
                    return;
                }
                index->compIndex++;
                if (index->compIndex >= post.size())
                {
                    index->complete = true;
                }
                return;
            }
            else
            {
                if (c != post[index->compIndex])
                {
                    if (index->acc.size() >= maxLen)
                    {
                        index->failed = true;
                        return;
                    }
                    if (isAlphanum && !isalnum((int)(unsigned char)c))
                    {
                        index->failed = true;
                        return;
                    }
                    index->acc.push_back(c);
                }
                else
                {
                    index->compIndex++;
                    if (index->compIndex >= post.size())
                    {
                        index->complete = true;
                    }
                    return;
                }
            }
        }
    }
    virtual void ingest(char c)
    {
        ingestByIndex(&index, c);
        if (index.complete)
        {
            results.insert(std::string(index.acc.begin(), index.acc.end()));
            index.reset();
            index.isReset = false;
            return;
        }
        if (index.failed)
        {
            index.reset();
            index.isReset = false;
            return;
        }

    };

    virtual  std::set<std::string>* result()
    {
        return &results;
    };

private:
    std::string pre;
    std::string post;
    char fr = 0;
    // std::vector<Index> indices;
    Index index;
    size_t maxLen;
    bool isAlphanum = false;
    std::set<std::string> results;
};
typedef basicSearchPattern* (__stdcall* patternFactory)();
class multipatternSearch
{
public:
    multipatternSearch() {};
    size_t addLane(const std::shared_ptr<basicSearchPattern>& pattern)
    {
        lanes.push_back(pattern);
        return lanes.size() - 1;
    }
    void ingest(char c)
    {
        for (auto& val : lanes)
        {
            val->ingest(c);
        }
    }
    std::set<std::string>* results(size_t index)
    {
        return lanes[index]->result();
    }

private:

    std::vector < std::shared_ptr<basicSearchPattern>> lanes;
};

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        std::cout << "Usage: executable <memdump path> <kindle documents path> <output file> [<output k4i file(optional)>]" << std::endl;
        std::cout << "This program needs accress to Kindle dlls, so it is easiest to run it in the folder with kindle executable or copied dlls" << std::endl;
        std::cout << "Please ensure that KRFDynamic.dll is of the appropriate version (currently md5 22ccc712f186e3f03567e2bec2189d6a, kindle 2.7.1(70978))" << std::endl;
        return 1;
    }
    HINSTANCE hinstLib;
    hinstLib = LoadLibrary(TEXT("KRFDynamic.dll"));
    std::string dump_path = argv[1];
    std::string folder_path = argv[2];
    std::string out_path = argv[3];
    std::cout << folder_path << std:: endl;
    std::string k4;
    std::string* k4file = nullptr;
    if (argc > 4)
    {
        k4 = argv[4];
        k4file = &k4;
    }
    //this is a bit dumb but I don't know of good ways of flipping between char types
    std::basic_string<TCHAR> wfolder_path = std::basic_string<wchar_t>(folder_path.begin(),folder_path.end());
    if (hinstLib)
    {
        initKrfFunctions(hinstLib, &globalKRFContext);
        initKRFContext(&globalKRFContext);
        substituteThunk(&globalKRFContext); //has to go after init;
        // Search for device serial and hex substrings
        std::ifstream memdump(dump_path, std::ios::binary);
        if (!memdump.is_open()) {
            std::cerr << "Error opening dump file: " << dump_path << std::endl;
            return 1;
        }
        std::cout << "Scanning dump file" << std::endl;
        const size_t buffer_size = 1024 * 1024;
        std::vector<char> buffer(buffer_size);
        multipatternSearch search;
        std::shared_ptr<prePostPatternSingle> dsn = std::make_shared<prePostPatternSingle>("\"device_serial_number\":\"", "\"", 60, true);
        std::shared_ptr <hexSearchPatternSingle> hexpat = std::make_shared<hexSearchPatternSingle>(40);
        search.addLane(dsn);
        search.addLane(hexpat);
        while (memdump.read(buffer.data(), buffer_size) || memdump.gcount() > 0) {
            std::streamsize bytes_read = memdump.gcount();
            for (std::streamsize i = 0; i < bytes_read; i++)
            {
                search.ingest(buffer[i]);
            }
        }
        memdump.close();
        std::set<std::string>* serial_candidates = search.results(0);
        std::set<std::string>* secret_candidates = search.results(1);
        if (serial_candidates->size() == 0)
        {
            std::cerr << "Could not find any serial candidates in dump" << std::endl;
            return 1;
        }
        if (secret_candidates->size() == 0)
        {
            std::cerr << "Could not find any client secret candidates in dump" << std::endl;
            return 1;
        }

        ///enumerate folder
        printf(("Trying to open  %s \n"), argv[1]);
        enumerateKindleDir(wfolder_path.data(),out_path, serial_candidates, secret_candidates,k4file);
    }
    else
    {
        std::cerr << "Could not load KRFDynamic.dll" << std::endl;
        return 2;
    }
    
    
}
