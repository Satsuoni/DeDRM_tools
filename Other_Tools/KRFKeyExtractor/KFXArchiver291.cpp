#include <iostream>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <DbgHelp.h>
#include <thread>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <shlobj_core.h>
#include <Shlwapi.h> 
#include <strsafe.h>
#include <ctype.h>
#include "json.hpp" //https://github.com/nlohmann/json/releases
#include "miniz.h" //https://github.com/richgel999/miniz/releases
#define POCKETLZMA_LZMA_C_DEFINE
#include "pocketlzma.hpp"
#include "plusaes.hpp"//https://github.com/kkAyataka/plusaes/releases

#pragma comment(lib, "User32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")


std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}


int stoffset = 0; //global base offset for loaded library

struct ExecOffsets
{
     int luceneaddr =0;
     int initterm_e_start = 0;
     int initterm_e_end = 0;
     int tls_reset = 0;
     int initterm_start = 0;
     int initterm_end = 0;
     int make_storage = 0;
     int get_storage_value = 0; //storageTable#3 - to check
     int get_plugin_man = 0;
     int load_all = 0;
     int get_factory = 0;
     int open_book = 0;
     int drm_provider = 0;
     int mem_offset = 0;
     int decr_offset = 0;
     int mbox_capture = 0;
     int entry = 0;
     int mbox_size = 0;
     int mbox_iv_offset = 0;
     std::string version="";
};

ExecOffsets curOffs;
ExecOffsets Kindle291()
{
    ExecOffsets ret;
    ret.luceneaddr = 0;
    ret.entry = 0x00002532b9c;

    ret.initterm_e_start = 0x00002add700;
    ret.initterm_e_end = 0x0002add718; 

    ret.tls_reset = 0x0253222f;
    ret.initterm_start = 0x002a9a160;
    ret.initterm_end = 0x002add6fc;       

    ret.make_storage = 0x01386d90;
    ret.get_storage_value = 0x04b8c80;

    ret.get_plugin_man = 0x017c42b0;
    ret.load_all = 0x0017c43b0;

    ret.get_factory = 0x0017c3830;
    ret.open_book = 0x017c3990;
    ret.drm_provider = 0x017c3cd0;
    ret.mem_offset = 20;

    ret.decr_offset = 0x020f54f0;
    ret.mbox_capture = 0x20ee50d;

    ret.mbox_size = 119208;
    ret.mbox_iv_offset = 0x1d180;
    ret.version = "Kindle 2.9.1(71006)";
    return ret;
}

ExecOffsets Kindle290()
{
    ExecOffsets ret;
    ret.luceneaddr = 0;
    ret.entry = 0x000252ea5c;
    ret.initterm_e_start = 0x0002ad96f8; 
    ret.initterm_e_end = 0x0002ad9710;

    ret.tls_reset = 0x252e0ef;
    ret.initterm_start = 0x02a9615c; 
    ret.initterm_end = 0x02ad96f4;
    ret.make_storage = 0x01382a80;
    ret.get_storage_value = 0x004b8c80;
    ret.get_plugin_man = 0x017c00c0;
    ret.load_all = 0x017c01c0;

    ret.get_factory = 0x017bf640;
    ret.open_book = 0x017bf7a0;
    ret.drm_provider = 0x017bfae0;
    ret.mem_offset = 20;

    ret.decr_offset = 0x20f1310;
    ret.mbox_capture = 0x20f13d0;
    
    ret.mbox_size = 119208;
    ret.mbox_iv_offset = 0x1d180;
    ret.version = "Kindle 2.9.0(71000)";
    return ret;
}

ExecOffsets Kindle283()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x0016cdc20;
    ret.initterm_e_start = 0x002ad66f8;
    ret.initterm_e_end = 0x002ad6710;
    ret.tls_reset = 0x00252be0f;
    ret.initterm_start = 0x2a93158;
    ret.initterm_end = 0x02ad66f4;
    ret.make_storage = 0x137de20;
    ret.get_storage_value = 0x004b8c80;
    ret.get_plugin_man = 0x017baf60;
    ret.load_all = 0x0017bb060;
    ret.get_factory = 0x17ba4e0;
    ret.open_book = 0x17ba640;
    ret.drm_provider = 0x017ba980;
    ret.mem_offset = 20;

    ret.decr_offset = 0x20f0180;
    ret.mbox_capture = 0x20f0240;
    ret.mbox_size = 119448;
    ret.mbox_iv_offset =0x1d270;
    ret.version = "Kindle 2.8.3(70995)";
    return ret;
}

ExecOffsets Kindle282()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x016cdc20;
    ret.initterm_e_start = 0x002ad66f8;
    ret.initterm_e_end = 0x002ad6710;
    ret.tls_reset = 0x0252be9f;
    ret.initterm_start = 0x2a93158;
    ret.initterm_end = 0x02ad66f4;
    ret.make_storage = 0x00137deb0;
    ret.get_storage_value = 0x004b8c80; 
    ret.get_plugin_man = 0x017baf60;
    ret.load_all = 0x0017bb060;
    ret.get_factory = 0x17ba4e0;
    ret.open_book = 0x17ba640;
    ret.drm_provider = 0x017ba980;
    ret.mem_offset = 20;
    ret.decr_offset =  0x20f0200; 
    ret.mbox_capture = 0x20f02c0;
    ret.mbox_size = 119448;
    ret.mbox_iv_offset = 0x1d270;

    ret.version = "Kindle 2.8.2(70987)";
    return ret;
}

ExecOffsets Kindle281()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x0016fe420;
    ret.initterm_e_start = 0x02b016dc;
    ret.initterm_e_end = 0x0002b016f4;
    ret.tls_reset = 0x0255747f;
    ret.initterm_start = 0x2abe150;
    ret.initterm_end = 0x02b016d8;
    ret.make_storage = 0x013ae590;
    ret.get_storage_value = 0x0004bc400; 
    ret.get_plugin_man = 0x0017eb760;
    ret.load_all = 0x017eb860;

    ret.get_factory = 0x017eace0;
    ret.open_book = 0x17eae40;
    ret.drm_provider = 0x0017eb180;
    ret.mem_offset = 20;
    ret.decr_offset = 0x0211d580;
    ret.mbox_capture = 0x211d640; //check
    ret.mbox_size = 119448;
    ret.mbox_iv_offset = 0x1d270;

    ret.version = "Kindle 2.8.1(70985)";
    return ret;
}

ExecOffsets Kindle280()
{
    ExecOffsets ret;
    ret.luceneaddr = 0x01705150;
    ret.initterm_e_start = 0x02c8f6ec;
    ret.initterm_e_end = 0x02c8f704;
    ret.tls_reset = 0x026d943f;
    ret.initterm_start = 0x2c4c138;
    ret.initterm_end = 0x2c8f6e8;
    ret.make_storage = 0x013b5430;
    ret.get_storage_value = 0x004bc400; 
    ret.get_plugin_man = 0x17f23f0;
    ret.load_all = 0x017f24f0;
    ret.get_factory = 0x017f1970;
    ret.open_book = 0x017f1ad0;
    ret.drm_provider = 0x017f1e10;
    ret.mem_offset = 16;
    ret.decr_offset = 0x022782d0;
    ret.mbox_capture = 0x2278390;
    ret.mbox_size = 119448;
    ret.mbox_iv_offset = 0x1d270;
    ret.version = "Kindle 2.8.0(70980)";
    return ret;
}
const int knum = 6;
ExecOffsets kindles[knum] = { Kindle280(),Kindle281(),Kindle282(),Kindle283(),Kindle290(),Kindle291()};
bool checkExecs(int luceneAddr,int entry, const ExecOffsets& offs)
{

    int diff = 0;
    if(luceneAddr!=0)
    {
    diff=luceneAddr - offs.luceneaddr;
    }
    else
    {
        diff = entry - offs.entry;
    }
    /*printf("Lucene %02X\n", *(unsigned char*)(luceneAddr));
    printf("TLS Reset %02X\n", *(unsigned char*)(diff + offs.tls_reset));

    printf("make_storage %02X\n", *(unsigned char*)(diff + offs.make_storage));
    printf("get_storage_value %02X\n", *(unsigned char*)(diff + offs.get_storage_value));
    printf("get_plugin_man %02X\n", *(unsigned char*)(diff + offs.get_plugin_man));
    printf("load_all %02X\n", *(unsigned char*)(diff + offs.load_all));
    printf("get_factory %02X\n", *(unsigned char*)(diff + offs.get_factory));
    printf("open_book %02X\n", *(unsigned char*)(diff + offs.open_book));
    printf("drm_provider %02X\n", *(unsigned char*)(diff + offs.drm_provider));*/
    if (*(unsigned char*)(diff + offs.tls_reset) != 0x55) return false;
    if (*(unsigned char*)(diff + offs.make_storage) != 0x55) return false;
    if (*(unsigned char*)(diff + offs.get_storage_value) != 0x55) return false;
    if (*(unsigned char*)(diff + offs.get_plugin_man) != 0x55) return false;
    if (*(unsigned char*)(diff + offs.load_all) != 0x8b) return false;
    if (*(unsigned char*)(diff + offs.get_factory) != 0x55) return false;
    if (*(unsigned char*)(diff + offs.open_book) != 0x55) return false;
    if (*(unsigned char*)(diff + offs.drm_provider) != 0x55) return false;
    return true;
}

static std::string hexStr(const uint8_t* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}


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
HINSTANCE qtlib = nullptr;


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
void ParseIAT(HINSTANCE h, IATRESULTS& res, const std::map<FARPROC, FARPROC>& seek, const std::map<std::string, FARPROC>& seekName)
{
    // Get IAT size
    DWORD ulsize = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
    if (!pImportDesc)
        return;

    // Loop names
    for (; pImportDesc->Name; pImportDesc++)
    {
        PSTR pszModName = (PSTR)((PBYTE)h + pImportDesc->Name);
        if (!pszModName)
            break;

        IATRESULTS::MODULEINFO m;

        m.name = pszModName;

        HINSTANCE hImportDLL;
        hImportDLL = GetModuleHandleA(pszModName);
        if (hImportDLL != nullptr)
        {
            std::cout << "Library already loaded" << std::endl;
        }
        else 
        {
        hImportDLL = LoadLibraryA(pszModName);
        }
        char buffer[2048];
        GetModuleFileNameA(hImportDLL, buffer, sizeof(buffer));
      
        /*if (main_path == nullptr)
            hImportDLL = LoadLibraryA(pszModName);
        else
        {
            std::string pth = WcharToUtf8(main_path, 0) + "\\" + std::string(pszModName);
            //std::cout << "Loading path " << pth <<std::endl;
            hImportDLL = LoadLibraryA(pth.c_str());
            if (!hImportDLL)
                hImportDLL = LoadLibraryA(pszModName);
            //else 
             //   std::cout << "Loaded " << pszModName << std::endl;
        }*/
        if (std::string(pszModName) == "Qt5Core.dll")
        {
            qtlib = hImportDLL;// LoadLibrary(qt_path);
        }
        if (!hImportDLL)
        {
            m.f = IATRESULTS::FAILUREREASON::NOTFOUND;
            res.modules.push_back(m);
            std::cout << "Could not load DLL " << pszModName << " with error " << GetLastError() << ", please check your paths" << std::endl;
            continue;
        }
        std::cout << "Loaded dll from path " << buffer << " to address ";
        printf("%08x\n", hImportDLL);
        m.handle = hImportDLL;
        m.f = IATRESULTS::FAILUREREASON::SUCCESS;

        // Get caller's import address table (IAT) for the callee's functions
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
            ((PBYTE)h + pImportDesc->FirstThunk);

        // Replace current function address with new function address
        for (; pThunk->u1.Function; pThunk++)
        {
            IATRESULTS::FUNCTIONINFO fu;

            FARPROC pfnNew = 0;
            size_t rva = 0;
#ifdef _WIN64
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
#else
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
#endif
            {
                // Ordinal
#ifdef _WIN64
                size_t ord = IMAGE_ORDINAL64(pThunk->u1.Ordinal);
#else
                size_t ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
#endif

                fu.ord = ord;
                m.functions.push_back(fu);
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (!ppfn)
                {
                    fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
                    m.functions.push_back(fu);
                    continue;
                }
                rva = (size_t)pThunk;

                char fe[100] = { 0 };
                sprintf_s(fe, 100, "#%u", ord);
                pfnNew = GetProcAddress(hImportDLL, (LPCSTR)ord);
                if (!pfnNew)
                {
                    fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
                    m.functions.push_back(fu);
                    continue;
                }
            }
            else
            {
                // Get the address of the function address
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (!ppfn)
                {
                    fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
                    m.functions.push_back(fu);
                    continue;
                }
                rva = (size_t)pThunk;
                PSTR fName = (PSTR)h;
                fName += pThunk->u1.Function;
                fName += 2;
                if (!fName)
                    break;
                fu.name = fName;


                pfnNew = GetProcAddress(hImportDLL, fName);
                // std::cout << "Func " << fName << "  " << pfnNew <<std::endl;
                if (!pfnNew)
                {
                    fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
                    m.functions.push_back(fu);
                    continue;
                }
                auto fs = seekName.find(std::string(fName));
                if (fs != seekName.end())
                {

                    pfnNew = fs->second;
                    printf("Found sought after function by name \n");
                }
            }

            // Patch it now...
            auto hp = GetCurrentProcess();
            auto it = seek.find(pfnNew);
            if (it != seek.end())
            {
                pfnNew = it->second;
                printf("Found sought after function\n");
            }
            if (!WriteProcessMemory(hp, (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError()))
            {
                DWORD dwOldProtect;
                if (VirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect))
                {
                    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID*)rva, &pfnNew,
                        sizeof(pfnNew), NULL))
                    {
                        fu.f = IATRESULTS::FAILUREREASON::CANNOTPATCH;
                        continue;
                    }
                    if (!VirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect,
                        &dwOldProtect))
                    {
                        fu.f = IATRESULTS::FAILUREREASON::CANNOTPATCH;
                        continue;
                    }
                }
            }
            m.functions.push_back(fu);
        }
        res.modules.push_back(m);
    }
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

std::vector<std::string> sn;
const int keysetIndex = 38;
const int secretKeyIndex = 44;
const int idIndex = 34;
const int algorithmIndex = 28;
const int formatIndex = 33;
const int encodedIndex = 29;

char* read_file(const char* filename, size_t& size)
{
    FILE* fp = fopen(filename, "rb"); 
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
    char* buffer = (char*) malloc(bufsize );
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

std::vector<char> mboxsave(150000);//119424
bool mbox_saved = false;

class BasicDecryptor
{
public:
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out)=0;
};
class MboxDecryptor : public BasicDecryptor
{
public:
    virtual void decrypt(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, std::vector<uint8_t>& out)
    {
        if (!mbox_saved)
        {
            printf("Mbox not saved, decrytion failed!");
        }
        char* mbox_address = &mboxsave[0];
        typedef void(__cdecl* aes_decrypt_call)(void* mbbox_1, unsigned char* input_ciphertext_2, unsigned int chunk_len_3, unsigned char* output_4, unsigned int* alllocated_len_ptr_5);
        aes_decrypt_call callme = (aes_decrypt_call)(stoffset + curOffs.decr_offset);
        //set iv
       //memcpy(mbox_address + 0x749c * 4, &iv[0], iv.size());
        memcpy(mbox_address + curOffs.mbox_iv_offset, &iv[0], iv.size());
        
        out.resize(ciphertext.size());
        unsigned int sz = out.size();
        callme(mbox_address, &ciphertext[0], ciphertext.size(), &out[0], &sz);
        //std::cout << "Decr data " << hexStr(&out[0], out.size()) << std::endl;
        out.resize(sz);

        if (sz == 0)
        {
            printf("Plaintext size is 0 \n");
            return;
        }
        if (out[out.size() - 1] >= out.size()|| out[out.size() - 1]>16)
        {
            printf("Invalid padding length: %d\n", (int)out[out.size() - 1]);
            out.resize(0);
            return;
        }
        out.resize(sz- out[out.size() - 1]);
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
            printf("Unsupported IV size %ld\n",iv.size());
            out.resize(0);
            return;
        }
        out.resize(ciphertext.size());
        unsigned long padded_size = 0;
        plusaes::decrypt_cbc(&ciphertext[0], ciphertext.size(), &key[0], key.size(), (unsigned char (*)[16]) & iv[0], &out[0], out.size(), &padded_size);
        //printf("Padding %ld",padded_size);
        out.resize(out.size()-padded_size);
    }
};
std::vector<uint8_t> drmionHeader = HexToBytes("ea44524d494f4eee");

void  processPage(std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& iv, BasicDecryptor* decr,bool decompress, bool decrypt,std::vector<uint8_t>& out)
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
        printf("Unsupported compression type %d\n",(int)msg[0]);
    }
    plz::PocketLzma p;
    std::vector<uint8_t> decompressed;
    //std::cout << "Lzma hex " << hexStr(&msg[0], msg.size()) << std::endl;
    plz::StatusCode  status = p.decompress(&msg[1],msg.size()-1, decompressed);
    if (status == plz::StatusCode::Ok)
    {
        out=decompressed;
        return;
    }
    printf("LZMA decompression failed!\n"); //maybe throw? 
}
bool processDRMION(char* buf, size_t size,BasicDecryptor* decr, std::vector<uint8_t>& out)
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
            if (nm=="com.amazon.drm.EncryptedPage@1.0" || nm=="com.amazon.drm.EncryptedPage@2.0")
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
                        processPage(ct,civ,decr,decompress,decrypt, page);
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
                    if (!plaintext.empty() )
                    {
                        std::vector<uint8_t> page;
                        processPage(plaintext, plaintext, decr, decompress, decrypt,page);
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

typedef void(__stdcall* svcall)(void);
typedef void(__cdecl* vcall)(void);
typedef void(__cdecl* ipcall)(int*);

typedef void* (__cdecl* vpcall)(void);
typedef void* (__thiscall* getver)(void*, std::unordered_map<std::string, std::string>*);
typedef void(__thiscall* thisvoid)(void*);
typedef void* (__thiscall* thisvoidret)(void*);
typedef void(__thiscall* openBook)(void* factory, void* bk, const std::string& name, const void* drmprovider, void* error, const std::list<std::string>& mayberes);
typedef void* (__thiscall* drmDataProv)(void*, const std::string& book, const std::list<std::string>& resources, const std::list<std::string>& vouchers);
struct krfErr
{
    int code = -1;
    std::string msg;
    char padding[28] = { 0 };
};
typedef void* (__cdecl* toQString)(void* qstring, const std::string& input);
typedef void* (__thiscall* fromQString)(void* qstring, std::string& output);
typedef void* (__thiscall* getme)(void* map, void* qstring, void* output);
typedef void* (__thiscall* makeaccsec)(void* as, void* k_11, const std::string& tname);
typedef int(__thiscall* getint)(void* as);
typedef void(__thiscall* getbyIndex)(void* as, int index, void*);




typedef void* (__thiscall* KRFError)(void*);
typedef void* (__cdecl* getBookFactory)();
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



void initKrfFunctions(KrfAccessFunctions* out)
{
    out->GetPluginManager = (getPluginManager)(stoffset + curOffs.get_plugin_man);
    out->LoadAllStaticModules = (loadAllStaticModules)(stoffset + curOffs.load_all);
    out->DrmDataProvider = (drmDataProv)(stoffset + curOffs.drm_provider);
    out->GetBookFactory = (getBookFactory)(stoffset + curOffs.get_factory);
    out->OpenBook = (openBook)(stoffset + curOffs.open_book);

}

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


struct DrmParameters
{
    std::string bookFile;
    std::string shortBookFile;

    std::list<std::string> resources;
    std::list<std::string> shortResources;

    std::list<std::string> vouchers;
};

bool enumerateKindleFolder(TCHAR* path, DrmParameters* out)
{
    if (out == nullptr) return false;
    WIN32_FIND_DATA ffd;
    //LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg = 0;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    std::basic_string<TCHAR> conv = path;// std::basic_string<TCHAR>(path.begin(), path.end());
    std::string shortPath = std::string(conv.begin(), conv.end());
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
        std::string fname = std::string(wfname.begin(), wfname.end());
        std::string fullname = shortPath + "\\" + fname;
        if (ends_with(fname, ".azw"))
        {
            out->bookFile = fullname;
            out->shortBookFile = fname;
            //std::cout << "Bookname " << fullname << std::endl;
            continue;
        }
        if (ends_with(fname, ".voucher"))
        {
            out->vouchers.push_back(fullname);
            continue;
        }
        if (ends_with(fname, ".res")|| ends_with(fname, ".md"))
        {
            out->resources.push_back(fullname);
            out->shortResources.push_back(fname);
            //std::cout << "Resource " << fullname << std::endl;
            continue;
        }

    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);
    if (out->bookFile.empty()) return false;
    //if (out->vouchers.size() == 0) return false;
    return true;

}

bool armed = false;

KeyData keydataAccumulator;


std::vector<uint8_t> page2 = HexToBytes("17939db6bad6d802183c199520cbc0ddffb88921f74d16931e79a2db4592b14d818f223a89a9ee67c3d6954f47a58837201107a3e8edb0ecea6b5fbe70bac157c6fefaa07d75e610c1c9f208950a2b6d3efe9c00fc284f023a86bca6a01f5704236d367618f48c566210a10fcfadf47d4a04d6aaee7988d9c4f39a4c1a29bca9e346c83c72968506e2385a90c1cb15c346890a9daeae97072b7692f104f137466c782ee98bfddd4494ee97dc5864a344e162c866e1f07585b6d79a68199424abd01ca5b939089c41a3e5e5fa789b9b09430759b6b2b3fbfe82f80fa8e2fc5776bafcf7f9015a3fb62a8144a1b1917e50e1d7de760f99fe0990c3fea881c1349557b841f91edfe553c8dbcfc882897f6da5cf8c05d179dc1fba35df2b8863fa4f03d472c5e3a2b6ddeeec72eb3cd8287be752131b9887fe305ed8f9a95931c06f0ce2f52dda7fa88d025cc480ca71f47c193964b115dd7a658fdd1f7a492ff78c6e3b9a1fdfc086e7dc27f18a8f95075840f287263dfce96fa04a5003b8efea4585200a05b9976a1f608dd395b158cfc7af11d33808f761459835d52b86de311100dd9e13be1f22a6a8c3509ed8a793b4a38a467bf1def7b486174f47db0ad5e6ce5487751dea4d65e2476774f8b5de5b255a514755df10dd40849b065e6221ba50580de8374f412ddae4e7799a567cbc9b2b4bbe9a1d61245a6c7a15b22f82b969df63f3568a7c13a6740acacb6322836c9e6c529df111bf4e0cf44acd9d1d43a347b5a8a4aec4b8668704aca70d7a81c0a92d84607f89b828539cf1714c16dfa4fb5c0a3c445b86e0c9f30322b189813f7d7082f705f82ce05f34fab5f24f894c45dad912b30bd7b412ade873e139d2ae20d4cd0d9be54df8c5e48a60632bc2a7aaa4ff62bc5c260f29f063065ab3aa955541f805c7c68b1062b37b8176bc32bd2576b4d3b03ee456337a6f7bc544b7cf3b8671fe23330a812d9e22f7aa2a5f03f9e27599a6fae12dcd2db7dcac35f1172c9dba121a9d7e41f016d3ea95b42d455cf2d1233fe8775cc5358c9399a1e67b3e1294d0acc0c1ea5a18b6308e691fb05c6830179488ac8cff42ee05dc2461b7dd98f835996bcafc7c6430b6e31017717d932f1d0d4b38854672a4fbcc0a4b2ef39d3cfd5fcc8dbe635179d5e79e5b99eb3b80c57cdf5f29c040f12cb5813cbb7adba7d67eb623067c56c408372d9916ba7b362297f113cc99c93262f46c8b3bb6919a1ff754d8d1b9851e6af708f23066be616739204103d654eb2eb7cab599a03c05ac261c82e2a5c337b9e4c9ec09d660184ce3af26dac18b1ab2383f87c847fdda0cd50af12b025f078afb5cefdbde60d568fe1925ebe6f9261584b7b25c3fc04140d5b5e75bda8a8bd39762f3cd833c54c545322e69996acf304a863a5e294f7fcef268f34cc481d53c6c3c306bdd0afbfeb5a58b85796ed968b03bfb57001a66dbbe6d4b0f5d960106e8e753dbd8e7a7d0ba0b607c17639434bf04fd62a9d1d06ed5f7068fb59a1f623f1f88f7a1b31106ab82cb464e252256e502dd1986de7a9e6b4800657c06ef787e1d9c741d5e78916da1f3f7602d7ead8fd2f35f97cb268340897bb9e23a9e7cb4706f39a370be62903de8928e8bf9fae19c6ecfdb4b0e80ed46a744f49c75ee315fcb611cd240ca54f311da6ae5951ab81c421a8c529ec47728b8e6198f041d6191bceb2d3a382064c0d467507b4cb0955a468aba2164c4962a43e14d762ad0e1993d0c60f6c6c53536e2e66150ca4321a771e09e475a34fb22d1ebe1661f9f3f29c9e180524c5b26430bc06ff612e7062bdd659176a2c2d381b8d93bba1d95b1b031a7b5e0288be60ae8196bffead0deae52c24465d134578701c5108c6c75f290e10a295e185fc1e5858d65cf9b0748dd125e2a0d858f53e12b344afcb27a22b527e65f22266dd182a5c1c2965620a1fad02227f6da2d9e66d23aaea14226bfc9b359e1c15d23ff6444d96ace6a2f5473632f6e515cd1aa9ecd416f90ee6cd132d68ca83f8048705b9b4123eba8721b73f5f35b37a036f55a917ed10685f386308e64a27e4ff062ef6c1e89a9d4c8bfcf52b46f4caca387bd7a0115f26d5c5dbe2ef1e471dff37c160da80149a72a03d659b5aafe51d71084f26b152d3644497c24ffd3d2b2ffade5857478fd77d52db448cd4abf4e34c83422621ecea17fdf697d617db84752109046452c8a315cacd0f484f982e5f04e351263884191f10511544377db5b7215fd4d07fbcbd113e9cfd3");
std::vector<uint8_t> iv2 = HexToBytes("188ce4ac13e7bdfde67ad9f76b2c7e9c");
std::vector<uint8_t> page3 = HexToBytes("63f89e8d1713c98a415db230bb571672e23f9cb8c0e0b97be129a76d92fb41771ff2da452783582abf599b5d09a2e04c39d17c10f72c439e02bedaadf0c5828a1c5f1df3d2ffae64a86e8c8e29b2493f7f210cd5719e3874944c2aa01888b5911c6627c4f935f4a091ba5dab9e85e0d210c14dec708287c465a211a0c810c7002f63c035619d19277c8fcad1f1570efdb620db920de560828a085cc2b1664985d13f921ebc6c6b01a5360f85e184d0912a57c86a59c9033158b9ce367ed0538606b0f432995f7e6e177a7eab4724e673393ee116990ec1770347cfcdcd886e707bd2b64dc1a5a8317bba86d5de286a991bad9ff3747572bf9fb29c4b3ff8ff622f8cfb7088293cf648128b96acaea4fb8e380d1a08d031d3770c0f1629c5dc07ba92ca8a485459680590735bff05dc707db5fd44849c4a000a93b81475430b9ed30808c1a5ee0419a4992b22e5b70ac15f48abc0b77d5eb78af60983752682861dfb0ed2484a549d46e49545c6e64fb5c85d9c0ea1d88763188dee1cac286eae01d208f2bd9f173e21ef891594d5c90cdc94a53cdd215b7d33a94e8623c6451df70a88778cd15143d53289bde3dd603352e0da3c4738f05b5c2266a20222a46bd9dbb476c5570f2f108b0ed090eb5d61e8399eff0d408c43b83c17eb5cce86c825335a383b74239366d74d67b8eae7979aa2221ba9da587569f7becb592c9632a85ca2bc63c15cc1d26c1072f13b1ea6735498fd4d6d3fff7e3d19cb2da88c84b6763e1623a90a9a7d0a23aaa8c8633e65410897316b52a227f0d04b622dc20582d1c1ec1c1a08cbd1df21f7c41d0587e5bfdd81635e393e2fdd73b91520c35b0e3a4d113232c62f040584874947dac617666751a047b62248ef02653a6056a276e283f51f48885d15881a05a355fbc3a2244e88bf03d12766ba8c053a5c7e30d3729f9374f53e37517cacd06519d4e0a44e068af23bc1870a6d0d4ddf5cb26f04aa393b32719727d056a103075e28ca42090aabbf044942704d3dc67f4567bae0543875bc228b50f7a8e7fa7175182d3e6082e013040e5def6ee495399263d6e0a144828d33b0135944f916bc7760154c1136d0391e98b0b3d6c1e06f8cfa635640cfec156b63ea7240206ebc3c6617c67e5869b2aca8e41646c95d9d70ae62ff40476ddb73a24132e3d2a614c74073ce9c35095d9e586f274c182f931a2b07770ed64bbacca37cac7ac2ccb84a455911fdff0a00c8500e1e56067846c67469d42b9adcba12d7ad38ddcada187a50f0df89652abfee635319a157422a998066515e5110aad86b248296d6642375b24f3fa348e07eb0b7861ee7168aa779069ff845b68f51bb1690df157d5b4ec825da1df55eddf2beb825ef53a6bec5af04715dbb00917665db75f277730c24dabc9c9a168fd0861c9c8ff9c206d12c6d11094b91b8007e1ed1eb0dbfaaa5074c1df25fb7c62ea81eb6cca85a46ff0de6e4b03cf035473d0034e00ed8170966402d0a0fd4d866ca19b4331976b051d5fc0f2ff1bbe7a65c313530236217a10989b24ebad4d770b5a571c5ec6adb8e29ff0b1925efe971b495c06be23d55e406124b42be089352b7c530decc96be93c70f01e1e8f66d6f918882383871297ecf2263f2c34590b8713d2c8b29bc71e0995d3f5177faf0e75e9d1fdf51fe4c754c0549d9757264410b8bd5a9a166a2e774ff8a90e661c6964c6492d70580c0d01b56644cafc9f5f7349ea9b27bb24fcb6f84eebde6aabdd8f234a186c529cec6dc2d874a2ecb9b82eccb191be81f5ac4ce3a600d7f78a463e8bf0daaad798610d3c3f5db26164f0c6adbd763a7e8ad49562255d08351d53469baaff79fba8cb4fec23932d58f8df92cb5ef72e0d8bb2c21c3aa0e8bd1f425e3dd05297aa92ead4d5d0a108d89b245a3c9fd01f602085896b3caa1ab88e99a4ed4d667667025d8f84f355deca326b042978ce8145efe2d8c0e1e35ee6da293fa1405f7ae441258492105a63ecd039429b9434459dbfbe6d6d7f9e766067250caed5703644c169108b03583792690b107b6aac7624265948544f72eebf849513b95b9afc54643e81d518dcc0186c9dbeb860bae609556752761056cf2fd07e6eacb384922c0335548b273e90956d76f0879bb4c69d20ceb47d0ad956d262dc4ba93134ccffc29be55bd0d0d8a5f16910e292eae3f497960d936d11ad8f31db78c560e0d470647af89309bf688c2065c92a151c9933bfc90c19b4afe86bd19b3a9c63d025bab12780bf736dbb706fec47920b1e51fce719a8a67c57a2651f297ef276b8ba7504a6396b2ec34");
std::vector<uint8_t> iv3 = HexToBytes("1fceaa3fcced6c577616437df4611ddf");
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

int processFile(const char* outputFile,const std::string& fname, const std::string& archivedName ,BasicDecryptor* decr)
{
   
    size_t bl = 0;
    char* buf = read_file(fname.c_str(), bl);
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
    if (bl > drmionHeader.size() && memcmp(&drmionHeader[0],buf, drmionHeader.size()) == 0)
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
        mz_bool status = mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), buf, bl, NULL, 0, MZ_BEST_COMPRESSION);
        if (!status)
        {
            printf("mz_zip_add_mem_to_archive_file_in_place of non-DRM file  failed!\n");
            free(buf);
            return EXIT_FAILURE;
        }
    }
    
    free(buf);
    return 0;
}
void enumerateKindleDir(const TCHAR* path, const std::string& outdir, std::set<std::string>* serial_candidates, std::set<std::string>* secret_candidates, std::string* k4ifile)
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
        std::cout << "Could not open book directory : " << err<< std::endl;
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
                            break;
                        }
                    }
                    if (opened || invalid)break;
                }
                if (!opened && !invalid)
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
                                break;
                            }
                        }
                        if (opened || invalid)break;
                    }
                }
                if (invalid)
                {
                    std::cout << "Invalid book format, maybe KF8/MOBI?" << std::endl;
                }
                if (!opened && !invalid)
                {
                    std::cout << "Could not open " << params.bookFile << std::endl;

                }
                if (opened)
                {
                    std::string output_name = outdir + std::string("\\") + remove_extension(base_name(params.shortBookFile)) + ".kfx-zip";
                    BasicDecryptor* decr=nullptr;
                    if (acc.keys_128.size()  == 0)
                    {
                        std::cout << "Book opened, but no book keys detected... Trying to use mbox" << std::endl;
                        decr = new MboxDecryptor();
                    }
                    else
                    {
                        std::cout << "Found key "<< *acc.keys_128.begin() <<", trying to use clear AES" << std::endl;
                        std::vector < uint8_t> key = HexToBytes(*acc.keys_128.begin());

                        decr = (BasicDecryptor * )new AesDecryptor(key);
                    }

                    std::cout << "Removal result " << std::remove(output_name.c_str()) <<std::endl; //clear if exists
                    processFile(output_name.c_str(), params.bookFile, params.shortBookFile, decr);
                    auto it1 = params.resources.begin();
                    auto it2 = params.shortResources.begin();
                    while (it1 != params.resources.end() && it2 != params.shortResources.end())
                    {
                        processFile(output_name.c_str(),*it1, *it2, decr);
                        ++it1;
                        ++it2;
                    }
                    delete decr;
                    
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


void tryAssignKey(BinaryIonParser* drmkey)
{
    drmkey->stepin();
    if (drmkey->readerr) return;
    std::string key;
    std::string keyid;
    std::string algo;
    std::string form;
    while (drmkey->hasnext())
    {
        //std::cout << "Next" << std::endl;
        if (drmkey->readerr) return;
        drmkey->next();
        //std::cout << drmkey->getAnnotType() << std::endl;
        if (drmkey->getAnnotType() != secretKeyIndex)
            continue;
       // std::cout << "Found index" << std::endl;
        drmkey->stepin();
        if (drmkey->readerr) return;
        while (drmkey->hasnext())
        {
            drmkey->next();
            if (drmkey->readerr) return;
            switch (drmkey->valuefieldid)
            {
            case idIndex: { keyid = drmkey->stringvalue(); }; break;
            case algorithmIndex: {
                algo = drmkey->stringvalue();
                if (algo != "AES")
                {
                    std::cout << "Found key with unknown algo: " << algo << std::endl;
                    return;
                }
            }; break;
            case formatIndex: {
                form = drmkey->stringvalue();
                if (form != "RAW")
                {
                    std::cout << "Found key with unknown format: " << form << std::endl;
                    return;
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
    }

}
std::map<void*, size_t> sizes;
std::map<void*, std::vector<char>> mcontents;
std::vector<uint8_t> replaceme = HexToBytes("cc5eefa541f02052124ae13d46efcf6e0b7d029b03526bc11c9b3056e5464440578cc2a8cf92541f52f41a2862424410e031311c5e41a8826b324dec1adc339a25048f2cc67f9bf97a743bb4c684d91e92654a857f072017472d0ecf4f813dc0156a1bbf962cf7c4202877327cf9753ff4e0112853c45a9b851071a9452af4a204a8c4dfa3d9cb88109bafc7a230c3634f76bcb8dc546826e06c4e8e6708468302bbdff2ef2d173f126a937042dcf5f90c82354ff7bcf8abacf1bc1f07b2b944d1e47942697834f5d3ad9ff23ece6efcc048ead30e40f8dc569a9ea6ebaef48013e91c64aaef999e95372b58e0cc19bd0a3bde9e92a78d0a0171bc527f43193e5af09a7c595dc32108a50e1fc45b036643170f31acd3eecbcdadf24045debed120bc758199b78b6df5f1843b187b3ab1bd7bbf3fe02d7dbdceea937612400b4356d300a5167b14ddfd4adca93c9d67dbd1a58cf74baaab3580700a37edf24bd66970f7800da073007d51d6efd6b629cdef0cd179793d388a88662eec61171deed6fb20d27b5075746fcf39e950c8b762c8365a3bb200a844ae56b1d51c504acf97df0be7d2a582eddca5acdb1b48567c0f7498105c57b6c1a65b12c75d3fbc43905ef3bb24a7fc3b93ab10b1467a0bfb4860b82ae5e1f3adf1ac8b2a3c073ed2ff479e880297c71d00a78ecc0da69ded0d2b438a66edb2e3a78ddc42101ffd2d856fe3e2686fa0e973848cfeaadaff204d68cf1347a393deca4d94093d2d6247");
std::vector<uint8_t> replacewith = HexToBytes("fb8ab4ef7d669bf123d4402dddf8f8bd09e0709970897cf751b5e3004f1e41bf5d7c3ccdb69160a1cdb970e22466eda4");
std::string compareto = "fb8ab4ef7d669bf123d4402dddf8f8bd09e0709970897cf751b5e3004f1e41bf5d7c3ccdb69160a1cdb970e22466eda4";

void pmemset(void* p, int v, size_t s)
{
    if (armed && s > 0)
    {
        armed = false;
        //std::cout << "Memset of " << s << " :  " << hexStr((uint8_t*)p, s) << "  to  "<<v<< std::endl;
       // printf("At %p \n", p);
        armed = true;
    }
    memset(p, v, s);
}
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
void pmemcpy(void* p, const void* src, size_t s)
{
    //bool replace = false;
    if (armed && s > 0)
    {
        armed = false;
        std::string hex = hexStr((uint8_t*)src, s);
       // std::cout << "Memcpy of " << s << " :  " << hex << std::endl;
        if (s == 48)
        {
            const char* srcc = (const char*)src;
            const char padding[8] = { 8,8,8,8,8,8,8,8 };
            if (memcmp(&srcc[40], padding, 8)==0)
            {
                std::string psecret(srcc,40);
                std::cout << "potential padded secret " << psecret << std::endl;

                keydataAccumulator.old_secrets.insert(psecret);
            }
        }
        if (s == 31 && sizes[p] >= 40&&allhex((uint8_t*)src,s))
        {
            scandidate = (uint8_t*)p;
            std::cout << "Secrect candidate " << hex << std::endl;
            scancntr = 0;
        }
       // printf("Atcpy %p  to %p caller %x \n", src,p, (int)_ReturnAddress()- stoffset);
       
        int caller = (int)_ReturnAddress() - stoffset;
        if (caller == curOffs.mbox_capture)
        {
            char* mbox_addess =(char*)( (int)src - 0x749c * 4);
            
            armed = false;
            if (!mbox_saved)
            {
                printf("Mbox address %p \n", mbox_addess - 8);
                memcpy(&mboxsave[0], mbox_addess, 119424 - 8);//119448
                mbox_saved = true;
            }
            armed = true;
           
        }
        
        //printf("Caller %x \n", caller);
        //if (hex == compareto)
        {
        //    replace = true;
        }
        sizes[p] = s;
        armed = true;
    }
    //if (!replace)
    {
        memmove(p, src, s);
    }
   /* else
    {
        printf("Replacing \n");
        unsigned int rpl = 32;
       // replacewith[rpl] = replacewith[rpl] ^ 1;
        std::cout << "Replacement " << s << " :  " << hexStr((uint8_t*)&replacewith[0], s) << std::endl;
        memcpy(p, &replacewith[0], s);
    }*/
    
}

void* pmalloc(size_t sz)
{
    void* dat = malloc(sz);
    if (armed)
    {
        //printf("Allocating %lu to %p\n",sz, dat);
        //printf("Allocating %lu \n", sz);
        //printf("Caller %x \n", (int)_ReturnAddress() - stoffset);
        if(sz>0&&dat!=nullptr)
          sizes[dat] = sz;
    }
    return dat;
}
inline void assigncont(char* p, size_t size)
{
    sizes[p] = size;
    mcontents[p] = std::vector<char>(size);
    memcpy(&mcontents[p][0], p, size);
}
inline bool checkcont(char* p, size_t size)
{
    if (sizes[p] != size)
    {
        assigncont(p, size);
        return false;
    }
    auto fnd = mcontents.find(p);
    if (fnd == mcontents.end())
    {
        assigncont(p, size);
        return false;
    }
    if (memcmp(&fnd->second[0], p, size)==0)
    {
        return true;
    }
    assigncont(p, size);
    return false;
}
void pfree(void* p)
{
    if (armed)
    {
        if (scandidate != nullptr)
        {
            scancntr += 1;
            if(scancntr==2)
            {
            std::cout << "Candidate: " << hexStr((uint8_t*)&scandidate[0],48) << std::endl;
            if (allhex(scandidate, 40))
            {
                std::cout << "secrets " << std::string((char*)scandidate,40) << std::endl;

                keydataAccumulator.old_secrets.insert(std::string((char*)scandidate,40));
            }
            scandidate = nullptr;
            }
        }
      /// printf("Freeing %p %lu\n",p,sizes[p]);
        uint8_t* pp = (uint8_t*)p;
       if (sizes[p] == curOffs.mbox_size)
       {
           if (!mbox_saved)
           {
              
               memcpy(&mboxsave[0], pp+8, curOffs.mbox_size-8);//119448
               mbox_saved = true;
               printf("Mbox saved\n");
           }
       }
      // std::cout << "Freed: " <<hexStr((uint8_t*)&pp[0], sizes[p]) << std::endl;
       if (p == scandidate) scandidate = nullptr;
    }
    if (armed)
    {
       
       // for (auto pit : sizes)
        {
           // if (pit.second == 0) continue;
           // if (pit.first == nullptr) continue;
           // uint8_t* pp = (uint8_t*)pit.first;
            /*if (!checkcont((char*)pp, pit.second))
            {
                //printf("changed: %p %lu \n", pp, pit.second);
                printf("changed: %lu \n",  pit.second);
                std::cout << hexStr((uint8_t*)&pp[0], pit.second) << std::endl;
            }*/
            
            /*if (pit.second == replaceme.size() && memcmp(&replaceme[0], pit.first, pit.second) == 0)
            {
                printf("Replacing...\n");
                armed = false;
                memcpy(pit.first, &replacewith[0],replacewith.size());
                armed = true;
            }*/
            
           // uint8_t* pp = (uint8_t*)p;
            /*
            if (pit.second > 16)//arbitrary
            {
                BinaryIonParser bp(pp, pit.second, TID_TYPEDECL);

                if (bp.hasnext())
                {
                    int nxt = bp.next();
                    if (nxt == TID_LIST)
                    {
                        if (bp.annotations.size() > 0 && bp.annotations[0] == keysetIndex)
                        {
                            //valuefieldid
                            //std::cout << "Correct: " << hexStr((uint8_t*)&pp[16], 16) << std::endl;
                            tryAssignKey(&bp);
                            // while (true) {}
                        }

                    }

                }
            }*/

        }
    }
    if (armed && p != nullptr && sizes[p] > 39)
    {
        uint8_t* pp = (uint8_t*)p;
        char* pc = (char*)p;
        BinaryIonParser bp(&pp[curOffs.mem_offset], sizes[p] - curOffs.mem_offset, TID_TYPEDECL);
        
        if (bp.hasnext())
        {
            int nxt = bp.next();
            if (nxt == TID_LIST)
            {
                if (bp.annotations.size() > 0 && bp.annotations[0] == keysetIndex)
                {
                    //valuefieldid
                    //std::cout << "Correct: " << hexStr((uint8_t*)&pp[16], 16) << std::endl;
                    tryAssignKey(&bp);
                    // while (true) {}
                }

            }

        }
        else
        {
            bool brk = false;
            for (int i = 0; i < 40; i++)
            {
                if (!isxdigit(pc[i]) || pc[i] == 0)
                {
                    brk = true;
                    break;
                }
            }
             //std::cout << hexStr((uint8_t*)&pp[0], sizes[p]>42 ? 42 : sizes[p]) << std::endl;
            if (!brk && pc[41] == 0)
            {
                std::cout << "secrets " << std::string(pc) << std::endl;

                keydataAccumulator.old_secrets.insert(std::string(pc));
            }
        }
        sizes.erase(p);
    }
    free(p);
}


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


bool findExec(int lucene,int entry)
{
    for (int i = 0; i < knum; i++)
    {
        if (checkExecs(lucene, entry,kindles[i]))
        {
            curOffs = kindles[i];
            return true;
        }
    }
  
   
    return false;
}

bool directoryExistsWinAPI(const std::string& dirName_in) 
{
    DWORD ftyp = GetFileAttributesA(dirName_in.c_str());
    if (ftyp == INVALID_FILE_ATTRIBUTES)
        return false;  // something is wrong with the path, or it doesn't exist

    if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
        return true;   // This is a directory!

    return false;      // This is not a directory, but a file
}
void* GetModuleEntryPoint(HMODULE hMod) 
{
    if (hMod == NULL) return nullptr;

    // 1. Get the DOS Header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;

    // 2. Get the NT Headers using the offset from the DOS header
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);

    // 3. Get the AddressOfEntryPoint (RVA)
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // 4. Add the RVA to the Base Address (hMod) to get the absolute address
    return (void*)((BYTE*)hMod + entryPointRVA);
}


LONG WINAPI PrintStackTraceFilter(EXCEPTION_POINTERS* pExp) {
    PEXCEPTION_RECORD pRecord = pExp->ExceptionRecord;

    // Print the exception code and the instruction address where it happened
    printf("Exception Code: 0x%08X\n", pRecord->ExceptionCode);
    printf("Exception Address: 0x%p\n", pRecord->ExceptionAddress);

    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    SymInitialize(process, NULL, TRUE);

    STACKFRAME64 stackFrame = {};
    DWORD machineType;
    CONTEXT* context = pExp->ContextRecord;

#ifdef _M_IX86
    machineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context->Eip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
    machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#endif

    while (StackWalk64(machineType, process, thread, &stackFrame, context,
        NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        // Use SymFromAddr here to print function names
        std::cout << "Address: " << (void*)stackFrame.AddrPC.Offset << std::endl;
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;

        // 2. Resolve address to symbol
        // AddrPC.Offset is the current instruction pointer from StackWalk64
        if (SymFromAddr(process, stackFrame.AddrPC.Offset, &displacement, pSymbol)) {
            printf("Frame: %s + 0x%llx (Address: 0x%llx)\n",
                pSymbol->Name, displacement, pSymbol->Address);
        }
        else {
            printf("Frame: [Unknown Symbol] (Address: 0x%llx)\n", stackFrame.AddrPC.Offset);
        }
        IMAGEHLP_MODULE64 moduleInfo = { 0 };
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

        if (SymGetModuleInfo64(process, stackFrame.AddrPC.Offset, &moduleInfo)) {
            // moduleInfo.ModuleName contains the short name (e.g., "ntdll")
            // moduleInfo.ImageName contains the full path (e.g., "C:\Windows\System32\ntdll.dll")
            DWORD64 moduleBase = SymGetModuleBase64(process, stackFrame.AddrPC.Offset);
            printf("Module: %s %08llx + %08llx (ghidra: %08llx)\n", moduleInfo.ImageName, moduleBase,stackFrame.AddrPC.Offset- moduleInfo.BaseOfImage, stackFrame.AddrPC.Offset - moduleInfo.BaseOfImage+0x400000);
        }
        printf("----\n");
    }

    SymCleanup(process);
    return EXCEPTION_EXECUTE_HANDLER;
}

int fake_initterm(_PVFV* ppfn, _PVFV* ppend)
{
    do {
        if (_PVFV pfn = *++ppfn) {
          //  printf("Running initializer %x\n", (int)pfn - stoffset);
            __try {
                pfn();
            }
            __except (PrintStackTraceFilter(GetExceptionInformation())) {
                printf("Ignored exception in the handler block.\n");
                exit(0);
            }
        }
    } while (ppfn < ppend);
    return 0;
}
int main(int argc, char* argv[])
{
    PWSTR localcappdata = NULL;
    PWSTR programfiles = NULL;
    const wchar_t* amazon_storage = L"Amazon\\Kindle\\storage\\.kinf2024";
    const wchar_t* amazon_app = L"Amazon\\Kindle\\application";
    const wchar_t* storage_fl = L"storage\\.kinf2024";


    if (argc < 4)
    {
        std::cout << "Usage: executable <kindle documents path (with _EBOK folders)> <output folder> <output k4i file> [optional path to Kindle.exe folder]" << std::endl;
        std::cout << "Output folder must exist. Output folder will contain kfx-zips after running, hopefully. THose can be imported with KFX Input plugin into calibre";
        std::cout << "This program searches for Kindle executable in standard locations, run it from wherever, but it prefers Kindle installations in local folder (%APPDATA%/Local/Amazon/Kindle)" << std::endl;
        std::cout << "Please ensure that Kindle.exe is of the appropriate version (currently  Kindle 2.8.0(70980), Kindle 2.8.1(70985), Kindle 2.8.2(70987))" << std::endl;
        std::cout << "In case Kindle version does not match, it would exit" << std::endl;
        std::cout << "Note: to get proper values into k4i file, at least one KFX book that uses account secrets should be downloaded. If resulting k4i has no tokens set, try downloading some free books." << std::endl;
        std::cout << "Note 2: this utility creates a temporary /storage folder in %APPDATA%/Local. It can be deleted after use. " << std::endl;
        return -1;
    }
    std::string folder_path = argv[1];
    std::string out_dir_path = argv[2];
    if (!directoryExistsWinAPI(out_dir_path))
    {
        std::cout << "Directory " << out_dir_path << " does not appear to exist. Please check path and create is necessary." << std::endl;
        return - 2;
    }
    std::cout << "Scanning " << folder_path << " for book folders" << std::endl;
    std::string k4;
    std::string* k4file = nullptr;
    k4 = argv[3];
    k4file = &k4;
    bool hasReplPath = false;
    std::basic_string<TCHAR> replPath = L"";
    if (argc > 4)
    {
        hasReplPath = true;
        std::string shortRPath = std::string(argv[4]);
        replPath = std::basic_string<TCHAR>(shortRPath.begin(), shortRPath.end());
    }
   
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localcappdata);

    // Check if the function call was successful.
    if (!SUCCEEDED(hr))
    {
        std::cerr << "Failed to get the LocalAppData folder path. HRESULT: " << hr << std::endl;
        return 1;
    }
    hr = SHGetKnownFolderPath(FOLDERID_ProgramFilesX86, 0, NULL, &programfiles);
    if (!SUCCEEDED(hr))
    {
        std::cerr << "Failed to get the Programfiles folder path. HRESULT: " << hr << std::endl;
        return 1;
    }

    wchar_t kindle_local_path[MAX_PATH];
    wchar_t kindle_global_path[MAX_PATH];
    PathCombineW(kindle_local_path, localcappdata, amazon_app);
    PathCombineW(kindle_global_path, programfiles, L"Amazon\\Kindle\\");
    wchar_t exe_local[MAX_PATH];
    wchar_t exe_global[MAX_PATH];

    //can swap Kindle executables here
    if (hasReplPath)
    {
        PathCombineW(kindle_local_path, replPath.data(), L"");
    }

    PathCombineW(exe_local, kindle_local_path, L"Kindle.exe");
    PathCombineW(exe_global, kindle_global_path, L"Kindle.exe");

    wchar_t kindle_path[MAX_PATH];
    wchar_t qt_path[MAX_PATH];
    wchar_t kindle_storage[MAX_PATH];
    main_path = kindle_local_path;
    if (PathFileExists(exe_local))
    {
        PathCombineW(kindle_path, kindle_local_path, L"Kindle.exe");
        PathCombineW(qt_path, kindle_local_path, L"Qt5Core.dll");
        main_path = kindle_local_path;
    }
    else
    {
        if (PathFileExists(exe_global))
        {
            PathCombineW(kindle_path, kindle_global_path, L"Kindle.exe");
            PathCombineW(qt_path, kindle_global_path, L"Qt5Core.dll");
            main_path = kindle_global_path;
            if (!PathFileExists(kindle_path))
            {
                PathCombineW(kindle_global_path, programfiles, L"Amazon\\Kindle\\");
                PathCombineW(kindle_path, kindle_global_path, L"Kindle.exe");
                PathCombineW(qt_path, kindle_global_path, L"Qt5Core.dll");
                main_path = kindle_global_path;
            }

            std::cout << "Kindle4PC appears to be installed globally, this is not tested and the utility might not work" << std::endl;
        }
        else
        {
            std::wcout << L"Kindle.exe not found in " << exe_local << L" or " << exe_global << std::endl;
            return 1;
        }

    }
    std::wcout << "adding search dir " << main_path << std::endl;
    SetDllDirectory(main_path);
    wchar_t old_cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, old_cwd);
    
    PathCombineW(kindle_storage, localcappdata, amazon_storage);
    if (!PathFileExists(kindle_storage))
    {
        std::wcout << "Kindle4PC kinf file not found at " << kindle_storage << " , Please log in to kindle4pc or copy that file if it is placed somewhere else" << std::endl;
        return 1;
    }
    std::wcout << L"Kindle Directory: " << kindle_path << std::endl;
    SetCurrentDirectoryW(main_path);
    HINSTANCE kindle = LoadLibrary(L"./Kindle.exe");//load kindle.exe 
    IATRESULTS res;
    std::map<FARPROC, FARPROC> repls;
    repls[(FARPROC)&free] = (FARPROC)&pfree;
    repls[(FARPROC)&malloc] = (FARPROC)&pmalloc;
    repls[(FARPROC)&memcpy] = (FARPROC)&pmemcpy;
    //repls[(FARPROC)&memset] = (FARPROC)&pmemset;
    std::map<std::string, FARPROC> replsName;
    replsName["memset"]= (FARPROC)&pmemset;
    replsName["memcpy"] = (FARPROC)&pmemcpy;
   //replsName["memmove"] = (FARPROC)&pmemcpy;
    ParseIAT(kindle, res, repls, replsName); //patch and replace symbols
    SetCurrentDirectoryW(old_cwd); //return back to original dir
    if (kindle == nullptr)
    {
        std::cerr << "Error loading kindle " << GetLastErrorAsString() << std::endl;
        return 2;
    }
    wchar_t empty_storage_folder[MAX_PATH];
    PathCombineW(empty_storage_folder, localcappdata, L"storage");
    if (!PathFileExists(empty_storage_folder))
    {
        std::wcout << "Creating storage folder for temp storage file: " << empty_storage_folder << std::endl;
        if (!CreateDirectory(empty_storage_folder, NULL))
        {
            std::cout << "Could not create directory " << GetLastErrorAsString() << std::endl;
            return 2;
        }
    }
    wchar_t temp_storage_file[MAX_PATH];
    PathCombineW(temp_storage_file, localcappdata, storage_fl);
    if (!CopyFile(kindle_storage, temp_storage_file, false))
    {
        std::cout << "Could not copy storage file to temp location" << GetLastErrorAsString() << std::endl;
        return 2;
    }


    if (qtlib == nullptr)
    {
        std::cerr << "Error loading qt " << GetLastErrorAsString() << std::endl;
        SetCurrentDirectoryW(old_cwd);
        return 2;
    }
    toQString toQ = (toQString)GetProcAddress(qtlib, "?fromStdString@QString@@SA?AV1@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z");
    fromQString fromQ = (fromQString)GetProcAddress(qtlib, "?toStdString@QString@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ");
    int cc = (int)GetProcAddress(kindle, ("??0Analyzer@Lucene@@QAE@ABV01@@Z"));
    int centry = (int)GetModuleEntryPoint(kindle);
    printf("Lucene: %x entry: %x\n ", cc, centry);
    if (!findExec(cc, centry))
    {
        std::cout << "Could not find supported kindle version, aborting"  << std::endl;
        return 4;
    }
    else
    {
        std::cout << "Found Kindle executable of version " << curOffs.version << std::endl;
    }
    stoffset = cc - curOffs.luceneaddr;
    if (curOffs.luceneaddr == 0)
    {
        stoffset = centry - curOffs.entry;
    }
    printf("Got offset: %x\n", stoffset);
    _initterm_e((_PIFV*)(stoffset + curOffs.initterm_e_start), (_PIFV*)(stoffset + curOffs.initterm_e_end));
    printf("Initialized exceptions \n");

    //flip tlls initialized flag
    ipcall tlsset = (ipcall)(stoffset + curOffs.tls_reset);
    int rt = 1;
    //need to reset tls flag so that static vars would initialize, i think
    tlsset(&rt);
    printf("Flipped tls \n");

    //init global/static vars
    _PVFV* ppfn = (_PVFV*)(stoffset + curOffs.initterm_start);
    _PVFV* ppend = (_PVFV*)(stoffset + curOffs.initterm_end);
    fake_initterm(ppfn,ppend);
    //_initterm((_PVFV*)(stoffset + initterm_start), (_PVFV*)(stoffset + initterm_end));
    printf("Initialized globals \n");
    std::string tokens = std::string("kindle.account.tokens");
    std::string dsn = std::string("DSN");
    vpcall MakeKindleInfoStorage = (vpcall)(stoffset + curOffs.make_storage);
    void* kinfo = MakeKindleInfoStorage();
    //printf("Opened storage %p\n", kinfo);
    //note: QStrings are not destroyed, so there is some leak, but we don't care
    getme getVal = (getme)(stoffset + curOffs.get_storage_value);
    char qtokens[256];
    void* tknz = toQ(qtokens, tokens); //std::string("kindle.account.tokens"));
    char qdsn[256];
    void* dsnz = toQ(qdsn, dsn); //std::string("kindle.account.tokens"));
    char qstbufout[256];
    void* nretout = toQ(qstbufout, std::string(""));
    //getVal(kinfo, nretout, tknz);
    std::string out_tokens = "fdf";
    std::string out_dsn = "sds";
    getVal(kinfo, nretout, tknz);
    fromQ(nretout, out_tokens);
    //printf("Got tokens\n");
    getVal(kinfo, nretout, dsnz);
    fromQ(nretout, out_dsn);
    //printf("Got dsn\n");
    std::cout << "DSN " << out_dsn << std::endl;
    std::cout << "Tokens " << out_tokens << std::endl;

    if (out_dsn.empty())
    {
        std::cout << "Could not get DSN from storage, aborting" << std::endl;
        SetCurrentDirectoryW(old_cwd);
        return 3;
    }

    if (out_tokens.empty())
    {
        std::cout << "Could not get account tokens from storage, aborting" << std::endl;
        SetCurrentDirectoryW(old_cwd);
        return 3;
    }
    std::list<std::string> secrets = splitStringBySubstring(out_tokens, ",");
    initKrfFunctions(&globalKRFContext);
    initKRFContext(&globalKRFContext);
    std::set<std::string> serial_candidates;
    std::set<std::string> secret_candidates;
    serial_candidates.insert(out_dsn);
    for (auto val : secrets)
    {
     secret_candidates.insert(val);
    }
    // 


    std::basic_string<TCHAR> wfolder_path = std::basic_string<wchar_t>(folder_path.begin(), folder_path.end());// L".\\";
    SetCurrentDirectoryW(old_cwd);
    enumerateKindleDir(wfolder_path.data(), out_dir_path, &serial_candidates, &secret_candidates, k4file);
    if (curOffs.version == "Kindle 2.9.0(71000)")
    {
        std::cout << "WARNING: 2.9.0 K4PC Secret decryption might be unstable. USE k4i file WITH CAUTION. "<< std::endl;
    }
  //  while (true) {}

    

}
