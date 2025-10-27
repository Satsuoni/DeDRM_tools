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
#pragma comment(lib, "User32.lib")

#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")

int stoffset = 0; //global base offset for loaded library
const int luceneaddr = 0x01705150;
const int initterm_e_start = 0x02c8f6ec;
const int initterm_e_end= 0x02c8f704;
const int tls_reset = 0x026d943f;
const int initterm_start = 0x2c4c138;
const int initterm_end = 0x2c8f6e8;
const int make_storage = 0x013b5430;
const int get_storage_value = 0x004bc400; //storageTable#3
const int get_plugin_man = 0x17f23f0;
const int load_all = 0x017f24f0;
const int get_factory = 0x017f1970;
const int open_book = 0x017f1ad0;
const int drm_provider = 0x017f1e10;


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
            //std::cout << "MIght have next" << std::endl;
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
        //std::cout << "Stepping in vlen:" << valuelen << "nextpos "<< stream_pos + valuelen<< std::endl;
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
            maxid = (int) table.symnames.size();
        }
        if (table.name != "-")
        {
            symbols.import_(table.symnames, min(maxid, table.symnames.size()));
            if (table.symnames.size() < maxid)
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
void ParseIAT(HINSTANCE h, IATRESULTS& res, const std::map<FARPROC, FARPROC>& seek)
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
        if(main_path==nullptr)
            hImportDLL = LoadLibraryA(pszModName);
        else
        {
            std::string pth = WcharToUtf8(main_path,0) + "\\"+std::string(pszModName);
            //std::cout << "Loading path " << pth <<std::endl;
            hImportDLL = LoadLibraryA(pth.c_str());
            if (!hImportDLL)
                hImportDLL = LoadLibraryA(pszModName);
            //else 
             //   std::cout << "Loaded " << pszModName << std::endl;
        }
        if (std::string(pszModName)=="Qt5Core.dll")
        {
            qtlib = hImportDLL;// LoadLibrary(qt_path);
        }
		if (!hImportDLL)
		{
			m.f = IATRESULTS::FAILUREREASON::NOTFOUND;
			res.modules.push_back(m);
            std::cout << "Could not load DLL " << pszModName << " with error "<< GetLastError() << ", please check your paths" << std::endl;
			continue;
		}
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
				if (!pfnNew)
				{
					fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
					m.functions.push_back(fu);
					continue;
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


std::vector<char> HexToBytes(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

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



void initKrfFunctions( KrfAccessFunctions* out)
{
    out->GetPluginManager = (getPluginManager)(stoffset+ get_plugin_man);
    out->LoadAllStaticModules = (loadAllStaticModules)(stoffset + load_all);
    out->DrmDataProvider = (drmDataProv)(stoffset + drm_provider);
    out->GetBookFactory = (getBookFactory)(stoffset + get_factory);
    out->OpenBook = (openBook)(stoffset + open_book);

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
    std::list<std::string> resources;
    std::list<std::string> vouchers;
};

bool enumerateKindleFolder(TCHAR* path, DrmParameters* out)
{
    if (out == nullptr) return false;
    WIN32_FIND_DATA ffd;
    //LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg=0;
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
            //std::cout << "Bookname " << fullname << std::endl;
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
        out->aggregate(&keydataAccumulator);
        //return true;
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
    for (auto secret :*secret_candidates)
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
void enumerateKindleDir(const TCHAR* path, const std::string& outfile, std::set<std::string>* serial_candidates, std::set<std::string>* secret_candidates, std::string* k4ifile)
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
        std::cout << "Could not open directory" << std::endl;
        return;
    }
    std::ofstream out(outfile);
    std::set<std::string> working_serials;
    std::set<std::string> working_secrets;
    std::set<std::string> old_secrets;
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
                        if (acc.old_secrets.size() > 0)
                        {
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
            nlohmann::json jsn= nlohmann::json();
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
        if (drmkey->readerr) return;
        drmkey->next();
        if (drmkey->getAnnotType() != secretKeyIndex)
            continue;
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

void pfree(void* p)
{

    if (armed&&p!=nullptr)//armed&&
    {
        uint8_t* pp=(uint8_t*)p;
        char* pc = (char*)p;
        BinaryIonParser bp(&pp[16], 2000, TID_TYPEDECL);
        //std::cout << hexStr((uint8_t*)p, 128) << std::endl;
        if (bp.hasnext())
        {
            int nxt = bp.next();
            if (nxt == TID_LIST)
            {
                if (bp.annotations[0] == keysetIndex)
                {
                    //valuefieldid
                    //std::cout << "Correct: " << hexStr((uint8_t*)addr, 16) << std::endl;
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
                if (!isxdigit(pc[i])|| pc[i]==0)
                {
                    brk = true;
                    break;
                }
            }
            if (!brk && pc[41] == 0)
            {
                std::cout << "secrets " << std::string(pc) << std::endl;
                
                keydataAccumulator.old_secrets.insert(std::string(pc));
            }
        }
        
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




int main(int argc, char* argv[])
{
	PWSTR localcappdata = NULL;
	PWSTR programfiles = NULL;
	const wchar_t * amazon_storage = L"Amazon\\Kindle\\storage\\.kinf2024";
	const wchar_t* amazon_app = L"Amazon\\Kindle\\application";
	const wchar_t* storage_fl = L"storage\\.kinf2024";


    if (argc < 4)
    {
        std::cout << "Usage: executable <kindle documents path (with _EBOK folders)> <output file> <output k4i file>" << std::endl;
        std::cout << "This program searches for Kindle executable in standard locations, run it from wherever, but it prefers Kindle installations in local folder (%APPDATA%/Local/Amazon/Kindle)" << std::endl;
        std::cout << "Please ensure that Kindle.exe is of the appropriate version (currently md5 93fce0fedb6cd17514f9a72f963dbdba, kindle 2.8.0(70980))" << std::endl;
        std::cout << "In case Kindle version does not match, it would crash" << std::endl;
        std::cout << "Note: to get proper values into k4i file, at least one KFX book that uses account secrets should be downloaded. If resulting k4i has no tokens set, try downloading some free books." << std::endl;
        std::cout << "Note 2: this utility creates a temporary /storage folder in %APPDATA%/Local. It can be deleted after use. " << std::endl;
        return -1;
    }
    std::string folder_path = argv[1];
    std::string out_path = argv[2];
    std::cout << "Scanning " << folder_path << " for book folders"<<std::endl;
    std::string k4;
    std::string* k4file = nullptr;
    k4 = argv[3];
    k4file = &k4;


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
    wchar_t exe_local [MAX_PATH] ;
    wchar_t exe_global[MAX_PATH];
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
	PathCombineW(kindle_storage, localcappdata, amazon_storage);
	if (!PathFileExists(kindle_storage))
	{
		std::wcout << "Kindle4PC kinf file not found at " << kindle_storage << " , Please log in to kindle4pc or copy that file if it is placed somewhere else" << std::endl;
		return 1;
	}
	std::wcout << L"Kindle Directory: " << kindle_path << std::endl;
	HINSTANCE kindle = LoadLibrary(kindle_path);
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
			std::cout << "Could not create directory " << GetLastErrorAsString()<<std::endl;
			return 2;
		}
	}
	wchar_t temp_storage_file[MAX_PATH];
	PathCombineW(temp_storage_file, localcappdata, storage_fl);
	if (!CopyFile(kindle_storage, temp_storage_file,false))
	{
		std::cout << "Could not copy storage file to temp location" << GetLastErrorAsString() << std::endl;
		return 2;
	}
	IATRESULTS res;
	std::map<FARPROC, FARPROC> repls;
	repls[(FARPROC)&free] = (FARPROC)&pfree;
	ParseIAT(kindle, res, repls);
	
	if (qtlib == nullptr)
	{
		std::cerr << "Error loading qt " << GetLastErrorAsString() << std::endl;
		return 2;
	}
	toQString toQ = (toQString)GetProcAddress(qtlib, "?fromStdString@QString@@SA?AV1@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z");
	fromQString fromQ = (fromQString)GetProcAddress(qtlib, "?toStdString@QString@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ");
	int cc = (int)GetProcAddress(kindle, ("??0Analyzer@Lucene@@QAE@ABV01@@Z"));
	stoffset = cc - luceneaddr;
    printf("Got offset: %x\n",stoffset);
	_initterm_e((_PIFV*)(stoffset + initterm_e_start), (_PIFV*)(stoffset + initterm_e_end));
    //printf("Initialized exceptions \n");

    //flip tlls initialized flag
	ipcall tlsset = (ipcall)(stoffset + tls_reset);
	int rt = 1;
	//need to reset tls flag so that static vars would initialize, i think
	tlsset(&rt);
    //printf("Flipped tls \n");

	//init global/static vars
    _PVFV* ppfn = (_PVFV*)(stoffset + initterm_start);
    _PVFV* ppend = (_PVFV*)(stoffset + initterm_end);
    do {
        if (_PVFV pfn = *++ppfn) {
            //printf("Running initializer %x\n",(int)pfn-stoffset);
            pfn();
        }
    } while (ppfn < ppend);
	//_initterm((_PVFV*)(stoffset + initterm_start), (_PVFV*)(stoffset + initterm_end));
    //printf("Initialized globals \n");
	std::string tokens = std::string("kindle.account.tokens");
	std::string dsn = std::string("DSN");
	vpcall MakeKindleInfoStorage = (vpcall)(stoffset + make_storage);
	void* kinfo = MakeKindleInfoStorage();
    //printf("Opened storage %p\n", kinfo);
	//note: QStrings are not destroyed, so there is some leak, but we don't care
	getme getVal = (getme)(stoffset + get_storage_value);
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
		return 3;
	}
	if (out_tokens.empty())
	{
		std::cout << "Could not get account tokens from storage, aborting" << std::endl;
		return 3;
	}
    std::list<std::string> secrets = splitStringBySubstring(out_tokens, ",");
    initKrfFunctions( &globalKRFContext);
    initKRFContext(&globalKRFContext);
    std::set<std::string> serial_candidates;
    std::set<std::string> secret_candidates;
    serial_candidates.insert(out_dsn);
    for (auto val : secrets)
    {
       secret_candidates.insert(val);
    }
    

    std::basic_string<TCHAR> wfolder_path = std::basic_string<wchar_t>(folder_path.begin(), folder_path.end());// L".\\";
   
    enumerateKindleDir(wfolder_path.data(), out_path, &serial_candidates, &secret_candidates,k4file);
}
