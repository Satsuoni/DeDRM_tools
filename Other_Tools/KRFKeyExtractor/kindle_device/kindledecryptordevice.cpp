//#define _GLIBCXX_USE_CXX11_ABI 0
#define _FILE_OFFSET_BITS 64
#include "miniz.h" //https://github.com/richgel999/miniz/releases
#include "plthook.h"
#include <dlfcn.h>
#include <fcntl.h>
#include "filesystem.hpp"
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <execinfo.h>
#define POCKETLZMA_LZMA_C_DEFINE
#include "plusaes.hpp" //https://github.com/kkAyataka/plusaes/releases
#include "pocketlzma.hpp" //https://github.com/SSBMTonberry/pocketlzma ,but needs fixing, in decompress, replace (value << (i * 8)); with ((size_t)value << (i * 8));
#include "json.hpp"


namespace fs = ghc::filesystem;
using json=nlohmann::json;

static std::string hexStr(const uint8_t *data, int len)
{

  char* buffer=new char[len*2+1]; 
  
  int snprintf(char *str, size_t size, const char *format, ...);
  for (int i(0); i < len; ++i)
  {
    snprintf(&buffer[i*2],3,"%02x",(int)data[i]);
  }
  std::string ret(buffer,len*2);
  return ret;
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
// const uint8_t TID_UNUSED = 0xF;

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

const uint8_t VERSION_MARKER[3] = {(uint8_t)0x01, (uint8_t)0x00, (uint8_t)0xEA};

struct IonCatalogItem
{
  std::string name = "";
  int version = 0;
  std::vector<std::string> symnames;
  IonCatalogItem(const std::string &nm, int ver, const std::vector<std::string> &snames)
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
  SymbolToken(const std::string &txt, int sd)
  {
    text = txt;
    sid = sd;
    if (txt.empty() && sid == 0)
    {
      std::cerr << "SymbolToken must have text or sid " << std::endl;
    }
  }
};

const char *SystemSymbols_ION = "$ion";
const char *SystemSymbols_ION_1_0 = "$ion_1_0";
const char *SystemSymbols_ION_SYMBOL_TABLE = "$ion_symbol_table";
const char *SystemSymbols_NAME = "name";
const char *SystemSymbols_VERSION = "version";
const char *SystemSymbols_IMPORTS = "imports";
const char *SystemSymbols_SYMBOLS = "symbols";
const char *SystemSymbols_MAX_ID = "max_id";
const char *SystemSymbols_ION_SHARED_SYMBOL_TABLE = "$ion_shared_symbol_table";

struct SymbolTable
{
  std::vector<std::string> table;
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
  void import_(const std::vector<std::string> &stable, size_t maxid)
  {
    maxid = (stable.size() < maxid) ? stable.size() : maxid;
    for (size_t i = 0; i < maxid; i++)
    {
      table.push_back(stable[i]);
    }
  }
  void importunknown(const std::string &name, size_t maxid)
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
  bool needhasnext = false;
  bool isinstruct = false;
  int valuetid = 0;
  int valuefieldid = 0;
  int parenttid = 0;
  int valuelen = 0;
  bool valueisnull = false;
  bool valueistrue = false;
  IonVtype vtype = IonVtype::None;
  std::string sval = "";
  int ival = 0;
  long long int lval = 0;
  std::vector<uint8_t> vec;
  void assignIonValue() {}
  void assignIonValue(const std::string &v)
  {
    valueisnull = false;
    vtype = IonVtype::String;
    sval = v;
  }
  void assignIonValue(const std::vector<uint8_t> &v)
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
  uint8_t *stream;
  size_t maxstrlen;
  size_t stream_pos;
  bool readerr = false;
  int eFTid = -1;
  BinaryIonParser(uint8_t *stream, size_t maxlen, int enforceFirstTid)
  {
    this->stream = stream;
    maxstrlen = maxlen;
    stream_pos = 0;
    eFTid = enforceFirstTid;
    reset();
  }
  void resetFor(uint8_t *stream, size_t maxlen)
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
  void addtocatalog(const std::string &name, int ver, const std::vector<std::string> &snames)
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
  uint8_t *read() { return read(1); }
  uint8_t *read(int count)
  {
    // std::cout << " Reading " << (int)stream << " at " << stream_pos << " len: " << count << " localrem: "<< localremaining <<std::endl;
    if (localremaining != -1)
    {
      localremaining -= count;
      if (localremaining < 0)
      {
        readerr = true;
        return nullptr;
      }
    }
    uint8_t *res = &stream[stream_pos];
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
    uint8_t *r = read();
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
  unsigned int readvaruint()
  {
    if (readerr) return 0;
    // std::cout << hexStr(&stream[stream_pos], 4) << std::endl;
    uint8_t *r = read();
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

  void push(int tpid, int nxtpos, int nxtrem) { containerstack.push_back(ContainerRec(nxtpos, tpid, nxtrem)); }
  void skip(int count) { read(count); }

  bool hasnextraw()
  {
    if (readerr) return false;
    clearvalue();
    while (valuetid == -1 && !eof)
    {
      needhasnext = false;
      switch (state)
      {
      case ParserState::BeforeField:
      {
        if (valuefieldid != SID_UNKNOWN) return false;
        valuefieldid = readfieldid();
        if (valuefieldid != SID_UNKNOWN) state = ParserState::BeforeTID;
        else
        {
          eof = true;
        }
      };
      break;
      case ParserState::BeforeTID:
      {
        state = ParserState::BeforeValue;
        // std::cout << "Getting tid " << std::endl;
        valuetid = readtypeid();
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
          // break;
        }
        else
        {
          eFTid = -1;
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
      };
      break;
      case ParserState::BeforeValue:
      {
        skip(valuelen);
        if (readerr) return false;
        state = ParserState::AfterValue;
      };
      break;

      case ParserState::AfterValue:
      {
        if (isinstruct)
        {
          state = ParserState::BeforeField;
        }
        else
        {
          state = ParserState::BeforeTID;
        }
      };
      break;
      default:
      {
        if (state != ParserState::EOFF) return false;
        eof = true;
      };
      break;
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
      // std::cout << "Might have next" << std::endl;
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
        readerr = true; // invalid stream
        return -1;
      }
      else if (result == TID_BOOLEAN)
      {
        if (ln > 1)
        {
          readerr = true; // invalid stream
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
    // std::cout << "Rlen: " << ln << std::endl;
    return result;
  }
  void stepin()
  {

    if (readerr) return;
    // std::cout << "Valuetid: " << valuetid << std::endl;
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
    // std::cout << "Stepping out " << std::endl;
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
    uint8_t *b = read(localremaining);
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
    for (int e = 0; e < exponent; e++) // this be dumb;
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
      // std::cout << "Fieldtype " << fieldtype << std::endl;
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
  void erval() { vtype = IonVtype::None; }
  void loadscalarvalue()
  {
    if (valuetid != TID_NULL && valuetid != TID_BOOLEAN && valuetid != TID_POSINT && valuetid != TID_NEGINT && valuetid != TID_FLOAT &&
        valuetid != TID_DECIMAL && valuetid != TID_SYMBOL && valuetid != TID_STRING && valuetid != TID_TIMESTAMP)
    {
      return;
    }
    // std::cout << "Load scalar val " << std::endl;
    if (valueisnull)
    {
      erval();
      return;
    }
    erval();
    switch (valuetid)
    {
    case TID_STRING:
    {
      char *buf = (char *)read(valuelen);
      if (readerr) return;
      assignIonValue(std::string(buf, valuelen));
    };
    break;
    case TID_POSINT:
    case TID_NEGINT:
    case TID_SYMBOL:
    {
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
          uint8_t *b = read();
          if (readerr) return;
          v = (v << 8) + b[0];
        }
        if (valuetid == TID_NEGINT)
        {
          v = -v;
        }
        assignIonValue(v);
      }
    };
    break;
    case TID_DECIMAL:
    {
      long long r = readdecimal();
      if (readerr) return;
      assignIonValue(r);
    };
    break;
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
  IonCatalogItem findcatalogitem(const std::string &name)
  {
    for (auto it = catalog.begin(); it != catalog.end(); ++it)
    {
      if (it->name == name)
      {
        return *it;
      }
    }
    return IonCatalogItem("-", -1, std::vector<std::string>()); // also dumb
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
        case SID_NAME:
        {
          name = stringvalue();
        };
        break;
        case SID_VERSION:
        {
          version = intvalue();
        };
        break;
        case SID_MAX_ID:
        {
          maxid = intvalue();
        };
        break;
        default:
          break;
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
      symbols.import_(table.symnames, (size_t)maxid > table.symnames.size() ? table.symnames.size() : maxid);
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
  int intvalue()
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

  std::string stringvalue()
  {
    // std::cout << "Stringvalue" << std::endl;
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
    // std::cout << "Stringvalue out " << sval<<std::endl;
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
      return std::vector<uint8_t>();
    }
    if (valueisnull)
    {
      return std::vector<uint8_t>();
    }
    uint8_t *buf = read(valuelen);
    if (readerr)
    {
      return std::vector<uint8_t>();
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
    // std::cout << "Annots " << ln<<std::endl;
    while (stream_pos < maxpos)
    {
      unsigned int nx = readvaruint();
      if (readerr) return;
      // std::cout << "Annotation " << nx << std::endl;
      annotations.push_back(nx);
    }
    valuetid = readtypeid();
  }
  void forceimport(const std::vector<std::string> &sym) { symbols.import_(sym, sym.size()); }
  std::string getfieldname()
  {
    if (valuefieldid == SID_UNKNOWN) return "";
    return symbols.findbyid(valuefieldid);
  }
  void checkversionmarker()
  {
    uint8_t *rd = read(sizeof(VERSION_MARKER));

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
  SymbolToken getfieldnamesymbol() { return SymbolToken(getfieldname(), valuefieldid); }
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
  std::vector<std::string> SYM_NAMESr = {"com.amazon.drm.Envelope@1.0",
                                         "com.amazon.drm.EnvelopeMetadata@1.0",
                                         "size",
                                         "page_size",
                                         "encryption_key",
                                         "encryption_transformation",
                                         "encryption_voucher",
                                         "signing_key",
                                         "signing_algorithm",
                                         "signing_voucher",
                                         "com.amazon.drm.EncryptedPage@1.0",
                                         "cipher_text",
                                         "cipher_iv",
                                         "com.amazon.drm.Signature@1.0",
                                         "data",
                                         "com.amazon.drm.EnvelopeIndexTable@1.0",
                                         "length",
                                         "offset",
                                         "algorithm",
                                         "encoded",
                                         "encryption_algorithm",
                                         "hashing_algorithm",
                                         "expires",
                                         "format",
                                         "id",
                                         "lock_parameters",
                                         "strategy",
                                         "com.amazon.drm.Key@1.0",
                                         "com.amazon.drm.KeySet@1.0",
                                         "com.amazon.drm.PIDv3@1.0",
                                         "com.amazon.drm.PlainTextPage@1.0",
                                         "com.amazon.drm.PlainText@1.0",
                                         "com.amazon.drm.PrivateKey@1.0",
                                         "com.amazon.drm.PublicKey@1.0",
                                         "com.amazon.drm.SecretKey@1.0",
                                         "com.amazon.drm.Voucher@1.0",
                                         "public_key",
                                         "private_key",
                                         "com.amazon.drm.KeyPair@1.0",
                                         "com.amazon.drm.ProtectedData@1.0",
                                         "doctype",
                                         "com.amazon.drm.EnvelopeIndexTableOffset@1.0",
                                         "enddoc",
                                         "license_type",
                                         "license",
                                         "watermark",
                                         "key",
                                         "value",
                                         "com.amazon.drm.License@1.0",
                                         "category",
                                         "metadata",
                                         "categorized_metadata",
                                         "com.amazon.drm.CategorizedMetadata@1.0",
                                         "com.amazon.drm.VoucherEnvelope@1.0",
                                         "mac",
                                         "voucher",
                                         "com.amazon.drm.ProtectedData@2.0",
                                         "com.amazon.drm.Envelope@2.0",
                                         "com.amazon.drm.EnvelopeMetadata@2.0",
                                         "com.amazon.drm.EncryptedPage@2.0",
                                         "com.amazon.drm.PlainText@2.0",
                                         "compression_algorithm",
                                         "com.amazon.drm.Compressed@1.0",
                                         "page_index_table"};
  // can not be bothered...
  for (int i = 1; i < 200; i++)
  {
    std::ostringstream s;
    s << "com.amazon.drm.VoucherEnvelope@" << (i);
    SYM_NAMESr.push_back(s.str());
  }
  return SYM_NAMESr;
}
void addprottable(BinaryIonParser *ion)
{
  if (!ion) return;
  ion->addtocatalog("ProtectedData", 1, SYM_NAMES());
}

int finIndexIn(const std::vector<std::string> &p, const std::string &val)
{
  for (size_t i = 0; i < p.size(); i++)
  {
    if (p[i] == val) return i;
  }
  return -1;
}

//--------------------------------------------------end ION
class BasicDecryptor
{
public:
  virtual bool decrypt(std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &iv, std::vector<uint8_t> &out) = 0;
};
class AesDecryptor : public BasicDecryptor
{
public:
  std::vector<uint8_t> key;
  AesDecryptor(const std::vector<uint8_t> &k) : key(k) {}
  virtual bool decrypt(std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &iv, std::vector<uint8_t> &out)
  {
    if (iv.size() != 16)
    {
      printf("Unsupported IV size %ld\n", iv.size());
      out.resize(0);
      return false;
    }
    out.resize(ciphertext.size());
    unsigned long padded_size = 0;
    plusaes::Error err = plusaes::decrypt_cbc(&ciphertext[0], ciphertext.size(), &key[0], key.size(), (unsigned char(*)[16]) & iv[0], &out[0],
                                              out.size(), &padded_size);
    if (err != plusaes::kErrorOk) return false;
    // printf("Padding %ld",padded_size);
    out.resize(out.size() - padded_size);
    return true;
  }
};

std::vector<uint8_t> HexToBytes(const std::string &hex)
{
  std::vector<uint8_t> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2)
  {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

std::vector<uint8_t> drmionHeader = HexToBytes("ea44524d494f4eee");

bool processPage(std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &iv, BasicDecryptor *decr, bool decompress, bool decrypt,
                 std::vector<uint8_t> &out)
{

  std::vector<uint8_t> msg;
  if (decrypt)
  {
    if (!decr->decrypt(ciphertext, iv, msg)) return false;
  }
  else
  {
    msg = ciphertext;
  }
  // printf("Got message %ld\n",msg.size());
  if (!decompress)
  {
    out = msg;
    return true;
  }
  if (msg[0] != 0)
  {
    printf("Unsupported compression type %d\n", (int)msg[0]);
    return false;
  }

  plz::PocketLzma p;
  std::vector<uint8_t> decompressed;
  // std::cout << "Lzma hex " << hexStr(&msg[1], msg.size()-1) << std::endl;
  plz::StatusCode status = p.decompress(&msg[1], msg.size() - 1, decompressed);
  // printf("Got decomp %ld\n",decompressed.size());
  if (status == plz::StatusCode::Ok)
  {
    out = decompressed;
    return true;
  }
  printf("LZMA decompression failed!\n"); // maybe throw?
  return false;
}
bool processDRMION(char *buf, size_t size, BasicDecryptor *decr, std::vector<uint8_t> &out, bool &has_encryption, std::string& keyname)
{
  BinaryIonParser bp((unsigned char *)buf, size, -1);
  addprottable(&bp);
  has_encryption = false;
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
      if (nm == "com.amazon.drm.EnvelopeMetadata@1.0" || nm == "com.amazon.drm.EnvelopeMetadata@2.0")
      {
         //printf("Typename %s\n",nm.c_str());
        bp.stepin();
        while (bp.hasnext())
        {
          bp.next();
          std::string tn = bp.getfieldname();
          //printf("Inner fieldname %s\n",tn.c_str());
          if (tn == "encryption_key") keyname = bp.stringvalue();
        
        }
        bp.stepout();
      }
      if (nm == "com.amazon.drm.EncryptedPage@1.0" || nm == "com.amazon.drm.EncryptedPage@2.0")
      {
        has_encryption = true;
        bool decompress = false;
        bool decrypt = true;
        std::vector<uint8_t> ct;
        std::vector<uint8_t> civ;
        bp.stepin();
        while (bp.hasnext())
        {
          bp.next();
          if (bp.gettypename() == "com.amazon.drm.Compressed@1.0") decompress = true;
          if (bp.getfieldname() == "cipher_text") ct = bp.lobvalue();
          if (bp.getfieldname() == "cipher_iv") civ = bp.lobvalue();
        }
        if (!ct.empty() && !civ.empty())
        {
          // std::cout <<"Got page " <<std::endl;
          std::vector<uint8_t> page;
          if (!processPage(ct, civ, decr, decompress, decrypt, page)) return false;
          // printf("Got page of size %ld\n", page.size());

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
            if (bp.gettypename() == "com.amazon.drm.Compressed@1.0") decompress = true;
            if (bp.getfieldname() == "data") plaintext = bp.lobvalue();
          }
          if (!plaintext.empty())
          {
            std::vector<uint8_t> page;
            if (!processPage(plaintext, plaintext, decr, decompress, decrypt, page)) return false;
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
bool read_file_to_vector(const std::string &filename, std::vector<char> &buffer)
{
  std::ifstream file(filename, std::ios::binary | std::ios::ate);

  if (!file.is_open())
  {  std::cerr << "Error: " << strerror(errno) << " (" << filename << ")" << std::endl;

    return false;
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  std::cout << "File size " << size << std::endl;
  buffer.resize(size);
  if (file.read(reinterpret_cast<char *>(buffer.data()), size))
  {
    return true;
  }

  return false;
}


std::vector<char> read_proc_file(const std::string& path) {
    // Open without std::ios::ate
    std::ifstream file(path, std::ios::binary);
    
    if (!file.is_open()) return {};

    // Iterators will read until EOF is reached
    return std::vector<char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

std::string read_file_to_string(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    
    if (!file.is_open()) return {};
    return std::string(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

bool get_drmion(const fs::path &path, std::vector<char> &buf)
{
  if (!fs::is_regular_file(path)) return false;
  if (!read_file_to_vector(path.string(), buf))
  {
    printf("Could not read file? \n");
    return false;
  }
  // std::cout <<"Got file " <<std::endl;
  if (buf.size() > drmionHeader.size() && memcmp(&drmionHeader[0], buf.data(), drmionHeader.size()) == 0)
  {
    return true;
  }
  return false;
}
std::vector<std::vector<uint8_t>> test_drmions_for_keys(const std::vector<fs::path> &paths, const std::vector<std::vector<uint8_t>> &keys,std::string& keyname)
{
  std::vector<std::vector<uint8_t>> ret = keys;
  bool found_encryption = false;
  if (keys.size() == 0)
  {
    printf("No key candidates!\n");
    return ret;
  }
  for (const auto &file : paths)
  {
    std::vector<char> drmion;
    if (!get_drmion(file, drmion))
    {
      continue;
    }
    bool has_encryption = false;
    std::vector<uint8_t> outme;
    std::cout << "Got drmion " << std::endl;
    for (auto key = ret.begin(); key != ret.end();)
    {
      AesDecryptor decr(*key);
      // std::cout <<"Got decr " << hexStr(&(*key)[0],16) <<std::endl;
      if (processDRMION(&drmion[8], drmion.size() - 16, &decr, outme, has_encryption,keyname))
      {
        ++key;
      }
      else
      {
        key = ret.erase(key);
      }
      if (has_encryption)
      {
        found_encryption = true;
      }
      else
      {
        break; // no point in continuing
      }
    }
    if (ret.size() <= 1) break; // only one candidate left or none worked
  }
  if (!found_encryption)
  {
    printf("No encryption in these \n");
    ret.resize(1);
  }
  return ret;
}
int processFile(const char *outputFile, const std::string &fname, const std::string &archivedName, BasicDecryptor *decr)
{

  size_t bl = 0;
  std::vector<char> buf;
  if (!read_file_to_vector(fname, buf))
  {
    printf("Could not read file? \n");
    return 1;
  }
  bl = buf.size();
  printf("Read file of %lu bytes\n", buf.size());
  if (bl == 0)
  {
    return 0;
  }
   std::string discard;
  if (bl > drmionHeader.size() && memcmp(&drmionHeader[0], buf.data(), drmionHeader.size()) == 0)
  {
    std::vector<uint8_t> outme;
    printf("Decrypting DRMION... \n");
    bool has_enc;
    if (processDRMION(&buf[8], bl - 16, decr, outme, has_enc,discard))
    {
      mz_bool status =
          mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), outme.data(), outme.size(), NULL, 0, MZ_BEST_COMPRESSION);
      if (!status)
      {
        printf("mz_zip_add_mem_to_archive_file_in_place of DRMION file failed!\n");
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
    mz_bool status = mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), buf.data(), bl, NULL, 0, MZ_BEST_COMPRESSION);
    if (!status)
    {
      printf("mz_zip_add_mem_to_archive_file_in_place of non-DRM file  failed!\n");
      return EXIT_FAILURE;
    }
  }

  return 0;
}

void kfx_scan(const fs::path& assets,std::vector<fs::path>& acc)
{
  for (const auto &entry : fs::directory_iterator(assets))
  {
    if (entry.is_directory())
    {
      kfx_scan(entry.path(),acc);
    }
    if(fs::is_regular_file(entry.path())&&entry.path().extension()==".kfx")
    {
      acc.push_back(entry.path());
    }
  }
}

bool process_assets(const std::string &bookid,const fs::path& kfx_path, std::map<std::string, std::vector<fs::path>>& att)
{
  fs::path metadir=kfx_path.parent_path()/(kfx_path.stem().string()+".sdr")/"assets";
  if (!fs::is_directory(metadir)) return false;
  std::vector<fs::path> vouchers;
  fs::path vouch=metadir/"voucher";
  if(fs::is_regular_file(vouch))
  {
    vouchers.push_back(vouch);
  }
  att["vouchers"]=vouchers;
  std::vector<fs::path> bf;
  bf.push_back(kfx_path);
  att["bookFiles"] = bf;
  std::vector<fs::path> resources;
  resources.push_back(kfx_path);
  kfx_scan(metadir,resources);
  att["resources"]=resources;
  return true;
}
void scan_folder_for_book_candidates(const fs::path &collection, std::vector<fs::path> &book_folders)
{
  for (const auto &entry : fs::directory_iterator(collection))
  {
  
      if(fs::is_regular_file(entry.path())&&entry.path().extension()==".kfx")
      {
        fs::path metadir=collection/(entry.path().stem().string()+".sdr");
         if (fs::is_directory(metadir))
         {
           std::cout << "Adding " << entry.path().filename() << " as book candidate" << std::endl;
           book_folders.push_back(entry.path());
         }
      }
    
    
  }
}



typedef void *(*mlc)(size_t);
mlc real_malloc;
typedef void (*fr)(void *);
fr real_free;
std::map<void *, size_t> allocations;
std::set<std::vector<uint8_t>> key_candidates;
void *my_malloc(size_t size)
{
  printf("Intercepted malloc call for %zu bytes\n", size);
  void *pt = real_malloc(size);
  if (size == 16)
  {
    allocations[pt] = 16;
  }
  return pt;
}
void my_free(void *pt)
{
  if (pt != nullptr)
  {
    auto fnd = allocations.find(pt);
    if (fnd != allocations.end())
    {
      std::cout << hexStr((uint8_t *)pt, 16) << std::endl;
      //key_candidates.insert(std::vector<uint8_t>((uint8_t *)pt, (uint8_t *)pt + 16));

      allocations.erase(fnd);
    }
  }
  free(pt);
}
typedef void *(*dlo)(const char *filename, int flag);
dlo real_dlopen=nullptr;
void *dlopen_new(const char *filename, int flag)
{
  printf("Dlopen: %s \n",filename);
  return real_dlopen(filename,flag);
}
typedef std::string * (*crstr)(std::string *me, std::string * other);
crstr real_mcreate;
void *mcreate_new(std::string *me, std::string * other)
{
  printf("mcreate_new: %s \n",other->c_str());
  return real_mcreate(me,other);
}
void delete_str(std::string* st)
{
 std::cout <<"Deleting string "<<std::endl;
 std::cout<<*st<<std::endl; 
}
//int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,ENGINE *impl,uchar *key,uchar *iv)
typedef int (*aesDecrypt)(void*,void*,void*,char*key,char*iv);
typedef int (*keylen)(const void *cipher);
aesDecrypt aesDecrypt_real;
keylen key_len_real;
int aesDecrypt_new(void*ctx,void*cipher,void*impl,char*key,char*iv)
{
  if(key_len_real(cipher)==16)
  {
  printf("AES decrypt called %p\n",aesDecrypt_real);
  std::cout <<hexStr((const unsigned char*)key,16)<<std::endl;
  //std::vector<char> vec(data, data + length);
  key_candidates.insert(std::vector<uint8_t>((uint8_t *)key, (uint8_t *)key + 16));
  }
  return aesDecrypt_real(ctx,cipher,impl,key,iv);
}

void install_hook(void *lib_symbol)
{
  real_malloc = (mlc)dlsym(RTLD_NEXT, "malloc");
  real_free = (fr)dlsym(RTLD_NEXT, "free");
  real_dlopen = (dlo)dlsym(RTLD_NEXT, "dlopen");
  real_mcreate = (crstr)dlsym(RTLD_NEXT, "_ZNSsC1ERKSs");
  aesDecrypt_real=(aesDecrypt)dlsym(dlopen("/usr/lib/libcrypto.so",RTLD_NOW),"EVP_DecryptInit_ex");
  key_len_real=(keylen)dlsym(dlopen("/usr/lib/libcrypto.so",RTLD_NOW),"EVP_CIPHER_key_length");
  plthook_t *plthook;

  if (plthook_open_by_address(&plthook, lib_symbol) != 0)
  {
    printf("could not create plthook\n");
    return;
  }

  //plthook_replace(plthook, "malloc", (void *)my_malloc, NULL);
  //plthook_replace(plthook, "free", (void *)my_free, NULL);
  //plthook_replace(plthook, "dlopen", (void *)dlopen_new, NULL);
  //plthook_replace(plthook, "_ZNSsC1ERKSs", (void *)mcreate_new, NULL);
 // plthook_replace(plthook, "_ZNSsD1Ev", (void *)delete_str, NULL);
  plthook_replace(plthook, "EVP_DecryptInit_ex", (void *)aesDecrypt_new, NULL);
  plthook_close(plthook);
}

void print_stacktrace() {
    void* array[10];
    size_t size = backtrace(array, 10);
    std::cerr << "--- Exception thrown: Backtrace ---" << std::endl;
    backtrace_symbols_fd(array, size, 2); // 2 is stderr
    exit(1);
}

std::vector<std::string> split_secrets(const std::string& secrfile)
{
    std::stringstream ss(secrfile);
    std::string item;
    std::vector<std::string> result;

    while (std::getline(ss, item, ',')) {
        result.push_back(item);
    }

    return result;
}

void updatemenufile(const std::vector<fs::path>&books)
{
  std::string expected_menu="/mnt/us/extensions/kfxdedrm/menu.json";
   std::ifstream file(expected_menu);
    if (!file.is_open())
    {
      throw std::runtime_error("Could not open file /mnt/us/extensions/kfxdedrm/menu.json for reading");
    }
    printf("Trying to update menu with %zu books \n",books.size());
    json data = json::parse(file);
    json alist=json::array();
    alist.push_back({{"name","Scan documents folder"},{"action", "bin/run_cmd.sh"},{"params","scan"},{"priority",1}});
    int p=2;
    for(const auto& pth:books)
    {
      std::string bname=pth.stem();
      std::string fpath=pth.string();
      alist.push_back({{"name",bname},{"action", "bin/run_cmd.sh"},{"params",std::string("dedrm \"")+fpath+"\""},{"priority",p}});
      p++;
    }
    if (data.contains("items") && data["items"].is_array()) 
   {
     for(auto& sub:data["items"])
     {
       if (sub.contains("items") && sub["items"].is_array()) 
   {
    for (auto& itm :sub["items"])
    {
      if (itm.contains("name")&&itm["name"].get<std::string>()=="Books")
      {
        printf("Found books \n");
        itm["items"]=alist;
        break;
      }
    }
   }
     }
   }
    file.close();
    std::ofstream outfile(expected_menu);
    outfile << data.dump(2); 
}
int main(int argc, char *argv[])
{
  printf("Kindle reader , %d arguments\n", argc);
  std::vector<fs::path> infolders;
  std::vector<fs::path> infiles;
  fs::path out_folder{"/mnt/us/dedrm"};
  infolders.push_back(fs::path("/mnt/us/documents"));

  std::string jdsn;
  std::vector<std::string> jsecrets;
  std::string mode="decrypt_all";
  fs::path sngl;
  if (argc>1)
  {
    std::string cmd=argv[1];
    if(cmd=="test") mode="test";
    if(cmd=="scan") mode="scan";
    if(cmd=="keyfile") mode="keyfile";
    if(cmd=="dedrm") 
    {
      if(argc<3)
      {
        printf("Requires two arguments, command and book name\n");
        return 2;
      }
      mode="decrypt_one";
      sngl=fs::path(std::string(argv[2]));
    }
  }
  if(mode=="scan")
  {
    for (auto &inpath : infolders)
    {
    scan_folder_for_book_candidates(inpath, infiles);
    }
    updatemenufile(infiles);
    return 0;
  }
  // open shared library
  fs::path libPath;
  void *prn =  dlopen("libYJSDK-shared.so", RTLD_LAZY);
  if (prn == nullptr)
  {
    printf("Could not open shared library at :  %s\n", dlerror());
    return 2;
  }
  typedef void (*getinst)(std::shared_ptr<void*>&res);
  getinst getsec=(getinst)dlsym(prn, "_ZN5yjsdk13IBookSecurity11getInstanceERSt10shared_ptrIS0_E");
   std::shared_ptr<void*> booksec;
  getsec(booksec);
  if(booksec.get()==nullptr)
  {
    printf("Could not get booksec");
    return 3;
  }
  void** vtable=*(void***)booksec.get();
  typedef void (*setParams)( void*,std::map<std::string,std::vector<std::string>>&p);
  setParams setSec=(setParams)vtable[4];
  typedef void (*attachVouch)( void*,const char* );
  attachVouch attachv=(attachVouch)vtable[5];
  std::string clientid=read_file_to_string("/proc/usid");
  void *pv = dlsym(prn, "_ZN5yjsdk11BookFactory7getBookEPKcSt10shared_ptrINS_13IBookSecurityEERS3_INS_12IDigitalBookEE");
  if(pv==nullptr)
  {
    printf("Could not find getBook, check libYJSDK-shared.so library variant\n");
    return 4;
  }
  if(mode=="test")
  {
    std::map<std::string,std::vector<std::string>> testpars;
    std::vector<std::string> clientids;
    std::vector<std::string> fakesecrets;
    fakesecrets.push_back("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    fakesecrets.push_back("ffffffffffffffffffffffffffffffff");
    clientids.push_back(clientid);
    testpars["CLIENT_ID"]=clientids;
    testpars["ACCOUNT_SECRET"]=fakesecrets;
    setSec(booksec.get(),testpars); //it would throw if incompatible, hopefully;
    return 0;
  }
  
  std::cout << "Selected Out folder: " << out_folder << std::endl;

  // prep output folder
  if (!fs::exists(out_folder))
  {
    fs::create_directory(out_folder);
    std::cout << "Created directory: " << out_folder << std::endl;
  }
  if (!fs::is_directory(out_folder))
  {
    printf("Output folder %s could not be created or is a file\n", out_folder.string().c_str());
    return -3;
  }
  

  

// ibooksec getinstance _ZN5yjsdk13IBookSecurity11getInstanceERSt10shared_ptrIS0_E
 
  
  std::string sz="sizelarge";
  printf("usid length %zu string legnth: %zu\n",clientid.size(),sizeof(sz));
  std::map<std::string,std::vector<std::string>> secpars;
  std::vector<std::string> cl1;
  std::string secrcomb=read_file_to_string("/var/local/java/prefs/acsr");
  std::vector<std::string> asecrets;
  std::cout << "DSN " <<clientid <<std::endl;
  if(secrcomb.size()>2)
  {
    asecrets=split_secrets(secrcomb);
    for(auto& sec:asecrets)
    {
      std::cout << "Secr: " << sec << std::endl;
    }
  }
  cl1.push_back(clientid);
  secpars["CLIENT_ID"]=cl1;
  secpars["ACCOUNT_SECRET"]=asecrets;
  install_hook((void*)getsec);
  
  printf("Booksec: %p\n",booksec.get());
  
  printf("Vtable: %p\n",vtable);
  
  printf("Found getbook %p \n", pv);
 
 typedef int (*getbook1)(const char *,std::shared_ptr<void*>&booksec, std::shared_ptr<void*>&);
  getbook1 gb=(getbook1)pv;
  if(mode=="decrypt_one")
  {
    infiles.clear();
    infiles.push_back(sngl);
  }
  
  if(mode=="decrypt_all" ||mode=="keyfile")
  {
  for (auto &inpath : infolders)
  {
    scan_folder_for_book_candidates(inpath, infiles);
  }
  }
std::ofstream outkeyfile;
 if(mode=="keyfile")
 {
   outkeyfile.open("/mnt/us/dedrm/keyfile.txt");
 }
  key_candidates.clear();
  for (auto &itm : infiles)
  {
    fs::path metadata_path = itm ;
    std::string bookid = itm.stem().string();
    std::cout << bookid << std::endl;
    std::map<std::string, std::vector<fs::path>> metadata;
    if (process_assets(bookid, itm, metadata))
    {
      key_candidates.clear();
       std::shared_ptr<void*> nbook=nullptr;
       std::shared_ptr<void*> nbooksec=nullptr;
       getsec(nbooksec);
       setSec(nbooksec.get(),secpars);
       for(auto&v:metadata["vouchers"])
       {
        attachv(nbooksec.get(),v.string().c_str());
       }
       std::cout << metadata["bookFiles"][0]<<std::endl;
      int res= gb(metadata["bookFiles"][0].string().c_str(),nbooksec,nbook);
      printf("Open book result: %d \n",res);
       nbook=nullptr;
       nbooksec=nullptr;
      if(res!=0)
      {
        printf("Could not open book, skipping \n");
        continue;
      }
      allocations.clear();
      std::vector<std::vector<uint8_t>> keyset(key_candidates.begin(), key_candidates.end());
      std::cout << keyset.size() << " key candidates" << std::endl;
      bool no_enc=false;
      if(keyset.size()==0) 
      {
        no_enc=true;
        std::vector<uint8_t> dummy(16);
        keyset.push_back(dummy);
      }
      std::string keyname;
      std::vector<std::vector<uint8_t>> result = test_drmions_for_keys(metadata["resources"], keyset,keyname);
      std::cout <<"Key name: " <<keyname <<std::endl;
      if (result.size() == 1)
      {

        std::cout << "Found key: " << hexStr(result[0].data(), 16) << std::endl;
        if(mode=="keyfile")
        {
          if(!no_enc)
          {
        printf("Adding to keyfile\n");
        outkeyfile << keyname<<"$secret_key:"<< hexStr(result[0].data(), 16) <<std::endl;
          }
         
        }
        else 
        {
        AesDecryptor decr(result[0]);
        fs::path output_path = out_folder / fs::path(bookid + ".kfx-zip");
        std::cout << "Generating " << output_path << std::endl;
        std::cout << "Removal result " << std::remove(output_path.string().c_str()) << std::endl; // clear if exists
        for (auto fl : metadata["resources"])
        {
          processFile(output_path.string().c_str(), fl.string(), fl.filename().string(), &decr);
        }
        }
        printf("Book processed \n");
      }

      printf("Done opening book ~~ \n");
    }
    else
    {
      std::cout << "Invalid or unsupported metadata" << std::endl;
    }
  }
   if(mode=="keyfile")
 {
   outkeyfile.close();
 }
  printf("DeDRM all done.\n");
}
