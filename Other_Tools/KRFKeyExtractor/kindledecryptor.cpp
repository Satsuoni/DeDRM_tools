
#define _FILE_OFFSET_BITS 64
#include "json.hpp"
#include "miniz.h" //https://github.com/richgel999/miniz/releases
#include "plthook.h"
#include <android/dlext.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <jni.h>
#include <map>
#include <set>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#define POCKETLZMA_LZMA_C_DEFINE
#include "plusaes.hpp" //https://github.com/kkAyataka/plusaes/releases
#include "pocketlzma.hpp" //https://github.com/SSBMTonberry/pocketlzma ,but needs fixing, in decompress, replace (value << (i * 8)); with ((size_t)value << (i * 8));

namespace fs = std::filesystem;
using json = nlohmann::json;

static std::string hexStr(const uint8_t *data, int len)
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
bool processDRMION(char *buf, size_t size, BasicDecryptor *decr, std::vector<uint8_t> &out, bool &has_encryption)
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
      if (nm == "com.amazon.drm.EncryptedPage@1.0" || nm == "com.amazon.drm.EncryptedPage@2.0")
      {
        has_encryption = true;
        bool decompress = false;
        bool decrypt = true;
        std::vector<uint8_t> ct;
        std::vector<uint8_t> civ;
        // std::vector<uint8_t> data(buffer, buffer + size);
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
  {
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
std::vector<std::vector<uint8_t>> test_drmions_for_keys(const std::vector<fs::path> &paths, const std::vector<std::vector<uint8_t>> &keys)
{
  std::vector<std::vector<uint8_t>> ret = keys;
  bool found_encryption = false;
  if (keys.size() == 0)
  {
    printf("No key candidates!");
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
      if (processDRMION(&drmion[8], drmion.size() - 16, &decr, outme, has_encryption))
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

  if (bl > drmionHeader.size() && memcmp(&drmionHeader[0], buf.data(), drmionHeader.size()) == 0)
  {
    std::vector<uint8_t> outme;
    printf("Decrypting DRMION... \n");
    bool has_enc;
    if (processDRMION(&buf[8], bl - 16, decr, outme, has_enc))
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

// Java overloads, etc...

#define HELPER_LIB_DSO "libnativehelper.so"

typedef jint (*JNI_CreateJavaVM_t)(JavaVM **p_vm, JNIEnv **p_env, void *vm_args);

typedef struct JniInvocation
{
  const char *jni_provider_library_name;
  void *jni_provider_library;
  jint (*JNI_GetDefaultJavaVMInitArgs)(void *);
  jint (*JNI_CreateJavaVM)(JavaVM **, JNIEnv **, void *);
  jint (*JNI_GetCreatedJavaVMs)(JavaVM **, jsize, jsize *);
} JniInvocationImpl;

/* CTX */
typedef struct JavaContext
{
  JavaVM *vm;
  JNIEnv *env;
  JniInvocationImpl *invoc;
} JavaCTX;

typedef JniInvocationImpl *(*JniInvocationCreate_t)();
typedef bool (*JniInvocationInit_t)(JniInvocationImpl *, const char *);

int initialize_java_environment(JavaCTX *ctx, const std::string &base_apk)
{
  JNI_CreateJavaVM_t JNI_CreateJVM;

  void *lib_native_helper;
  JniInvocationImpl *(*JniInvocationCreate)();

  bool (*JniInvocationInit)(JniInvocationImpl *, const char *);

  printf("[+] Starting initialization\n");

  if ((lib_native_helper = dlopen(HELPER_LIB_DSO, RTLD_NOW)) == NULL)
  {
    fprintf(stderr, "[!] Can't obtain a handle to the library: %s\n", HELPER_LIB_DSO);
    return JNI_ERR;
  }

  if ((JNI_CreateJVM = (JNI_CreateJavaVM_t)dlsym(lib_native_helper, "JNI_CreateJavaVM")) == NULL)
  {
    fprintf(stderr, "[!] Can't obtain a handle to JNI_CreateJavaVM\n");
    return JNI_ERR;
  }

  if ((JniInvocationCreate = (JniInvocationCreate_t)dlsym(lib_native_helper, "JniInvocationCreate")) == NULL)
  {
    fprintf(stderr, "[!] Can't obtain a handle to JniInvocationCreate\n");
    return JNI_ERR;
  }

  if ((JniInvocationInit = (JniInvocationInit_t)dlsym(lib_native_helper, "JniInvocationInit")) == NULL)
  {
    fprintf(stderr, "[!] Can't obtain a handle to JniInvocationInit\n");
    return JNI_ERR;
  }

  ctx->invoc = JniInvocationCreate();
  JniInvocationInit(ctx->invoc, "libart.so");

  // JavaVMOption options[jvm_nb_options];
  const std::string classpath = "-Djava.class.path=" + base_apk + ":" + "/system/framework/framework.jar";
  JavaVMOption options[4];
  options[0].optionString = classpath.c_str();
  options[1].optionString = "-agentlib:jdwp=transport=dt_android_adb,suspend=n,server=y";
  options[2].optionString = "-Djava.library.path=/data/local/tmp";
  options[3].optionString = "-verbose:jni";

  JavaVMInitArgs args;
  args.version = JNI_VERSION_1_6;
  args.nOptions = 4;
  args.options = options;
  args.ignoreUnrecognized = JNI_TRUE;

  jint status = JNI_CreateJVM(&ctx->vm, &ctx->env, &args);

  if (status == JNI_ERR)
  {
    printf("[!] Can't create java vm/env \n");
    return JNI_ERR;
  }

  printf("[+] Initialization completed successfully.\n \
    [+]Java VM pointer: %p\n \
    [+]Java env pointer: %p\n",
         ctx->vm, ctx->env);

  return JNI_OK;
}

typedef jmethodID (*GetMethodID_t)(JNIEnv *env, jclass clazz, const char *name, const char *sig);
GetMethodID_t GetMethodID_old;
jmethodID GetMethodID_repl(JNIEnv *env, jclass clazz, const char *name, const char *sig)
{
  // printf("Called GetMethodID %s %s \n",name,sig);
  return GetMethodID_old(env, clazz, name, sig);
}

typedef jclass (*FindClass_t)(JNIEnv *env, const char *name);
FindClass_t FindClass_old;

std::map<std::string, jclass> jclasses;
std::map<jobject, jobject> jreferences;
jclass FindClass_repl(JNIEnv *env, const char *name)
{

  jclass cls = FindClass_old(env, name);
  // printf("Called FindClass %s %p\n", name,cls);
  jclasses[name] = cls;
  return cls;
}

typedef jobject (*NewGlobalRef_t)(JNIEnv *env, jobject obj);
NewGlobalRef_t NewGlobalRef_old;
jobject NewGlobalRef_repl(JNIEnv *env, jobject obj)
{
  // printf("Entering Newglobalref\n");
  if (obj == (jobject)(0xfb00b5))
  {
    jobject fake = (jobject)(0xb055);
    jreferences[fake] = obj;
    return fake;
  }
  jobject ret = NewGlobalRef_old(env, obj);
  // printf("Casting %p to global ref %p \n",obj,ret);
  jreferences[ret] = obj;
  return ret;
}

typedef jobject (*CallObjectMethodV_t)(JNIEnv *, jobject, jmethodID, va_list);

CallObjectMethodV_t call_old;
jobject CallObjectMethod_repl(JNIEnv *env, jobject obj, jmethodID methodID, ...)
{
  va_list args;
  va_start(args, methodID);
  // printf("Called CallObjectMethod with object %p \n",obj);
  if (obj == nullptr)
    return (jobject)0xbeefdead; // bypass lack of proper android app and get
                                // ANDROID_ID in  another way
  if (obj == (jobject)0xbeefdead) return (jobject)0xbeefdead;
  jobject ret = call_old(env, obj, methodID, args);
  va_end(args);
  return ret;
}

typedef jobject (*CallStaticObjectMethodV_t)(JNIEnv *env, jclass clazz, jmethodID methodID, va_list args);
CallStaticObjectMethodV_t callstatic_old;
jobject CallStaticObjectMethod_repl(JNIEnv *env, jclass clazz, jmethodID methodID, ...)
{
  va_list args;
  va_start(args, methodID);
  // printf("Called CallStaticObjectMethod with class  %p \n",clazz);
  // if(obj==nullptr) return (jobject)0xaa33;
  // if(obj==(jobject)0xaa33) return (jobject)0xaa33;
  // if (clazz == jclasses["android/provider/Settings$Secure"])
  //{
  // const char *cString = android_id.c_str();
  // jstring jniString = env->NewStringUTF(cString);
  // va_end(args);
  // return (jobject)jniString;
  //}
  jobject ret = callstatic_old(env, clazz, methodID, args);
  va_end(args);
  return ret;
}
typedef jobject (*NewObjectV_t)(JNIEnv *, jclass, jmethodID, va_list args);

// check down the reference tree to an actual object
bool in_ref(jobject ref, jobject origin)
{
  auto fnd = jreferences.find(ref);
  if (fnd == jreferences.end()) return false;
  if (fnd->second == origin) return true;
  return in_ref(fnd->second, origin);
}
NewObjectV_t NewObjectV_old;
jobject NewObjectV_repl(JNIEnv *env, jclass clazz, jmethodID methodID, va_list args)
{

  // printf("Called NewObjectV with class %p\n",clazz);
  if (clazz == jclasses["android/os/Handler"] || in_ref(clazz, jclasses["android/os/Handler"]))
  { // fake android.os.handler since it is not necessary
    printf("Faking handler  \n");
    // va_arg(args,int);
    return (jobject)0xfb00b5;
  }
  jobject ret = NewObjectV_old(env, clazz, methodID, args);
  return ret;
}
typedef jboolean (*CallBooleanMethodV_t)(JNIEnv *env, jobject obj, jmethodID methodID, va_list args);
CallBooleanMethodV_t CallBooleanMethodV_old;
jboolean CallBooleanMethodV_repl(JNIEnv *env, jobject obj, jmethodID methodID, va_list args)
{
  // printf("Called CallBooleanMethodV on object %p\n",obj);
  jboolean ret = CallBooleanMethodV_old(env, obj, methodID, args);
  return ret;
}

typedef jfieldID (*GetStaticFieldID_t)(JNIEnv *env, jclass clazz, const char *name, const char *sig);
GetStaticFieldID_t GetStaticFieldID_old;
jfieldID GetStaticFieldID_repl(JNIEnv *env, jclass clazz, const char *name, const char *sig)
{
  // printf("Called GetStaticFieldID %s %s \n",name,sig);
  return GetStaticFieldID_old(env, clazz, name, sig);
}

std::string getArchitectureName()
{
#if defined(__i386__)
  return "x86";
#elif defined(__x86_64__)
  return "x86_64";
#elif defined(__arm__)
  return "armeabi-v7a"; // Or potentially other ARM variants like armeabi
#elif defined(__aarch64__)
  return "arm64-v8a";
#else
  return "unknown";
#endif
}

fs::path find_base_app_path()
{
  const std::string subst = "com.amazon.kindle";

  fs::path dir_path{"/data/app/"};

  if (!fs::exists(dir_path))
  {
    printf("/data/app does not exist or cannot be accessed\n");
    return "";
  }
  // Enumerate directory contents

  for (const auto &entry : fs::directory_iterator(dir_path))
  {
    if (entry.is_directory())
    {
      for (const auto &secondary : fs::directory_iterator(entry.path()))
      {
        if (secondary.is_directory())
        {
          std::string path_str = secondary.path().filename().string();
          if (path_str.find(subst) != std::string::npos)
          {
            return secondary.path();
          }
        }
      }
    }
  }
  return "";
}
// create namespace to replace LD_LIBRARY_PATH bs
static struct android_namespace_t *(*_create_namespace)(const char *name, const char *ld_library_path, const char *default_library_path,
                                                        uint64_t type, const char *permitted_when_isolated_path,
                                                        struct android_namespace_t *parent_namespace) = nullptr;
static struct android_namespace_t *create_namespace(const char *name, const char *ld_library_path, const char *default_library_path, uint64_t type,
                                                    const char *permitted_when_isolated_path, struct android_namespace_t *parent_namespace)
{
  if (!_create_namespace)
  {
    void *libdl_handle;
    char *error;
    libdl_handle = dlopen("libdl_android.so", RTLD_NOW);
    if (!libdl_handle)
    {
      printf("error opening libdl.so: %s\n", dlerror());
      return nullptr;
    }
    _create_namespace =
        (struct android_namespace_t * (*)(const char *, const char *, const char *, uint64_t, const char *, struct android_namespace_t *))
            dlsym(libdl_handle, "android_create_namespace");

    if (_create_namespace == nullptr)
    {
      if ((error = dlerror()) != nullptr && strcmp(error, "undefined symbol") < 0)
        printf("error opening android_create_namespace in libdl.so: %s\n", error);
      else printf("error opening android_create_namespace in libdl.so");
      return nullptr;
    }
  }
  return _create_namespace(name, ld_library_path, default_library_path, type, permitted_when_isolated_path, parent_namespace);
}

void *load_custom_library(const char *lib_dir, const char *lib_path)
{

  struct android_namespace_t *ns = create_namespace("my_custom_ns",
                                                    lib_dir, // ld_library_path: Search here first
                                                    NULL,    // default_library_path
                                                    2,       // type: 2 is shared, not sure why it is needed, but 0 does not work.
                                                    NULL,    // permitted_path
                                                    NULL     // parent (NULL uses the default namespace)
  );
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns;

  void *handle = android_dlopen_ext(lib_path, RTLD_NOW, &extinfo);

  if (!handle)
  {
    fprintf(stderr, "android_dlopen_ext failed: %s\n", dlerror());
  }
  else
  {
    printf("Library loaded successfully at %p\n", handle);
  }
  return handle;
}

void *load_drm_lib_by_name(const fs::path &base_app_path, const std::string &name, fs::path &libPath)
{
  const fs::path lib = base_app_path / "lib";
  for (const auto &entry : fs::directory_iterator(lib))
  {
    if (entry.is_directory())
    {
      for (const auto &secondary : fs::directory_iterator(entry.path()))
      {
        if (secondary.path().filename().string() == name)
        {

          std::cout << entry.path() << std::endl;
          void *prn = load_custom_library(entry.path().c_str(), secondary.path().string().c_str());
          if (prn != nullptr)
          {
            std::cout << "Opened lib at" << secondary.path().string() << std::endl;
            libPath = entry.path();
            return prn;
          }
        }
      }
    }
  }
  return nullptr;
}

void scan_folder_for_book_candidates(const fs::path &collection, std::vector<fs::path> &book_folders)
{
  for (const auto &entry : fs::directory_iterator(collection))
  {
    if (entry.is_directory())
    {
      if (fs::is_regular_file(entry.path() / ".metadata"))
      {
        std::cout << "Adding " << entry.path().filename() << " as book candidate" << std::endl;
        book_folders.push_back(entry.path());
      }
    }
  }
}

jclass ArrayList;
jmethodID alConstr;
jmethodID alAdd;
jclass jFile;
jmethodID jConstr;
bool process_metadata(const std::string &bookid, const fs::path &metadata_path, std::map<std::string, std::vector<fs::path>> &output)
{
  if (!fs::exists(metadata_path) || !fs::is_regular_file(metadata_path))
  {
    std::cerr << "Error: File " << metadata_path << "does not exist or is not a file." << std::endl;
    return false;
  }

  try
  {
    // 2. Open the file
    std::ifstream file(metadata_path);
    if (!file.is_open())
    {
      throw std::runtime_error("Could not open file for reading");
    }

    // 3. Parse JSON directly from the stream
    json data = json::parse(file);

    // Access data example
    if (!data.contains("mimeType"))
    {
      std::cout << "Not a valid metadata, no mimetype " << std::endl;
      return false;
    }
    if (!data.contains("manifest"))
    {
      std::cout << "Not a valid metadata, no manifest " << std::endl;
      return false;
    }
    if (data["mimeType"] != "application/x-kfx-ebook")
    {
      std::cout << bookid << "is not a KFX book, use another way" << std::endl;
      return false;
    }
    json manifest = json::parse(data["manifest"].get<std::string>());
    std::vector<std::string> bases;
    std::vector<std::string> attachables;
    std::vector<std::string> vouchers;

    for (const auto &item : manifest["resources"])
    {
      std::string type = item["type"];
      if (type == "KINDLE_MAIN_BASE")
      {
        bases.push_back(item["id"]);
        attachables.push_back(item["id"]); // later used for full processing
      }
      if (type == "KINDLE_MAIN_ATTACHABLE" || type == "KINDLE_MAIN_METADATA")
      {
        attachables.push_back(item["id"]);
      }
      if (type == "DRM_VOUCHER")
      {
        vouchers.push_back(item["id"]);
      }
    }
    if (bases.size() > 1)
    {
      printf("Unusual book with id %s with several entry points, using first one", bookid.c_str());
      while ((bases.size() > 1))
      {
        // attachables.push_back(bases.back()); it is already in attachables
        bases.pop_back();
      }
    }
    fs::path bookdir = metadata_path.parent_path();
    std::vector<fs::path> bookFiles;
    for (const auto &itm : bases)
    {
      bookFiles.push_back(bookdir / fs::path(itm + ".kfx"));
    }
    output["bookFiles"] = bookFiles;

    std::vector<fs::path> containers;
    for (const auto &itm : attachables)
    {
      containers.push_back(bookdir / fs::path(itm + ".kfx"));
    }
    output["resources"] = containers;
    std::vector<fs::path> vouch;
    for (const auto &itm : vouchers)
    {
      vouch.push_back(bookdir / fs::path(itm + ".ast"));
    }
    output["vouchers"] = vouch;
  }
  catch (json::parse_error &e)
  {
    std::cerr << "JSON Parse Error: " << e.what() << std::endl;
  }
  catch (const std::exception &e)
  {
    std::cerr << "General Error: " << e.what() << std::endl;
  }
  return true;
}

enum prevCommand
{
  NONE,
  DATAFOLDER,
  APPFOLDER,
  OUTFOLDER,
  INFOLDER,
  INFILE,
  CREDS
};

typedef void *(*mlc)(size_t);
mlc real_malloc;
typedef void (*fr)(void *);
fr real_free;
std::map<void *, size_t> allocations;
std::set<std::vector<uint8_t>> key_candidates;
void *my_malloc(size_t size)
{
  // printf("Intercepted malloc call for %zu bytes\n", size);
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
      key_candidates.insert(std::vector<uint8_t>((uint8_t *)pt, (uint8_t *)pt + 16));

      allocations.erase(fnd);
    }
  }
  free(pt);
}

int pthread_mutex_lock_dummy(void *p)
{
  printf("Locking mutex %p\n", p);
  return 0;
}
void pthread_mutex_lock_dummy_std(void *p)
{
  // printf("Locking std::mutex %p\n",p);
  // return ;
}
int pthread_mutex_unlock_dummy(void *) { return 0; }
void pthread_mutex_unlock_dummy_std(void *)
{
  // return 0;
}
int pthread_mutex_destroy_dummy(void *p)
{
  printf("Destroying mutex %p\n", p);
  return 0;
}

void install_hook(void *lib_symbol)
{
  real_malloc = (mlc)dlsym(RTLD_NEXT, "malloc");
  real_free = (fr)dlsym(RTLD_NEXT, "free");
  plthook_t *plthook;

  if (plthook_open_by_address(&plthook, lib_symbol) != 0)
  {
    printf("could not plthook\n");
    return;
  }

  plthook_replace(plthook, "malloc", (void *)my_malloc, NULL);
  plthook_replace(plthook, "free", (void *)my_free, NULL);
  // std::cout <<"Mutex lock " << plthook_replace(plthook, "pthread_mutex_lock",
  // (void*)pthread_mutex_lock_dummy, NULL) <<std::endl;
  // replace stdlib mutex locks to avoid crash on exit
  plthook_replace(plthook, "_ZNSt6__ndk15mutex4lockEv", (void *)pthread_mutex_lock_dummy_std, NULL);
  plthook_replace(plthook, "_ZNSt6__ndk15mutex6unlockEv", (void *)pthread_mutex_unlock_dummy_std, NULL);
  // plthook_replace(plthook, "pthread_mutex_unlock",
  // (void*)pthread_mutex_unlock_dummy, NULL); plthook_replace(plthook,
  // "pthread_mutex_destroy", (void*)pthread_mutex_destroy_dummy, NULL);
  plthook_close(plthook);
}
jobject createJavaFile(JNIEnv *env, const char *path)
{
  jstring jPath = env->NewStringUTF(path);
  jobject fileObject = env->NewObject(jFile, jConstr, jPath);
  return fileObject;
}

jobject createJavaFileList(JNIEnv *env, const std::vector<fs::path> &paths)
{
  jobject ret = env->NewObject(ArrayList, alConstr);
  for (auto &pth : paths)
  {
    env->CallBooleanMethod(ret, alAdd, createJavaFile(env, pth.string().c_str()));
  }
  return ret;
}

void trigger_java_gc(JNIEnv *env)
{
  jclass systemClass = env->FindClass("java/lang/System");
  if (systemClass != nullptr)
  {
    jmethodID gcMethod = env->GetStaticMethodID(systemClass, "gc", "()V");
    if (gcMethod != nullptr)
    {
      env->CallStaticVoidMethod(systemClass, gcMethod);
    }
  }
}

int main(int argc, char *argv[])
{
  printf("Kindle reader , %d arguments\n", argc);

  fs::path datafolder{"/data/data/com.amazon.kindle/"};
  fs::path base_app = find_base_app_path();
  std::vector<fs::path> infolders;
  std::vector<fs::path> infiles;
  fs::path out_folder{"/storage/emulated/0/Download/bookz"};
  fs::path credentials{"./credentials.json"};
  if (argc == 1)
  {
    printf("Command line flags:\n -f <foldername> : add input book folder\n");
    printf("-d <foldername> :sets app data folder, default: %s \n", datafolder.string().c_str());
    printf("-o <foldername> :sets output folder, default: %s \n", out_folder.string().c_str());
    printf("-c <filename> :sets credential json file, default: %s\n", credentials.string().c_str());
    printf("-b <foldername> :sets base app folder (where base.apk is), "
           "default: %s \n",
           base_app.string().c_str());
    printf("-i <foldername> :input folder with books subfolders, can be "
           "several, default  "
           "/storage/emulated/0/Android/data/com.amazon.kindle/files/ \n");
  }
  //"/storage/emulated/0/Android/data/com.amazon.kindle/files/"
  // parse command line
  prevCommand command = prevCommand::NONE;
  for (int i = 1; i < argc; i++)
  {
    std::string en = std::string(argv[i]);
    std::cout << "Cmd " << en << std::endl;
    switch (command)
    {
    case prevCommand::NONE:
    {
      if (en == "-d") command = prevCommand::DATAFOLDER;
      if (en == "-b") command = prevCommand::APPFOLDER;
      if (en == "-o") command = prevCommand::OUTFOLDER;
      if (en == "-f") command = prevCommand::INFILE;
      if (en == "-i") command = prevCommand::INFOLDER;
      if (en == "-c") command = prevCommand::CREDS;
      if (command == prevCommand::NONE)
      {
        std::cout << "Unknown flag " << en << std::endl;
      };
    };
    break;
    case prevCommand::DATAFOLDER:
    {
      datafolder = fs::path(en);
      command = prevCommand::NONE;
    };
    break;
    case prevCommand::APPFOLDER:
    {
      base_app = fs::path(en);
      command = prevCommand::NONE;
    };
    break;
    case prevCommand::OUTFOLDER:
    {
      out_folder = fs::path(en);
      command = prevCommand::NONE;
    };
    break;
    case prevCommand::INFOLDER:
    {
      fs::path pth = fs::path(en);
      if (fs::is_directory(pth))
      {
        std::cout << "Adding input collection folder " << pth << std::endl;
        infolders.push_back(pth);
      }
      else
      {
        std::cout << "Folder " << pth << " is not a folder" << std::endl;
      }
      command = prevCommand::NONE;
    };
    break;
    case prevCommand::CREDS:
    {
      fs::path pth = fs::path(en);
      credentials = pth;
    };
    break;
    case prevCommand::INFILE:
    {
      fs::path pth = fs::path(en);
      if (fs::is_directory(pth) && fs::is_regular_file(pth / ".metadata"))
      {
        std::cout << "Adding input book folder " << pth << std::endl;
        infiles.push_back(pth);
      }
      else
      {
        std::cout << "Folder " << pth << " is not a directory or does not have .metadata" << std::endl;
      }
      command = prevCommand::NONE;
    };
    break;
    default:
      printf("Should not go here");
      break;
    }
  }
  if (!fs::exists(credentials) || !fs::is_regular_file(credentials))
  {
    std::cerr << "Error: File " << credentials << "does not exist or is not a file." << std::endl;
    exit(1);
  }
  std::string jdsn;
  std::vector<std::string> jsecrets;
  try
  {
    // 2. Open the file
    std::ifstream file(credentials);
    if (!file.is_open())
    {
      throw std::runtime_error("Could not open file for reading");
    }

    // 3. Parse JSON directly from the stream
    json data = json::parse(file);
    jdsn = data["dsn"];
    jsecrets = data["secrets"];
  }
  catch (json::parse_error &e)
  {
    std::cerr << "JSON Parse Error in credentials: " << e.what() << std::endl;
    exit(1);
  }
  catch (const std::exception &e)
  {
    std::cerr << "General Error: " << e.what() << std::endl;
    exit(1);
  }
  if (infolders.size() == 0 && infiles.size() == 0)
  {
    fs::path def{"/storage/emulated/0/Android/data/com.amazon.kindle/files/"};
    if (!fs::is_directory(def))
    {
      printf("Cannot find any input folders or files \n");
      return -2;
    }
    infolders.push_back(def);
  }
  std::cout << "Selected Datafolder: " << datafolder << std::endl;
  std::cout << "Selected App folder: " << base_app << std::endl;
  std::cout << "Selected Out folder: " << out_folder << std::endl;
  std::cout << "Selected Credential file: " << credentials << std::endl;
  fs::path libdir = base_app / "lib" / getArchitectureName();
  std::cout << " Libdir is " << libdir << std::endl;

  // fs::path drmcore_sharedlib = libdir / "libDrmManagerCore.so";
  fs::path base_apk = base_app / "base.apk";
  // prep folder
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
  // open shared library

  fs::path libPath;
  void *prn = load_drm_lib_by_name(base_app, "libKindleAndroidNativeBundlerJNI.so",
                                   libPath); // dlopen(drmcore_sharedlib.string().c_str(), RTLD_LAZY);
  if (prn == nullptr)
  {
    printf("Could not open shared library at :  %s\n", dlerror());
    return 2;
  }

  // init java
  JavaCTX ctx;
  int status = 0;
  if ((status = initialize_java_environment(&ctx, base_apk.string())) != 0)
  {
    printf("Could not initialize java environment");
    return status;
  }

  // override jnnienv vtable to monitor for AndroidID access. some are not
  // necessary but helped with debug.
  const void *jnientries[232];
  const void **offs = ((const void ***)ctx.env)[0];
  // JNI env has 232 entries in vtable...
  for (int i = 0; i < 232; i++)
  {
    jnientries[i] = offs[i];
    if (i == 33) // (offs[i]==(void*)&JNIEnv::GetMethodID)
    {
      printf("Found GetMethodID \n");
      GetMethodID_old = (GetMethodID_t)offs[i];
      jnientries[i] = (void *)&GetMethodID_repl;
      continue;
    }
    if (i == 6)
    {
      printf("Found FindClass \n");
      FindClass_old = (FindClass_t)offs[i];
      jnientries[i] = (void *)&FindClass_repl;
      continue;
    }
    if (i == 21)
    {
      printf("Found NewGlobalRef \n");
      NewGlobalRef_old = (NewGlobalRef_t)offs[i];
      jnientries[i] = (void *)&NewGlobalRef_repl;
      continue;
    }
    if (i == 29)
    {
      printf("Found NewObjectV \n");
      NewObjectV_old = (NewObjectV_t)offs[i];
      jnientries[i] = (void *)&NewObjectV_repl;
      continue;
    }
    if (i == 34)
    {
      printf("Found CallObjectMethod \n");
      call_old = (CallObjectMethodV_t)offs[35];
      jnientries[i] = (void *)&CallObjectMethod_repl;
      continue;
    }
    if (i == 114)
    {
      printf("Found CallStaticObjectMethodV \n");
      callstatic_old = (CallStaticObjectMethodV_t)offs[115];
      jnientries[i] = (void *)&CallStaticObjectMethod_repl;
      continue;
    }
    if (i == 144)
    {
      printf("Found GetStaticFieldID \n");
      GetStaticFieldID_old = (GetStaticFieldID_t)offs[i];
      jnientries[i] = (void *)&GetStaticFieldID_repl;
      continue;
    }
    if (i == 38)
    {
      printf("Found CallBooleanMethodV \n");
      CallBooleanMethodV_old = (CallBooleanMethodV_t)offs[i];
      jnientries[i] = (void *)&CallBooleanMethodV_repl;
      continue;
    }
  }
  ((const void ***)ctx.env)[0] = jnientries;
  // add Java_com_amazon_krf_internal_NativeObject_nativeDispose to delete native objects
  const JNINativeMethod method_table[] = {
      {"nativeDispose", "(J)V", (void *)dlsym(prn, "Java_com_amazon_krf_internal_NativeObject_nativeDispose")},
  };

  (ctx.env)->RegisterNatives((ctx.env)->FindClass("com/amazon/krf/internal/NativeObject"), method_table, 1);
  // run Java_com_amazon_krf_platform_KRF_loadYJAdapter (list of lib folders)
  // then Java_com_amazon_krf_platform_KRF_loadLibsFromPath(list of lib folders)
  void *pv = dlsym(prn, "Java_com_amazon_krf_internal_KRFBookImpl_createBook");
  printf("Found createbook %p \n", pv);

  typedef jint (*onload)(JavaVM *jvm, void *);
  onload loadme = (onload)dlsym(prn, "JNI_OnLoad");

  printf("Java VM is %p onload is %p\n", ctx.vm, loadme);

  loadme(ctx.vm, NULL);
  printf("Done running OnLoad\n");
  ArrayList = (ctx.env)->FindClass("java/util/ArrayList");
  jFile = (ctx.env)->FindClass("java/io/File");
  jConstr = ctx.env->GetMethodID(jFile, "<init>", "(Ljava/lang/String;)V");

  alConstr = ctx.env->GetMethodID(ArrayList, "<init>", "()V");
  alAdd = ctx.env->GetMethodID(ArrayList, "add", "(Ljava/lang/Object;)Z");
  if (alConstr == nullptr)
  {
    printf("No constructor for ArrayList\n");
    return 3;
  }
  if (alAdd == nullptr)
  {
    printf("No add method for ArrayList\n");
    return 3;
  }
  jobject emptyList = ctx.env->NewObject(ArrayList, alConstr);
  if (emptyList == nullptr)
  {
    printf("Error: Could not create new object of ArrayList");
    return 4;
  }
  jobject libList = ctx.env->NewObject(ArrayList, alConstr);
  if (libList == nullptr)
  {
    printf("Error: Could not create new object of ArrayList");
    return 4;
  }
  jstring fullLibPath;
  {
    std::string tmp = libPath.string();
    const char *cString = tmp.c_str();
    fullLibPath = ctx.env->NewStringUTF(cString);
  }
  ctx.env->CallBooleanMethod(libList, alAdd, fullLibPath);
  jclass KRFCLass = (ctx.env)->FindClass("com/amazon/krf/platform/KRF");
  printf("KRFClass %p\n", KRFCLass);
  install_hook(pv);
  typedef void (*loadYJ)(JNIEnv *, jclass, jobject);
  loadYJ loadYJAdapter = (loadYJ)dlsym(prn, "Java_com_amazon_krf_platform_KRF_loadYJAdapter");
  loadYJAdapter(ctx.env, KRFCLass, libList);

  loadYJ loadLibs = (loadYJ)dlsym(prn, "Java_com_amazon_krf_platform_KRF_loadLibsFromPath");
  loadLibs(ctx.env, KRFCLass, libList);
  printf("Done initializing krf\n");
  // com.amazon.krf.internal.KRFBookImpl;
  std::cout << "DSN: " << jdsn << std::endl;

  jstring dsn = ctx.env->NewStringUTF(jdsn.c_str());
  jobject secretList = ctx.env->NewObject(ArrayList, alConstr);
  for (auto secr : jsecrets)
  {
    std::cout << "Account Secret: " << secr << std::endl;
    jstring secret = ctx.env->NewStringUTF(secr.c_str());
    ctx.env->CallBooleanMethod(secretList, alAdd, secret);
  }
  jclass KRFImpl = (ctx.env)->FindClass("com/amazon/krf/internal/KRFBookImpl");
  printf("KRFImpl: %p \n", KRFImpl);
  typedef jobject (*makeBook)(JNIEnv *env, jclass thiz, jobject bookFile, jobject secrets, jobject dsn, jobject voucherList, jobject containerList);
  makeBook createBook = (makeBook)pv;
  for (auto &inpath : infolders)
  {
    scan_folder_for_book_candidates(inpath, infiles);
  }
  key_candidates.clear();
  for (auto &itm : infiles)
  {
    fs::path metadata_path = itm / ".metadata";
    std::string bookid = itm.filename().string();
    std::cout << bookid << std::endl;
    std::map<std::string, std::vector<fs::path>> metadata;
    if (process_metadata(bookid, metadata_path, metadata))
    {
      ctx.env->PushLocalFrame(100);
      jobject bookFile = createJavaFile(ctx.env, metadata["bookFiles"][0].string().c_str());
      jobject voucherList = createJavaFileList(ctx.env, metadata["vouchers"]);
      key_candidates.clear();
      jobject book = createBook(ctx.env, KRFImpl, bookFile, secretList, dsn, voucherList, emptyList);
      if ((ctx.env)->ExceptionCheck())
      {
        printf("There is exception \n");
        (ctx.env)->ExceptionClear();
      }
      ctx.env->PopLocalFrame(nullptr);

      trigger_java_gc(ctx.env);
      for (auto itm : allocations)
      {
        // std::cout << hexStr((uint8_t *)itm.first, 16) << std::endl;
        key_candidates.insert(std::vector<uint8_t>((uint8_t *)itm.first, (uint8_t *)itm.first + 16));
      }
      allocations.clear();
      std::vector<std::vector<uint8_t>> keyset(key_candidates.begin(), key_candidates.end());
      std::cout << keyset.size() << " key candidates" << std::endl;
      std::vector<std::vector<uint8_t>> result = test_drmions_for_keys(metadata["resources"], keyset);
      if (result.size() == 1)
      {

        std::cout << "Found key: " << hexStr(result[0].data(), 16) << std::endl;
        AesDecryptor decr(result[0]);
        fs::path output_path = out_folder / fs::path(bookid + ".kfx-zip");
        std::cout << "Generating " << output_path << std::endl;
        std::cout << "Removal result " << std::remove(output_path.string().c_str()) << std::endl; // clear if exists
        for (auto fl : metadata["resources"])
        {
          processFile(output_path.string().c_str(), fl.string(), fl.filename().string(), &decr);
        }
      }

      printf("DOne opening book ~~ \n");
    }
    else
    {
      std::cout << "Invalid or unsupported metadata" << std::endl;
    }
  }
}
