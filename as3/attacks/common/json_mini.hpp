// json_mini.hpp
//
// A deliberately small JSON value type + parser/serializer, just big enough
// to speak the AS3 wire protocol (protocol.md section 2). Not a general
// purpose JSON library: no exceptions-as-control-flow, no comments, no
// unicode escapes beyond \uXXXX passthrough. Good enough to build and read
// the envelopes defined in protocol.md.
//
// Every AS3 frame is one JSON object per line ("\n"-terminated), so the
// parser only needs to consume a single top-level value from a string.

#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <cstdint>

namespace json {

enum class Type { Null, Bool, Number, String, Array, Object };

class Value {
public:
    Type type = Type::Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<Value> arr;
    // Preserve insertion order: real JSON objects don't require it, but it
    // makes output diffable against captured traffic.
    std::vector<std::pair<std::string, Value>> obj;

    Value() = default;
    static Value mkNull() { return Value(); }
    static Value mkBool(bool v) { Value r; r.type = Type::Bool; r.b = v; return r; }
    static Value mkNum(double v) { Value r; r.type = Type::Number; r.num = v; return r; }
    static Value mkStr(const std::string& v) { Value r; r.type = Type::String; r.str = v; return r; }
    static Value mkArr() { Value r; r.type = Type::Array; return r; }
    static Value mkObj() { Value r; r.type = Type::Object; return r; }

    bool isObject() const { return type == Type::Object; }
    bool isNull() const { return type == Type::Null; }

    void set(const std::string& key, Value v) {
        for (auto& kv : obj) {
            if (kv.first == key) { kv.second = std::move(v); return; }
        }
        obj.emplace_back(key, std::move(v));
    }

    const Value* find(const std::string& key) const {
        for (auto& kv : obj) if (kv.first == key) return &kv.second;
        return nullptr;
    }

    // Accessors with sane defaults -- callers that need strict validation
    // should use find() and check presence explicitly.
    std::string getStr(const std::string& key, const std::string& def = "") const {
        auto* v = find(key);
        return (v && v->type == Type::String) ? v->str : def;
    }
    long getInt(const std::string& key, long def = 0) const {
        auto* v = find(key);
        return (v && v->type == Type::Number) ? (long)v->num : def;
    }
    bool getBool(const std::string& key, bool def = false) const {
        auto* v = find(key);
        return (v && v->type == Type::Bool) ? v->b : def;
    }
};

// ---------- serialize ----------

inline void escapeInto(const std::string& s, std::string& out) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    out.push_back('"');
}

inline void dumpInto(const Value& v, std::string& out) {
    switch (v.type) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += v.b ? "true" : "false"; break;
        case Type::Number: {
            if (v.num == (long long)v.num) {
                out += std::to_string((long long)v.num);
            } else {
                std::ostringstream ss;
                ss << v.num;
                out += ss.str();
            }
            break;
        }
        case Type::String: escapeInto(v.str, out); break;
        case Type::Array: {
            out.push_back('[');
            for (size_t i = 0; i < v.arr.size(); i++) {
                if (i) out.push_back(',');
                dumpInto(v.arr[i], out);
            }
            out.push_back(']');
            break;
        }
        case Type::Object: {
            out.push_back('{');
            for (size_t i = 0; i < v.obj.size(); i++) {
                if (i) out.push_back(',');
                escapeInto(v.obj[i].first, out);
                out.push_back(':');
                dumpInto(v.obj[i].second, out);
            }
            out.push_back('}');
            break;
        }
    }
}

inline std::string dump(const Value& v) {
    std::string out;
    dumpInto(v, out);
    return out;
}

// ---------- parse ----------

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s), i_(0) {}

    Value parse() {
        skipWs();
        Value v = parseValue();
        return v;
    }

private:
    const std::string& s_;
    size_t i_;

    void skipWs() { while (i_ < s_.size() && isspace((unsigned char)s_[i_])) i_++; }
    char peek() { return i_ < s_.size() ? s_[i_] : '\0'; }
    char next() { return i_ < s_.size() ? s_[i_++] : '\0'; }

    Value parseValue() {
        skipWs();
        char c = peek();
        if (c == '{') return parseObject();
        if (c == '[') return parseArray();
        if (c == '"') return parseString();
        if (c == 't' || c == 'f') return parseBool();
        if (c == 'n') { i_ += 4; return Value::mkNull(); }
        return parseNumber();
    }

    Value parseObject() {
        Value v = Value::mkObj();
        next(); // {
        skipWs();
        if (peek() == '}') { next(); return v; }
        while (true) {
            skipWs();
            Value key = parseString();
            skipWs();
            next(); // :
            Value val = parseValue();
            v.obj.emplace_back(key.str, std::move(val));
            skipWs();
            char c = next();
            if (c == '}') break;
            // c should be ','
        }
        return v;
    }

    Value parseArray() {
        Value v = Value::mkArr();
        next(); // [
        skipWs();
        if (peek() == ']') { next(); return v; }
        while (true) {
            Value val = parseValue();
            v.arr.push_back(std::move(val));
            skipWs();
            char c = next();
            if (c == ']') break;
        }
        return v;
    }

    Value parseString() {
        Value v;
        v.type = Type::String;
        next(); // opening quote
        std::string out;
        while (true) {
            char c = next();
            if (c == '"' || c == '\0') break;
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case 'n': out.push_back('\n'); break;
                    case 't': out.push_back('\t'); break;
                    case 'r': out.push_back('\r'); break;
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'u': {
                        // Keep it simple: copy the 4 hex digits back as
                        // literal ASCII \uXXXX if it's not plain ASCII; the
                        // protocol never puts non-ASCII in these fields.
                        std::string hex = s_.substr(i_, 4);
                        i_ += 4;
                        int cp = std::stoi(hex, nullptr, 16);
                        if (cp < 0x80) out.push_back((char)cp);
                        break;
                    }
                    default: out.push_back(e); break;
                }
            } else {
                out.push_back(c);
            }
        }
        v.str = out;
        return v;
    }

    Value parseBool() {
        if (s_.compare(i_, 4, "true") == 0) { i_ += 4; return Value::mkBool(true); }
        i_ += 5; // false
        return Value::mkBool(false);
    }

    Value parseNumber() {
        size_t start = i_;
        if (peek() == '-') next();
        while (isdigit((unsigned char)peek()) || peek() == '.' || peek() == 'e' || peek() == 'E' || peek() == '+' || peek() == '-') next();
        std::string numStr = s_.substr(start, i_ - start);
        return Value::mkNum(numStr.empty() ? 0 : std::stod(numStr));
    }
};

inline Value parse(const std::string& s) {
    Parser p(s);
    return p.parse();
}

} // namespace json
