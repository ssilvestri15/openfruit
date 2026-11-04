#include "openib/nib.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <climits>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace openib::nib {
namespace {

constexpr std::size_t kHeaderSize = 50;
constexpr char kMagic[] = "NIBArchive";

std::uint16_t read_u16(const std::vector<std::uint8_t>& b, std::size_t& p) {
    if (p + 2 > b.size()) throw OpenIBError("Truncated NIB uint16");
    std::uint16_t v = static_cast<std::uint16_t>(b[p]) |
                      (static_cast<std::uint16_t>(b[p + 1]) << 8);
    p += 2; return v;
}
std::uint32_t read_u32(const std::vector<std::uint8_t>& b, std::size_t& p) {
    if (p + 4 > b.size()) throw OpenIBError("Truncated NIB uint32");
    std::uint32_t v = static_cast<std::uint32_t>(b[p]) |
                      (static_cast<std::uint32_t>(b[p + 1]) << 8) |
                      (static_cast<std::uint32_t>(b[p + 2]) << 16) |
                      (static_cast<std::uint32_t>(b[p + 3]) << 24);
    p += 4; return v;
}
std::uint64_t read_u64(const std::vector<std::uint8_t>& b, std::size_t& p) {
    std::uint64_t lo = read_u32(b, p); std::uint64_t hi = read_u32(b, p); return lo | (hi << 32);
}
float read_f32(const std::vector<std::uint8_t>& b, std::size_t& p) {
    auto u = read_u32(b, p); float f; std::memcpy(&f, &u, 4); return f;
}
double read_f64(const std::vector<std::uint8_t>& b, std::size_t& p) {
    auto u = read_u64(b, p); double d; std::memcpy(&d, &u, 8); return d;
}
std::uint32_t read_vint(const std::vector<std::uint8_t>& b, std::size_t& p) {
    std::uint32_t value = 0; int shift = 0;
    for (int i = 0; i < 5; ++i) {
        if (p >= b.size()) throw OpenIBError("Truncated NIB VInt32");
        auto byte = b[p++]; value |= static_cast<std::uint32_t>(byte & 0x7F) << shift;
        if (byte & 0x80) return value;
        shift += 7;
    }
    throw OpenIBError("Invalid NIB VInt32");
}
void write_u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF);
}
void write_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xFF);
}
void write_u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back((v >> (8 * i)) & 0xFF);
}
void write_f32(std::vector<std::uint8_t>& b, float f) {
    std::uint32_t u; std::memcpy(&u, &f, 4); write_u32(b, u);
}
void write_f64(std::vector<std::uint8_t>& b, double d) {
    std::uint64_t u; std::memcpy(&u, &d, 8); write_u64(b, u);
}
void write_vint(std::vector<std::uint8_t>& b, std::uint32_t value) {
    while (true) {
        std::uint8_t byte = value & 0x7F; value >>= 7;
        if (value == 0) { b.push_back(byte | 0x80); return; }
        b.push_back(byte);
    }
}

std::string type_name(ValueType t) {
    switch (t) {
        case ValueType::Int8: return "i8"; case ValueType::Int16: return "i16";
        case ValueType::Int32: return "i32"; case ValueType::Int64: return "i64";
        case ValueType::False: return "false"; case ValueType::True: return "true";
        case ValueType::Float: return "float"; case ValueType::Double: return "double";
        case ValueType::Bytes: return "bytes"; case ValueType::Nil: return "nil";
        case ValueType::Reference: return "ref";
    }
    return "?";
}

} // namespace

Archive Reader::read_file(const std::filesystem::path& path) const {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw OpenIBError("Unable to open NIB: " + path.string());
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
    return read_bytes(bytes);
}

Archive Reader::read_bytes(const std::vector<std::uint8_t>& b) const {
    if (b.size() < kHeaderSize) throw OpenIBError("NIB is smaller than 50-byte header");
    if (std::memcmp(b.data(), kMagic, 10) != 0) throw OpenIBError("Not a UIKit NIBArchive");
    std::size_t p = 10;
    Archive a; a.format_version = read_u32(b,p); a.coder_version = read_u32(b,p);
    const auto oc = read_u32(b,p), oo = read_u32(b,p), kc = read_u32(b,p), ko = read_u32(b,p),
               vc = read_u32(b,p), vo = read_u32(b,p), cc = read_u32(b,p), co = read_u32(b,p);
    if (oo > b.size() || ko > b.size() || vo > b.size() || co > b.size()) throw OpenIBError("NIB table offset outside file");

    p = oo;
    for (std::uint32_t i=0;i<oc;++i) a.objects.push_back({read_vint(b,p),read_vint(b,p),read_vint(b,p)});
    p = ko;
    for (std::uint32_t i=0;i<kc;++i) {
        auto n=read_vint(b,p); if (p+n>b.size()) throw OpenIBError("Truncated NIB key");
        a.keys.emplace_back(reinterpret_cast<const char*>(b.data()+p), n); p += n;
    }
    p = vo;
    for (std::uint32_t i=0;i<vc;++i) {
        ValueEntry v; v.key_index=read_vint(b,p); if(p>=b.size()) throw OpenIBError("Truncated NIB value type");
        v.type=static_cast<ValueType>(b[p++]);
        switch(v.type) {
            case ValueType::Int8: v.payload=static_cast<std::int8_t>(b.at(p++)); break;
            case ValueType::Int16: v.payload=static_cast<std::int16_t>(read_u16(b,p)); break;
            case ValueType::Int32: v.payload=static_cast<std::int32_t>(read_u32(b,p)); break;
            case ValueType::Int64: v.payload=static_cast<std::int64_t>(read_u64(b,p)); break;
            case ValueType::False: case ValueType::True: case ValueType::Nil: v.payload=std::monostate{}; break;
            case ValueType::Float: v.payload=read_f32(b,p); break;
            case ValueType::Double: v.payload=read_f64(b,p); break;
            case ValueType::Bytes: { auto n=read_vint(b,p); if(p+n>b.size()) throw OpenIBError("Truncated NIB bytes"); Bytes x; x.data.insert(x.data.end(),b.begin()+p,b.begin()+p+n); p+=n; v.payload=std::move(x); break; }
            case ValueType::Reference: v.payload=Reference{read_u32(b,p)}; break;
            default: throw OpenIBError("Unknown NIB value type: " + std::to_string(static_cast<int>(v.type)));
        }
        a.values.push_back(std::move(v));
    }
    p = co;
    for (std::uint32_t i=0;i<cc;++i) {
        auto n=read_vint(b,p); auto fallback_count=read_vint(b,p); ClassEntry c;
        for(std::uint32_t j=0;j<fallback_count;++j) c.fallback_class_indices.push_back(read_u32(b,p));
        if(n==0 || p+n>b.size()) throw OpenIBError("Truncated NIB class name");
        c.name.assign(reinterpret_cast<const char*>(b.data()+p), n-1); p+=n;
        a.classes.push_back(std::move(c));
    }
    return a;
}

std::vector<std::uint8_t> Writer::write_bytes(const Archive& a) const {
    std::vector<std::uint8_t> objects, keys, values, classes;
    for(const auto& o:a.objects){write_vint(objects,o.class_index);write_vint(objects,o.value_start);write_vint(objects,o.value_count);}
    for(const auto& k:a.keys){write_vint(keys,static_cast<std::uint32_t>(k.size()));keys.insert(keys.end(),k.begin(),k.end());}
    for(const auto& v:a.values){
        write_vint(values,v.key_index); values.push_back(static_cast<std::uint8_t>(v.type));
        switch(v.type){
            case ValueType::Int8: values.push_back(static_cast<std::uint8_t>(std::get<std::int8_t>(v.payload))); break;
            case ValueType::Int16: write_u16(values,static_cast<std::uint16_t>(std::get<std::int16_t>(v.payload))); break;
            case ValueType::Int32: write_u32(values,static_cast<std::uint32_t>(std::get<std::int32_t>(v.payload))); break;
            case ValueType::Int64: write_u64(values,static_cast<std::uint64_t>(std::get<std::int64_t>(v.payload))); break;
            case ValueType::False: case ValueType::True: case ValueType::Nil: break;
            case ValueType::Float: write_f32(values,std::get<float>(v.payload)); break;
            case ValueType::Double: write_f64(values,std::get<double>(v.payload)); break;
            case ValueType::Bytes: {const auto& d=std::get<Bytes>(v.payload).data;write_vint(values,static_cast<std::uint32_t>(d.size()));values.insert(values.end(),d.begin(),d.end());break;}
            case ValueType::Reference: write_u32(values,std::get<Reference>(v.payload).index);break;
        }
    }
    for(const auto& c:a.classes){
        write_vint(classes,static_cast<std::uint32_t>(c.name.size()+1));
        write_vint(classes,static_cast<std::uint32_t>(c.fallback_class_indices.size()));
        for(auto x:c.fallback_class_indices) write_u32(classes,x);
        classes.insert(classes.end(),c.name.begin(),c.name.end()); classes.push_back(0);
    }
    const std::uint32_t oo=kHeaderSize, ko=oo+objects.size(), vo=ko+keys.size(), co=vo+values.size();
    std::vector<std::uint8_t> out; out.insert(out.end(),kMagic,kMagic+10); write_u32(out,a.format_version);write_u32(out,a.coder_version);
    write_u32(out,a.objects.size());write_u32(out,oo);write_u32(out,a.keys.size());write_u32(out,ko);write_u32(out,a.values.size());write_u32(out,vo);write_u32(out,a.classes.size());write_u32(out,co);
    out.insert(out.end(),objects.begin(),objects.end());out.insert(out.end(),keys.begin(),keys.end());out.insert(out.end(),values.begin(),values.end());out.insert(out.end(),classes.begin(),classes.end());
    return out;
}

void Writer::write_file(const Archive& a,const std::filesystem::path& path) const {
    std::filesystem::create_directories(path.parent_path()); auto b=write_bytes(a); std::ofstream f(path,std::ios::binary); if(!f) throw OpenIBError("Unable to write NIB: "+path.string()); f.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));
}

std::string dump_text(const Archive& a,bool show_types){
    std::ostringstream o; o<<"NIBArchive format="<<a.format_version<<" coder="<<a.coder_version<<" objects="<<a.objects.size()<<" keys="<<a.keys.size()<<" values="<<a.values.size()<<" classes="<<a.classes.size()<<"\n";
    for(std::size_t i=0;i<a.objects.size();++i){
        const auto& ob=a.objects[i];std::string cls=ob.class_index<a.classes.size()?a.classes[ob.class_index].name:"<bad-class>";o<<"["<<i<<"] "<<cls<<"\n";
        for(std::uint32_t j=0;j<ob.value_count;++j){
            auto vi=ob.value_start+j;if(vi>=a.values.size())break;const auto& v=a.values[vi];std::string key=v.key_index<a.keys.size()?a.keys[v.key_index]:"<bad-key>";
            o<<"  "<<key<<" = ";if(show_types)o<<"("<<type_name(v.type)<<") ";
            switch(v.type){
                case ValueType::True:o<<"true";break;case ValueType::False:o<<"false";break;case ValueType::Nil:o<<"nil";break;
                case ValueType::Int8:o<<static_cast<int>(std::get<std::int8_t>(v.payload));break;
                case ValueType::Int16:o<<std::get<std::int16_t>(v.payload);break;
                case ValueType::Int32:o<<std::get<std::int32_t>(v.payload);break;
                case ValueType::Int64:o<<std::get<std::int64_t>(v.payload);break;
                case ValueType::Float:o<<std::get<float>(v.payload);break;case ValueType::Double:o<<std::get<double>(v.payload);break;
                case ValueType::Reference:o<<"@"<<std::get<Reference>(v.payload).index;break;
                case ValueType::Bytes:{
                    const auto& d=std::get<Bytes>(v.payload).data;
                    const bool point=(key=="UICenter"||key=="UIContentSize")&&d.size()==17&&d[0]==7;
                    const bool rect=(key=="UIBounds"||key=="UIViewLayoutMargins")&&d.size()==33&&d[0]==7;
                    if(point||rect){std::size_t pos=1;o<<"{"<<read_f64(d,pos)<<", "<<read_f64(d,pos);if(rect)o<<", "<<read_f64(d,pos)<<", "<<read_f64(d,pos);o<<"}";}
                    else{bool printable=std::all_of(d.begin(),d.end(),[](auto c){return c==9||c==10||c==13||(c>=32&&c<127);});if(printable)o<<'"'<<std::string(d.begin(),d.end())<<'"';else o<<"<"<<d.size()<<" bytes>";}
                    break;
                }
            }
            o<<"\n";
        }
    }
    return o.str();
}
std::string canonical_text(const Archive& a){return dump_text(a,true);}

GraphObject& GraphObject::set(std::string key,GraphValue value){for(auto& [k,v]:properties)if(k==key){v=std::move(value);return *this;}properties.emplace_back(std::move(key),std::move(value));return *this;}
std::optional<GraphValue> GraphObject::get(const std::string& key) const {for(const auto& [k,v]:properties)if(k==key)return v;return std::nullopt;}
void GraphObject::erase(const std::string& key){properties.erase(std::remove_if(properties.begin(),properties.end(),[&](const auto& kv){return kv.first==key;}),properties.end());}
GraphBuilder::GraphBuilder()=default;
GraphRef GraphBuilder::object(std::string c){auto p=std::make_shared<GraphObject>();p->class_name=std::move(c);p->serial=next_serial_++;return p;}
GraphRef GraphBuilder::string(std::string s){auto found=strings_.find(s);if(found!=strings_.end())if(auto existing=found->second.lock())return existing;auto p=object("NSString");RawBytes b;b.data.assign(s.begin(),s.end());p->set("NS.bytes",std::move(b));strings_[s]=p;return p;}
GraphRef GraphBuilder::array(const std::vector<GraphRef>& items) {
    if (items.empty())
        if (auto existing = empty_array_.lock()) return existing;
    auto p = object("NSArray");
    p->set("NSInlinedValue", true);
    for (auto& x : items) p->properties.emplace_back("UINibEncoderEmptyKey", x);
    if (items.empty()) empty_array_ = p;
    return p;
}
GraphRef GraphBuilder::mutable_array(const std::vector<GraphRef>& items){auto p=object("NSMutableArray");p->set("NSInlinedValue",true);for(auto& x:items)p->properties.emplace_back("UINibEncoderEmptyKey",x);return p;}
GraphRef GraphBuilder::dictionary(const std::vector<std::pair<GraphRef,GraphRef>>& items){auto p=object("NSDictionary");p->set("NSInlinedValue",true);for(auto& [k,v]:items){p->properties.emplace_back("UINibEncoderEmptyKey",k);p->properties.emplace_back("UINibEncoderEmptyKey",v);}return p;}
GraphRef GraphBuilder::mutable_dictionary(const std::vector<std::pair<GraphRef, GraphRef>>& items) {
    auto p = object("NSMutableDictionary");
    p->set("NSInlinedValue", true);
    for (auto& [k, v] : items) {
        p->properties.emplace_back("UINibEncoderEmptyKey", k);
        p->properties.emplace_back("UINibEncoderEmptyKey", v);
    }
    return p;
}
GraphRef GraphBuilder::proxy(std::string id){auto p=object("UIProxyObject");p->set("UIProxiedObjectIdentifier",string(std::move(id)));return p;}

Archive GraphBuilder::flatten(const std::vector<GraphRef>& roots,std::uint32_t coder_version) const {
    Archive a; a.coder_version=coder_version; std::vector<GraphRef> objs; std::unordered_map<std::uint64_t,std::uint32_t> idx;
    std::function<void(const GraphRef&)> visit=[&](const GraphRef& o){if(!o||idx.contains(o->serial))return;idx[o->serial]=objs.size();objs.push_back(o);for(const auto& [k,v]:o->properties){(void)k;if(auto r=std::get_if<GraphRef>(&v))visit(*r);}};for(auto& r:roots)visit(r);
    auto keyidx=[&](const std::string& k){auto it=std::find(a.keys.begin(),a.keys.end(),k);if(it!=a.keys.end())return static_cast<std::uint32_t>(it-a.keys.begin());a.keys.push_back(k);return static_cast<std::uint32_t>(a.keys.size()-1);};
    auto clsidx=[&](const std::string& c){for(std::size_t i=0;i<a.classes.size();++i)if(a.classes[i].name==c)return static_cast<std::uint32_t>(i);a.classes.push_back({c,{}});return static_cast<std::uint32_t>(a.classes.size()-1);};
    for (auto& o : objs) {
        ObjectEntry oe;
        oe.class_index = clsidx(o->class_name);
        oe.value_start = a.values.size();
        for (const auto& [k, v] : o->properties) {
            ValueEntry ve;
            ve.key_index = keyidx(k);
            if (std::holds_alternative<std::monostate>(v)) {
                ve.type = ValueType::Nil;
            } else if (auto x = std::get_if<bool>(&v)) {
                ve.type = *x ? ValueType::True : ValueType::False;
            } else if (auto x = std::get_if<std::int64_t>(&v)) {
                if (*x >= -128 && *x <= 127) {
                    ve.type = ValueType::Int8;
                    ve.payload = static_cast<std::int8_t>(*x);
                } else if (*x >= -32768 && *x <= 32767) {
                    ve.type = ValueType::Int16;
                    ve.payload = static_cast<std::int16_t>(*x);
                } else if (*x >= INT32_MIN && *x <= INT32_MAX) {
                    ve.type = ValueType::Int32;
                    ve.payload = static_cast<std::int32_t>(*x);
                } else {
                    ve.type = ValueType::Int64;
                    ve.payload = *x;
                }
            } else if (auto x = std::get_if<double>(&v)) {
                ve.type = ValueType::Double;
                ve.payload = *x;
            } else if (auto x = std::get_if<RawFloat>(&v)) {
                ve.type = ValueType::Float;
                ve.payload = x->value;
            } else if (auto x = std::get_if<RawInt32>(&v)) {
                ve.type = ValueType::Int32;
                ve.payload = x->value;
            } else if (auto x = std::get_if<RawInt64>(&v)) {
                ve.type = ValueType::Int64;
                ve.payload = x->value;
            } else if (auto x = std::get_if<RawBytes>(&v)) {
                ve.type = ValueType::Bytes;
                ve.payload = Bytes{x->data};
            } else if (auto x = std::get_if<GraphRef>(&v)) {
                ve.type = ValueType::Reference;
                ve.payload = Reference{idx.at((*x)->serial)};
            }
            a.values.push_back(std::move(ve));
        }
        oe.value_count = a.values.size() - oe.value_start;
        a.objects.push_back(oe);
    }
    return a;
}

} // namespace openib::nib
