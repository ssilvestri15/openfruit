#include "openib/diff.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>

namespace openib {
namespace {
std::map<std::string,std::size_t> class_hist(const nib::Archive& a){std::map<std::string,std::size_t> h;for(const auto&o:a.objects){if(o.class_index<a.classes.size())++h[a.classes[o.class_index].name];else ++h["<invalid>"];}return h;}
std::map<std::string,std::size_t> key_hist(const nib::Archive& a){std::map<std::string,std::size_t> h;for(const auto&v:a.values){if(v.key_index<a.keys.size())++h[a.keys[v.key_index]];else ++h["<invalid>"];}return h;}
std::string class_name(const nib::Archive& a,std::uint32_t object_index){if(object_index>=a.objects.size())return "<invalid-object>";auto class_index=a.objects[object_index].class_index;return class_index<a.classes.size()?a.classes[class_index].name:"<invalid-class>";}
std::string scalar_value(const nib::ValueEntry& v) {
    std::ostringstream o;
    o << static_cast<int>(v.type) << ":";
    switch (v.type) {
    case nib::ValueType::Int8:
        o << static_cast<int>(std::get<std::int8_t>(v.payload));
        break;
    case nib::ValueType::Int16:
        o << std::get<std::int16_t>(v.payload);
        break;
    case nib::ValueType::Int32:
        o << std::get<std::int32_t>(v.payload);
        break;
    case nib::ValueType::Int64:
        o << std::get<std::int64_t>(v.payload);
        break;
    case nib::ValueType::False:
        o << "false";
        break;
    case nib::ValueType::True:
        o << "true";
        break;
    case nib::ValueType::Float:
        o << std::fixed << std::setprecision(5) << std::get<float>(v.payload);
        break;
    case nib::ValueType::Double:
        o << std::fixed << std::setprecision(10) << std::get<double>(v.payload);
        break;
    case nib::ValueType::Bytes: {
        o << std::hex << std::setfill('0');
        for (auto byte : std::get<nib::Bytes>(v.payload).data) o << std::setw(2) << static_cast<unsigned>(byte);
        break;
    }
    case nib::ValueType::Nil:
        o << "nil";
        break;
    case nib::ValueType::Reference:
        break;
    }
    return o.str();
}
bool nested_nib(const nib::ValueEntry& value){if(value.type!=nib::ValueType::Bytes)return false;const auto& bytes=std::get<nib::Bytes>(value.payload).data;return bytes.size()>=50&&std::memcmp(bytes.data(),"NIBArchive",10)==0;}
std::map<std::string, std::size_t> scalar_hist(const nib::Archive& a) {
    std::map<std::string, std::size_t> h;
    for (std::size_t oi = 0; oi < a.objects.size(); ++oi) {
        const auto& object = a.objects[oi];
        for (std::uint32_t j = 0; j < object.value_count; ++j) {
            auto vi = object.value_start + j;
            if (vi >= a.values.size()) continue;
            const auto& value = a.values[vi];
            if (value.type == nib::ValueType::Reference) continue;
            auto key = value.key_index < a.keys.size() ? a.keys[value.key_index] : "<invalid-key>";
            auto scalar =
                (class_name(a, static_cast<std::uint32_t>(oi)) == "NSData" && key == "NS.bytes" && nested_nib(value))
                    ? "8:<nested NIBArchive>"
                    : scalar_value(value);
            ++h[key + "=" + scalar];
        }
    }
    return h;
}
std::map<std::string, std::size_t> edge_hist(const nib::Archive& a) {
    std::map<std::string, std::size_t> h;
    for (std::size_t oi = 0; oi < a.objects.size(); ++oi) {
        const auto& o = a.objects[oi];
        auto source = class_name(a, static_cast<std::uint32_t>(oi));
        for (std::uint32_t j = 0; j < o.value_count; ++j) {
            auto vi = o.value_start + j;
            if (vi >= a.values.size()) continue;
            const auto& v = a.values[vi];
            if (v.type != nib::ValueType::Reference) continue;
            auto key = v.key_index < a.keys.size() ? a.keys[v.key_index] : "<invalid-key>";
            auto target = class_name(a, std::get<nib::Reference>(v.payload).index);
            ++h[source + "." + key + " -> " + target];
        }
    }
    return h;
}
bool constraint_set(const nib::Archive& a,std::size_t index){
    if(class_name(a,static_cast<std::uint32_t>(index))!="NSOrderedSet")return false;
    const auto& object=a.objects[index];bool any=false;
    for(std::uint32_t j=0;j<object.value_count;++j){auto vi=object.value_start+j;if(vi>=a.values.size())return false;const auto& value=a.values[vi];
        if(value.key_index>=a.keys.size())return false;
        const auto& key=a.keys[value.key_index];
        if(key.rfind("NS.object.",0)!=0)continue;
        if(value.type!=nib::ValueType::Reference||class_name(a,std::get<nib::Reference>(value.payload).index)!="NSLayoutConstraint")return false;
        any=true;
    }
    return any;
}
std::string object_label(const nib::Archive& a,std::size_t index,const std::vector<std::size_t>* colors){
    const auto& object=a.objects[index];std::vector<std::string> properties;const bool unordered_constraints=constraint_set(a,index);
    for(std::uint32_t j=0;j<object.value_count;++j){auto vi=object.value_start+j;if(vi>=a.values.size())continue;const auto& value=a.values[vi];auto key=value.key_index<a.keys.size()?a.keys[value.key_index]:"<invalid-key>";
        if(unordered_constraints&&key.rfind("NS.object.",0)==0)key="NS.object";
        std::string content;if(value.type==nib::ValueType::Reference){auto target=std::get<nib::Reference>(value.payload).index;content="ref:"+(colors&&target<colors->size()?std::to_string((*colors)[target]):class_name(a,target));}
        else content=key=="NS.bytes"&&class_name(a,static_cast<std::uint32_t>(index))=="NSData"&&nested_nib(value)?"8:<nested NIBArchive>":scalar_value(value);
        properties.push_back(std::to_string(key.size())+":"+key+"="+content);
    }
    std::sort(properties.begin(),properties.end());std::string label=class_name(a,static_cast<std::uint32_t>(index));for(const auto& property:properties)label+="|"+std::to_string(property.size())+":"+property;return label;
}
std::string topology_difference(const nib::Archive& left,const nib::Archive& right){
    std::vector<std::size_t> lc(left.objects.size()),rc(right.objects.size());
    const auto iterations=left.objects.size()+right.objects.size()+1;
    for(std::size_t round=0;round<iterations;++round){
        std::map<std::string,std::size_t> labels;std::vector<std::string> ll,rl;
        for(std::size_t i=0;i<lc.size();++i){ll.push_back(object_label(left,i,round?&lc:nullptr));labels.emplace(ll.back(),0);}
        for(std::size_t i=0;i<rc.size();++i){rl.push_back(object_label(right,i,round?&rc:nullptr));labels.emplace(rl.back(),0);}
        std::map<std::string,std::pair<std::size_t,std::size_t>> counts;for(const auto& label:ll)++counts[label].first;for(const auto& label:rl)++counts[label].second;
        for(const auto& [label,count]:counts)if(count.first!=count.second)return "round "+std::to_string(round)+": "+label.substr(0,240)+" ("+std::to_string(count.first)+" vs "+std::to_string(count.second)+")";
        std::size_t next=0;for(auto& [_,color]:labels)color=next++;
        std::vector<std::size_t> nl,nr;for(const auto& label:ll)nl.push_back(labels.at(label));for(const auto& label:rl)nr.push_back(labels.at(label));
        if(round&&nl==lc&&nr==rc)return {};lc=std::move(nl);rc=std::move(nr);
    }
    return {};
}
void compare_hist(const char* category, const std::map<std::string, std::size_t>& a,
                  const std::map<std::string, std::size_t>& b, DiffResult& r) {
    std::map<std::string, std::pair<std::size_t, std::size_t>> all;
    for (auto& [k, v] : a) all[k].first = v;
    for (auto& [k, v] : b) all[k].second = v;
    for (auto& [k, v] : all)
        if (v.first != v.second) {
            r.equivalent = false;
            r.differences.push_back({category, k + ": " + std::to_string(v.first) + " vs " + std::to_string(v.second)});
        }
}
std::vector<nib::Archive> nested_archives(const nib::Archive& archive) {
    std::vector<nib::Archive> nested;
    nib::Reader reader;
    for (std::size_t oi = 0; oi < archive.objects.size(); ++oi) {
        if (class_name(archive, static_cast<std::uint32_t>(oi)) != "NSData") continue;
        const auto& object = archive.objects[oi];
        for (std::uint32_t j = 0; j < object.value_count; ++j) {
            auto vi = object.value_start + j;
            if (vi >= archive.values.size()) continue;
            const auto& value = archive.values[vi];
            if (value.key_index < archive.keys.size() && archive.keys[value.key_index] == "NS.bytes" &&
                nested_nib(value))
                nested.push_back(reader.read_bytes(std::get<nib::Bytes>(value.payload).data));
        }
    }
    return nested;
}
}
DiffResult diff_archives(const nib::Archive& a, const nib::Archive& b) {
    DiffResult r;
    if (a.format_version != b.format_version) {
        r.equivalent = false;
        r.differences.push_back({"header", "format version differs"});
    }
    if (a.coder_version != b.coder_version) {
        r.equivalent = false;
        r.differences.push_back(
            {"header", "coder version " + std::to_string(a.coder_version) + " vs " + std::to_string(b.coder_version)});
    }
    compare_hist("class", class_hist(a), class_hist(b), r);
    compare_hist("key", key_hist(a), key_hist(b), r);
    compare_hist("scalar", scalar_hist(a), scalar_hist(b), r);
    compare_hist("edge", edge_hist(a), edge_hist(b), r);
    if (a.objects.size() != b.objects.size()) {
        r.equivalent = false;
        r.differences.push_back(
            {"count", "objects " + std::to_string(a.objects.size()) + " vs " + std::to_string(b.objects.size())});
    }
    if (a.values.size() != b.values.size()) {
        r.equivalent = false;
        r.differences.push_back(
            {"count", "values " + std::to_string(a.values.size()) + " vs " + std::to_string(b.values.size())});
    }
    if (r.equivalent) {
        auto difference = topology_difference(a, b);
        if (!difference.empty()) {
            r.equivalent = false;
            r.differences.push_back({"topology", difference});
        }
    }
    auto left_nested = nested_archives(a), right_nested = nested_archives(b);
    if (left_nested.size() != right_nested.size()) {
        r.equivalent = false;
        r.differences.push_back({"nested", "NIBArchive count " + std::to_string(left_nested.size()) + " vs " +
                                               std::to_string(right_nested.size())});
    } else {
        std::vector<bool> matched(right_nested.size());
        for (std::size_t i = 0; i < left_nested.size(); ++i) {
            bool found = false;
            for (std::size_t j = 0; j < right_nested.size(); ++j)
                if (!matched[j] && diff_archives(left_nested[i], right_nested[j]).equivalent) {
                    matched[j] = true;
                    found = true;
                    break;
                }
            if (!found) {
                r.equivalent = false;
                r.differences.push_back({"nested[" + std::to_string(i) + "]", "no equivalent nested NIBArchive"});
                if (!right_nested.empty()) {
                    auto details = diff_archives(left_nested[i], right_nested[0]);
                    for (const auto& item : details.differences)
                        r.differences.push_back({"nested[" + std::to_string(i) + "]/" + item.category, item.message});
                }
            }
        }
    }
    return r;
}
DiffResult diff_nib_files(const std::filesystem::path& l,const std::filesystem::path& r){nib::Reader rd;return diff_archives(rd.read_file(l),rd.read_file(r));}
std::string format_diff(const DiffResult& r){std::ostringstream o;if(r.equivalent){o<<"Semantically equivalent class/key/scalar/edge graphs.\n";return o.str();}o<<"Differences: "<<r.differences.size()<<"\n";for(auto&d:r.differences)o<<"  ["<<d.category<<"] "<<d.message<<"\n";return o.str();}
} // namespace openib
