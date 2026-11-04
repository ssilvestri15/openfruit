#include "openib/text_layout.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace openib {
namespace {

#ifdef _WIN32
using Opaque = void*;
struct CFRange { std::int64_t location; std::int64_t length; };
struct CGSize { double width; double height; };

std::filesystem::path environment_path(const wchar_t* name) {
    DWORD length=GetEnvironmentVariableW(name,nullptr,0);
    if(!length)return {};
    std::wstring value(length,L'\0');
    DWORD copied=GetEnvironmentVariableW(name,value.data(),length);
    if(!copied||copied>=length)return {};
    value.resize(copied);
    return value;
}

struct CoreText {
    HMODULE foundation{}, graphics{}, text{};
    using ProviderCreate=Opaque (*)(const char*);
    using ProviderRelease=void (*)(Opaque);
    using GraphicsFontCreate=Opaque (*)(Opaque);
    using GraphicsFontRelease=void (*)(Opaque);
    using FontCreate=Opaque (*)(Opaque,double,Opaque,Opaque);
    using StringCreate=Opaque (*)(Opaque,const char*,std::int64_t,std::uint32_t,bool);
    using StringLength=std::int64_t (*)(Opaque);
    using AttributedCreate=Opaque (*)(Opaque,std::int64_t);
    using AttributedReplace=void (*)(Opaque,CFRange,Opaque);
    using AttributedSet=void (*)(Opaque,CFRange,Opaque,Opaque);
    using FramesetterCreate=Opaque (*)(Opaque);
    using FramesetterSuggest=CGSize (*)(Opaque,CFRange,Opaque,CGSize,CFRange*);
    using Release=void (*)(Opaque);
    ProviderCreate provider_create{};ProviderRelease provider_release{};
    GraphicsFontCreate graphics_font_create{};GraphicsFontRelease graphics_font_release{};
    FontCreate font_create{};StringCreate string_create{};StringLength string_length{};
    AttributedCreate attributed_create{};AttributedReplace attributed_replace{};
    AttributedSet attributed_set{};FramesetterCreate framesetter_create{};
    FramesetterSuggest framesetter_suggest{};Release release{};Opaque font_key{};

    CoreText() {
        auto root=environment_path(L"ProgramFiles")/L"Common Files"/L"Apple"/L"Apple Application Support";
        constexpr DWORD flags=LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
        foundation=LoadLibraryExW((root/L"CoreFoundation.dll").c_str(),nullptr,flags);
        graphics=LoadLibraryExW((root/L"CoreGraphics.dll").c_str(),nullptr,flags);
        text=LoadLibraryExW((root/L"CoreText.dll").c_str(),nullptr,flags);
        if(!foundation||!graphics||!text)return;
        auto load=[](HMODULE module,const char* name){return GetProcAddress(module,name);};
        provider_create=reinterpret_cast<ProviderCreate>(load(graphics,"CGDataProviderCreateWithFilename"));
        provider_release=reinterpret_cast<ProviderRelease>(load(graphics,"CGDataProviderRelease"));
        graphics_font_create=reinterpret_cast<GraphicsFontCreate>(load(graphics,"CGFontCreateWithDataProvider"));
        graphics_font_release=reinterpret_cast<GraphicsFontRelease>(load(graphics,"CGFontRelease"));
        font_create=reinterpret_cast<FontCreate>(load(text,"CTFontCreateWithGraphicsFont"));
        string_create=reinterpret_cast<StringCreate>(load(foundation,"CFStringCreateWithBytes"));
        string_length=reinterpret_cast<StringLength>(load(foundation,"CFStringGetLength"));
        attributed_create=reinterpret_cast<AttributedCreate>(load(foundation,"CFAttributedStringCreateMutable"));
        attributed_replace=reinterpret_cast<AttributedReplace>(load(foundation,"CFAttributedStringReplaceString"));
        attributed_set=reinterpret_cast<AttributedSet>(load(foundation,"CFAttributedStringSetAttribute"));
        framesetter_create=reinterpret_cast<FramesetterCreate>(load(text,"CTFramesetterCreateWithAttributedString"));
        framesetter_suggest=reinterpret_cast<FramesetterSuggest>(load(text,"CTFramesetterSuggestFrameSizeWithConstraints"));
        release=reinterpret_cast<Release>(load(foundation,"CFRelease"));
        if(auto address=load(text,"kCTFontAttributeName"))font_key=*reinterpret_cast<Opaque*>(address);
    }
    ~CoreText(){if(text)FreeLibrary(text);if(graphics)FreeLibrary(graphics);if(foundation)FreeLibrary(foundation);}
    bool available() const {
        return provider_create&&provider_release&&graphics_font_create&&graphics_font_release&&font_create&&
               string_create&&string_length&&attributed_create&&attributed_replace&&attributed_set&&
               framesetter_create&&framesetter_suggest&&release&&font_key;
    }
};

std::optional<std::filesystem::path> installed_font(std::string_view font_name,bool system_font) {
    std::string stem;
    if(system_font)stem="SF-Pro-Text-Regular";
    else {
        if(font_name.empty())return std::nullopt;
        for(char c:font_name)if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return std::nullopt;
        stem=std::string(font_name);
    }
    auto local=environment_path(L"LOCALAPPDATA");
    auto windows=environment_path(L"WINDIR");
    std::vector<std::filesystem::path> roots;
    if(!local.empty()){roots.push_back(local/L"OPENFRUIT"/L"fonts");roots.push_back(local/L"Microsoft"/L"Windows"/L"Fonts");}
    if(!windows.empty())roots.push_back(windows/L"Fonts");
    for(const auto& root:roots)for(const auto* extension:{L".otf",L".ttf"}){
        auto path=root/(stem+std::filesystem::path(extension).string());
        std::error_code error;
        if(std::filesystem::is_regular_file(path,error))return path;
    }
    return std::nullopt;
}
#endif

} // namespace

std::optional<double> measure_text_height(std::string_view text,std::string_view font_name,double point_size,double container_width,bool system_font) {
#ifdef _WIN32
    if(text.empty()||point_size<=0||container_width<=0)return std::nullopt;
    static const CoreText backend;
    if(!backend.available())return std::nullopt;
    auto path=installed_font(font_name,system_font);
    if(!path)return std::nullopt;

    auto utf8=path->u8string();
    std::string filename(reinterpret_cast<const char*>(utf8.data()),utf8.size());
    auto provider=backend.provider_create(filename.c_str());
    if(!provider)return std::nullopt;
    auto graphics_font=backend.graphics_font_create(provider);
    backend.provider_release(provider);
    if(!graphics_font)return std::nullopt;
    // Installed SF Pro versions can have different metrics than the system
    // font used by older Interface Builder. This correction affects only the
    // archived layout estimate, never the UIFont or attributed text itself.
    const double layout_size=system_font?point_size*(14.0/15.0):point_size;
    auto font=backend.font_create(graphics_font,layout_size,nullptr,nullptr);
    backend.graphics_font_release(graphics_font);
    if(!font)return std::nullopt;
    auto string=backend.string_create(nullptr,text.data(),static_cast<std::int64_t>(text.size()),0x08000100,false);
    if(!string){backend.release(font);return std::nullopt;}
    auto length=backend.string_length(string);
    auto attributed=backend.attributed_create(nullptr,0);
    if(!attributed){backend.release(string);backend.release(font);return std::nullopt;}
    backend.attributed_replace(attributed,{0,0},string);
    backend.attributed_set(attributed,{0,length},backend.font_key,font);
    auto framesetter=backend.framesetter_create(attributed);
    std::optional<double> result;
    if(framesetter){CFRange fit{};auto size=backend.framesetter_suggest(framesetter,{0,0},nullptr,{container_width,10000000.0},&fit);if(fit.length==length&&size.height>0)result=size.height;backend.release(framesetter);}
    backend.release(attributed);backend.release(string);backend.release(font);
    return result;
#else
    (void)text;(void)font_name;(void)point_size;(void)container_width;(void)system_font;
    return std::nullopt;
#endif
}

} // namespace openib
