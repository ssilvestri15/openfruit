#include "apfs_compression.hpp"
#include <Util.h>
#include <array>
#include <vector>
#include <stdexcept>
#include <algorithm>
// Original utility library's diagnostic switches; never permit its lax mode.
int g_debug=0;
bool g_lax=false;
extern "C" int openfruit_lzvn_decode_complete(const unsigned char*,std::size_t,unsigned char*,std::size_t);
namespace OpenFruit {
namespace {
void Check(bool ok,const char* e){if(!ok)throw std::runtime_error(e);}
std::size_t U(std::string_view s,std::size_t p,unsigned n){Check(p<=s.size()&&n<=s.size()-p,"Truncated LZBITMAP field.");std::size_t v=0;for(unsigned i=0;i<n;++i)v|=std::size_t(static_cast<unsigned char>(s[p+i]))<<(8*i);return v;}
void Validate(std::string_view s,std::size_t expected){
    Check(s.size()>=10&&s.size()<=131072&&s.substr(0,4)==std::string_view("ZBM\x09",4),"Unsupported LZBITMAP frame or input budget.");std::size_t p=4,total=0;
    while(p<s.size()){
        const auto packed=U(s,p,3),plain=U(s,p+3,3);Check(packed>=6&&packed<=s.size()-p,"LZBITMAP block size invalid.");
        // The resource-fork slot can retain unused bytes after the frame terminator.
        // They belong to the bounded input slot, never to the decoded output.
        if(packed==6){Check(!plain&&total==expected,"LZBITMAP terminator/output length mismatch.");return;}
        Check(plain>0&&plain<=expected-total,"LZBITMAP output bounds invalid.");if(packed==plain+6){total+=plain;p+=packed;continue;}
        Check(plain<=32768&&packed>=32,"LZBITMAP compressed block budget invalid.");const auto b=s.substr(p,packed);const auto d=U(b,6,3),bm=U(b,9,3),tk=U(b,12,3),dictionary=packed-17;
        Check(d>=15&&d<=bm&&bm<=tk&&tk<=dictionary&&dictionary-tk<=2048,"LZBITMAP section bounds invalid.");
        std::array<unsigned,16> bitmap{},distance_kind{};for(unsigned i=0;i<3;++i)distance_kind[i]=i;
        unsigned bits=0,buffer=0;std::size_t at=dictionary;
        for(unsigned i=3;i<15;++i){while(bits<10){Check(at<packed,"LZBITMAP token dictionary truncated.");buffer|=unsigned(U(b,at++,1))<<bits;bits+=8;}bitmap[i]=buffer&255;distance_kind[i]=(buffer>>8)&3;buffer>>=10;bits-=10;}
        std::vector<unsigned> nibbles,tokens;nibbles.reserve((dictionary-tk)*2);for(auto i=tk;i<dictionary;++i){const auto c=U(b,i,1);nibbles.push_back(c&15);nibbles.push_back(c>>4);}
        const auto count=(plain+7)/8;
        for(std::size_t i=0;i<nibbles.size();++i){unsigned t=nibbles[i];if(t==15){Check(i>0&&nibbles[i-1]<15,"LZBITMAP RLE predecessor invalid.");t=nibbles[i-1];std::size_t repeat=3;do{Check(++i<nibbles.size(),"LZBITMAP RLE truncated.");repeat+=nibbles[i];Check(repeat<=4097-tokens.size(),"LZBITMAP RLE expansion budget exceeded.");}while(nibbles[i]==15);tokens.insert(tokens.end(),repeat,t);}else{Check(tokens.size()<4097,"LZBITMAP token expansion budget exceeded.");tokens.push_back(t);}}
        Check(tokens.size()>=count&&tokens.size()<=count+1,"LZBITMAP token count mismatch.");std::size_t lp=15,dp=d,bp=bm,produced=0,dist=8;
        for(std::size_t i=0;i<count;++i){const auto t=tokens[i];unsigned mask=bitmap[t];if(t<3){Check(bp<tk,"LZBITMAP bitmap overrun.");mask=static_cast<unsigned>(U(b,bp++,1));}const auto mode=distance_kind[t];if(mode==1||mode==2){Check(dp<=bm&&mode<=bm-dp,"LZBITMAP distance overrun.");dist=U(b,dp,mode);dp+=mode;}
            for(unsigned bit=0;bit<8&&produced<plain;++bit,++produced){if(mask&1){Check(lp<d,"LZBITMAP literal overrun.");++lp;}else Check(dist>0&&dist<=total+produced,"LZBITMAP back-reference outside decoded output.");mask>>=1;}}
        Check(lp==d&&dp==bm&&bp==tk,"LZBITMAP sections not consumed exactly.");total+=plain;p+=packed;
    }
    throw std::runtime_error("LZBITMAP terminator missing.");
}
}
std::optional<std::string> DecodeApfsLzBitmap(std::string_view input,std::size_t expected,std::string& error){error.clear();try{
    Check(expected>0&&expected<=65536,"APFS compression output block budget exceeded.");
    if(!input.empty()&&static_cast<unsigned char>(input[0])==255){Check(input.size()==expected+1,"APFS uncompressed LZBITMAP block length mismatch.");return std::string(input.substr(1));}
    Validate(input,expected);std::string out(expected,'\0');const auto got=DecompressLZBITMAP(reinterpret_cast<std::uint8_t*>(out.data()),out.size(),reinterpret_cast<const std::uint8_t*>(input.data()),input.size());Check(got==expected,"Original LZBITMAP decoder output mismatch.");return out;
}catch(const std::exception& e){error=e.what();return {};}}
std::optional<std::string> DecodeApfsLzBitmapResourceFork(std::string_view input,std::size_t expected,std::string& error,const std::function<void()>& control){error.clear();try{
    Check(expected>0&&expected<=512ULL*1024*1024,"APFS resource-fork decoded size budget exceeded.");
    const auto count=(expected+65535)/65536,table=(count+1)*4;
    Check(input.size()>=table&&input.size()<=count*131072+table,"APFS resource-fork input size invalid.");
    Check(U(input,0,4)==table&&U(input,count*4,4)==input.size(),"APFS resource-fork offset table bounds invalid.");
    std::string output;output.reserve(expected);
    for(std::size_t i=0;i<count;++i){if(control)control();const auto begin=U(input,i*4,4),end=U(input,(i+1)*4,4);Check(begin>=table&&end>begin&&end<=input.size(),"APFS resource-fork block offsets invalid.");
        auto block=DecodeApfsLzBitmap(input.substr(begin,end-begin),std::min<std::size_t>(65536,expected-output.size()),error);Check(block.has_value(),error.c_str());output.append(*block);}
    if(control)control();Check(output.size()==expected,"APFS resource-fork decoded size mismatch.");return output;
}catch(const std::exception& e){error=e.what();return {};}}
std::optional<std::string> DecodeApfsLzvn(std::string_view input,std::size_t expected,std::string& error){error.clear();try{
    Check(expected>0&&expected<=65536,"APFS compression output block budget exceeded.");
    if(!input.empty()&&static_cast<unsigned char>(input[0])==6){Check(input.size()==expected+1,"APFS uncompressed LZVN block length mismatch.");return std::string(input.substr(1));}
    Check(!input.empty()&&input.size()<=65537,"APFS LZVN input block budget invalid.");
    std::string out(expected,'\0');
    Check(openfruit_lzvn_decode_complete(reinterpret_cast<const unsigned char*>(input.data()),input.size(),reinterpret_cast<unsigned char*>(out.data()),out.size()),"Original LZVN decoder termination/output mismatch.");return out;
}catch(const std::exception& e){error=e.what();return {};}}
std::optional<std::string> DecodeApfsLzvnResourceFork(std::string_view input,std::size_t expected,std::string& error,const std::function<void()>& control){error.clear();try{
    Check(expected>0&&expected<=512ULL*1024*1024,"APFS resource-fork decoded size budget exceeded.");
    const auto count=(expected+65535)/65536,table=(count+1)*4;
    Check(input.size()>=table&&input.size()<=count*131072+table,"APFS resource-fork input size invalid.");
    Check(U(input,0,4)==table&&U(input,count*4,4)==input.size(),"APFS resource-fork offset table bounds invalid.");
    std::string output;output.reserve(expected);
    for(std::size_t i=0;i<count;++i){if(control)control();const auto begin=U(input,i*4,4),end=U(input,(i+1)*4,4);Check(begin>=table&&end>begin&&end<=input.size(),"APFS resource-fork block offsets invalid.");
        auto block=DecodeApfsLzvn(input.substr(begin,end-begin),std::min<std::size_t>(65536,expected-output.size()),error);Check(block.has_value(),error.c_str());output.append(*block);}
    if(control)control();Check(output.size()==expected,"APFS resource-fork decoded size mismatch.");return output;
}catch(const std::exception& e){error=e.what();return {};}}
}
