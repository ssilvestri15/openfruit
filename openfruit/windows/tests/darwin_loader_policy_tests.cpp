#include "darwin_loader_policy.hpp"
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
int main(){try{
    for(bool mounted:{false,true})for(bool authorized:{false,true}){
        DarwinLoaderPolicy policy(mounted,authorized);std::uint64_t output=0xff;
        if(policy.Query(0,output)||output!=(mounted&&authorized?1:0))throw std::runtime_error("actual namespace/launch authorization ignored");
        for(auto input:{1ULL,2ULL,4ULL,0xffffffffffffffffULL}){output=0xfeed;
            if(policy.Query(input,output)!=45||output!=0xfeed)throw std::runtime_error("unknown process mode fabricated permissions");}
        if(policy.ToJson().Get("signature_authority")->Bool())throw std::runtime_error("loader authorization fabricated signing authority");
    }
    std::cout<<"Native loader namespace/authorization isolation and unsupported process modes PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
