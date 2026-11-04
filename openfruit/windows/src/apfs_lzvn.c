// OPENFRUIT-owned bounds/termination adapter; Apple decoder is unchanged.
#include "lzvn_decode_base.h"
#include <string.h>

int openfruit_lzvn_decode_complete(const unsigned char* source,size_t source_bytes,
    unsigned char* output,size_t output_bytes){
    lzvn_decoder_state state;
    memset(&state,0,sizeof(state));
    state.src=source;state.src_end=source+source_bytes;
    state.dst=output;state.dst_begin=output;state.dst_current=output;
    state.dst_end=output+output_bytes;
    lzvn_decode(&state);
    // APFS resource slots retain unused bytes after EOS, including nonzero
    // bytes. Bounds apply to the slot; EOS and complete output prove decoding.
    return state.end_of_stream&&state.dst==state.dst_end
        &&state.L==0&&state.M==0;
}
