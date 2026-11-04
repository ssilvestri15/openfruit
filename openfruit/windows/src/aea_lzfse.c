// OPENFRUIT-owned bounded adapter to the unchanged Apple reference decoder.
#include "lzfse_internal.h"
#include <stdlib.h>
#include <string.h>
int openfruit_lzfse_decode_exact(const unsigned char* source,size_t source_bytes,
    unsigned char* output,size_t output_bytes){
    lzfse_decoder_state* state=(lzfse_decoder_state*)calloc(1,sizeof(lzfse_decoder_state));
    if(!state)return 0;
    state->src=source;state->src_begin=source;state->src_end=source+source_bytes;
    state->dst=output;state->dst_begin=output;state->dst_end=output+output_bytes;
    const int status=lzfse_decode(state);
    const int exact=status==LZFSE_STATUS_OK&&state->end_of_stream&&state->src==state->src_end&&state->dst==state->dst_end;
    memset(state,0,sizeof(*state));free(state);return exact;
}
