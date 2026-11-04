/* Deterministic decoder for decmpfs type-14 resource forks (LZBITMAP). */
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef void FILE;

#define NULL ((void *)0)
#define RTLD_LAZY 0x1
#define COMPRESSION_LZBITMAP 0x702
#define CHUNK_SIZE 65536UL

extern void *__stderrp;
#define stderr __stderrp
extern int fprintf(void *, const char *, ...);
extern FILE *fopen(const char *, const char *);
extern int fclose(FILE *);
extern size_t fread(void *, size_t, size_t, FILE *);
extern size_t fwrite(const void *, size_t, size_t, FILE *);
extern int fseek(FILE *, long, int);
extern void *malloc(size_t);
extern void free(void *);
extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);
extern char *dlerror(void);
extern int dlclose(void *);
extern unsigned long long strtoull(const char *, char **, int);

typedef size_t DecodeBuffer(
    uint8_t *, size_t, const uint8_t *, size_t, void *, int
);

static size_t minimum(size_t left, size_t right) {
    return left < right ? left : right;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: OPENFRUIT-decmpfs RESOURCE_FORK OUTPUT SIZE\n");
        return 64;
    }
    const unsigned long long output_size = strtoull(argv[3], NULL, 0);
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) return 65;
    FILE *output = fopen(argv[2], "wb");
    if (output == NULL) return 66;

    uint32_t first_offset = 0;
    if (fread(&first_offset, sizeof(first_offset), 1, input) != 1 ||
        first_offset < 8 || first_offset % 4 != 0) {
        fprintf(stderr, "invalid decmpfs offset table\n");
        return 67;
    }
    const uint32_t offset_count = first_offset / 4;
    uint32_t *offsets = (uint32_t *)malloc(offset_count * sizeof(uint32_t));
    if (offsets == NULL) return 68;
    offsets[0] = first_offset;
    if (fread(offsets + 1, sizeof(uint32_t), offset_count - 1, input) !=
        offset_count - 1) return 69;

    void *library = dlopen("/OPENFRUIT/libcompression.dylib", RTLD_LAZY);
    if (library == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 70;
    }
    DecodeBuffer *decode = (DecodeBuffer *)dlsym(library, "compression_decode_buffer");
    if (decode == NULL) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 71;
    }

    uint8_t *destination = (uint8_t *)malloc(CHUNK_SIZE);
    size_t source_capacity = CHUNK_SIZE * 2;
    uint8_t *source = (uint8_t *)malloc(source_capacity);
    if (destination == NULL || source == NULL) return 72;
    unsigned long long written = 0;
    for (uint32_t index = 0; index + 1 < offset_count; ++index) {
        const uint32_t begin = offsets[index];
        const uint32_t end = offsets[index + 1];
        if (end <= begin) return 73;
        const size_t source_size = end - begin;
        if (source_size > source_capacity) return 74;
        if (fseek(input, begin, 0) != 0 ||
            fread(source, 1, source_size, input) != source_size) return 75;
        const size_t expected = minimum(CHUNK_SIZE, (size_t)(output_size - written));
        const uint8_t *result = destination;
        size_t produced = 0;
        if (source_size == expected + 1 && source[0] == 0xff) {
            result = source + 1;
            produced = expected;
        } else {
            produced = decode(
                destination, expected, source, source_size, NULL, COMPRESSION_LZBITMAP
            );
        }
        if (produced != expected || fwrite(result, 1, produced, output) != produced) {
            fprintf(stderr, "decmpfs chunk %u failed: expected %lu, got %lu\n",
                    index, expected, produced);
            return 76;
        }
        written += produced;
    }
    free(source);
    free(destination);
    free(offsets);
    dlclose(library);
    fclose(input);
    if (fclose(output) != 0 || written != output_size) return 77;
    return 0;
}
