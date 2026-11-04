#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern _Bool swift_inproc_plugins_handle_message(
    const uint8_t *input_data,
    intptr_t input_length,
    uint8_t **output_data,
    intptr_t *output_length);

static int read_all(int fd, void *buffer, size_t size, int allow_eof) {
  uint8_t *cursor = buffer;
  size_t offset = 0;
  while (offset < size) {
    ssize_t amount = read(fd, cursor + offset, size - offset);
    if (amount == 0 && offset == 0 && allow_eof) return 0;
    if (amount < 0 && errno == EINTR) continue;
    if (amount <= 0) return -1;
    offset += (size_t)amount;
  }
  return 1;
}

static int write_all(int fd, const void *buffer, size_t size) {
  const uint8_t *cursor = buffer;
  size_t offset = 0;
  while (offset < size) {
    ssize_t amount = write(fd, cursor + offset, size - offset);
    if (amount < 0 && errno == EINTR) continue;
    if (amount <= 0) return -1;
    offset += (size_t)amount;
  }
  return 0;
}

int main(void) {
  static const char startup[] = "OPENFRUIT_APPLE_INPROC_HOST_START\n";
  (void)write_all(STDERR_FILENO, startup, sizeof(startup) - 1);

  for (;;) {
    uint64_t input_length = 0;
    int header = read_all(STDIN_FILENO, &input_length, sizeof(input_length), 1);
    if (header == 0) return 0;
    if (header < 0 || input_length == 0 || input_length > 256ull * 1024 * 1024)
      return 65;

    uint8_t *input = malloc((size_t)input_length);
    if (!input) return 70;
    if (read_all(STDIN_FILENO, input, (size_t)input_length, 0) < 0) {
      free(input);
      return 66;
    }

    uint8_t *output = NULL;
    intptr_t output_length = 0;
    if (getenv("OPENFRUIT_APPLE_HOST_PROBE_PAUSE")) sleep(60);
    _Bool failed = swift_inproc_plugins_handle_message(
        input, (intptr_t)input_length, &output, &output_length);
    free(input);

    if (failed || !output || output_length <= 0) {
      static const char error[] = "OPENFRUIT: Apple in-process plugin server failed: ";
      (void)write_all(STDERR_FILENO, error, sizeof(error) - 1);
      if (output && output_length > 0)
        (void)write_all(STDERR_FILENO, output, (size_t)output_length);
      (void)write_all(STDERR_FILENO, "\n", 1);
      free(output);
      return 67;
    }

    uint64_t framed_length = (uint64_t)output_length;
    int write_failed =
        write_all(STDOUT_FILENO, &framed_length, sizeof(framed_length)) < 0 ||
        write_all(STDOUT_FILENO, output, (size_t)output_length) < 0;
    free(output);
    if (write_failed) return 68;
  }
}
