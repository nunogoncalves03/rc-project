#include <string>

bool is_number(const std::string& str);
bool is_alphanumerical(const std::string& str);
bool is_valid_filename(const std::string& str);

ssize_t _read(int fd, void* buf, size_t count);
ssize_t _write(int fd, const void* buf, size_t count);
