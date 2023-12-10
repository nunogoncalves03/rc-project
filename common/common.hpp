#include <string>

#define MB_N_BYTES 1000000

#define CMD_SIZE 3
#define UID_SIZE 6
#define PASSWORD_SIZE 8
#define AID_SIZE 3
#define AUCTION_NAME_SIZE 10
#define DATE_TIME_SIZE 19
#define DATE_SIZE 10
#define TIME_SIZE 8
#define MAX_FNAME_SIZE 24
#define MAX_FSIZE_SIZE 8
#define MAX_ASSET_FILE_SIZE_MB 10
#define VALUE_SIZE 6
#define DURATION_SIZE 5
#define STATE_SIZE 1

std::string zero_pad_number(int number, int width);
bool is_number(const std::string& str);
bool is_alphanumerical(const std::string& str);
bool is_valid_filename(const std::string& str);
std::string get_date(time_t& n_sec);

ssize_t _read(int fd, void* buf, size_t count);
ssize_t read_from_tcp_socket(int fd, char* buf, size_t count);
ssize_t _write(int fd, const void* buf, size_t count);
