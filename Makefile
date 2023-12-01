CC = g++
CXX = g++
LD = g++

INCLUDE_DIRS := user server common
INCLUDES = $(addprefix -I, $(INCLUDE_DIRS))

TARGETS = user/user server/server
TARGET_EXECS = user server

USER_SOURCES := $(wildcard user/*.cpp)
COMMON_SOURCES := $(wildcard common/*.cpp)
SERVER_SOURCES := $(wildcard server/*.cpp)
SOURCES := $(USER_SOURCES) $(COMMON_SOURCES) $(SERVER_SOURCES)

USER_HEADERS := $(wildcard user/*.hpp)
COMMON_HEADERS := $(wildcard common/*.hpp)
SERVER_HEADERS := $(wildcard server/*.hpp)
HEADERS := $(USER_HEADERS) $(COMMON_HEADERS) $(SERVER_HEADERS)

USER_OBJECTS := $(USER_SOURCES:.cpp=.o)
COMMON_OBJECTS := $(COMMON_SOURCES:.cpp=.o)
SERVER_OBJECTS := $(SERVER_SOURCES:.cpp=.o)
OBJECTS := $(USER_OBJECTS) $(COMMON_OBJECTS) $(SERVER_OBJECTS)

CXXFLAGS = -std=c++17
LDFLAGS = -std=c++17

CXXFLAGS += $(INCLUDES)
LDFLAGS += $(INCLUDES)

vpath # clears VPATH
vpath %.hpp $(INCLUDE_DIRS)

# Run `make OPTIM=no` to disable -O3
ifeq ($(strip $(OPTIM)), no)
	CXXFLAGS += -O0
else
	CXXFLAGS += -O3
endif

# Run `make DEBUG=true` to run with debug symbols
ifeq ($(strip $(DEBUG)), yes)
	CXXFLAGS += -g
endif

#LDFLAGS = -fsanitize=address -lasan

CXXFLAGS += -fdiagnostics-color=always
CXXFLAGS += -Wall
CXXFLAGS += -Werror
CXXFLAGS += -Wextra
CXXFLAGS += -Wcast-align
CXXFLAGS += -Wconversion
CXXFLAGS += -Wfloat-equal
CXXFLAGS += -Wformat=2
CXXFLAGS += -Wnull-dereference
CXXFLAGS += -Wshadow
CXXFLAGS += -Wsign-conversion
CXXFLAGS += -Wswitch-default
CXXFLAGS += -Wswitch-enum
CXXFLAGS += -Wundef
CXXFLAGS += -Wunreachable-code
CXXFLAGS += -Wunused
LDFLAGS += -pthread


.PHONY: all clean fmt fmt-check package

all: $(TARGET_EXECS)

fmt: $(SOURCES) $(HEADERS)
	clang-format -i $^

fmt-check: $(SOURCES) $(HEADERS)
	clang-format -n --Werror $^

user/user: $(USER_OBJECTS) $(USER_HEADERS) $(COMMON_OBJECTS) $(COMMON_HEADERS)
server/server: $(SERVER_OBJECTS) $(SERVER_HEADERS) $(COMMON_OBJECTS) $(COMMON_HEADERS)

user: user/user
	cp user/user ./client
server: server/server
	cp server/server ./as

clean:
	rm -f $(OBJECTS) $(TARGETS) client as
