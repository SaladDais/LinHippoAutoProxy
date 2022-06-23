CC           = c++
LDFLAGS      = -shared -Wl, -ldl
CXXFLAGS     = -fPIC -Wall -march=native -g -std=c++11
DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -combine -fwhole-program

TARGET  = libhippoautoproxy.so
SOURCES = socks5udphooker.cpp
OBJECTS = $(SOURCES:.cpp=.o)

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin
LIBDIR = $(PREFIX)/lib

all: $(TARGET)

clean :
	-rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(LDFLAGS) $(CXXFLAGS) $(DEBUGFLAGS) -o $(TARGET) $(OBJECTS)
