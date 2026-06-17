# Termite-Sumu C++ Native Build
# Cross-compile from Kali Linux targeting Windows x64
# Requires: mingw-w64

CXX      = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -s -static -Wall -Wextra
LDFLAGS  = -ladvapi32 -luser32 -ldbghelp
SRCDIR   = src
OBJDIR   = build
BINDIR   = bin
TARGET   = $(BINDIR)/injector.exe

SOURCES  = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS  = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

.PHONY: all clean

all: $(BINDIR) $(OBJDIR) $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[+] Built: $@"
	@ls -lh $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJDIR) $(BINDIR)
