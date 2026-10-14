TARGET = titan
CC = xcrun -sdk iphoneos clang
CFLAGS = -arch arm64 -arch arm64e -o $(TARGET) -Iexternal/include
LDFLAGS = -framework CoreFoundation -framework IOSurface -framework IOKit -Lexternal/lib -ljailbreak
SRCS = $(wildcard main.c src/*.c src/*.m)

$(TARGET):
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS)

sign: $(TARGET)
	ldid -Sentitlements.plist -Cadhoc $(TARGET)

clean:
	rm -f $(TARGET)

all: clean $(TARGET) sign

.PHONY: all clean