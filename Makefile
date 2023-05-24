# Makefile

# Set the GOOS and GOARCH environment variables
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

# Define the target executable name
TARGET=eth-ws

# Define the default target
.PHONY: all
all: $(TARGET)

# Define the build target
$(TARGET): main.go
	go build -o $(TARGET)
	chmod a+x $(TARGET)

# Define the clean target
.PHONY: clean
clean:
	rm -f $(TARGET)
