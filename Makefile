CXX = g++
LDFLAGS = -lnetfilter_queue

TARGET = 1m-block
SRCS = main.cpp hdr.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.cpp hdr.h
	$(CXX) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

