CFLAGS=-Wall -pedantic -O3 -fno-strict-aliasing -fPIC
ARFLAGS=-rcs
CXX=clang++
AR=llvm-ar
SRCS=FastPointernullification.cpp \
	FastPointernullificationAllocator.cpp 
INCS=FastPointernullification.h \
	FastPointernullificationAllocator.h \
	DSE.h
#/usr/local/lib/LLVMgold.so

all: FPN_rt_shared

FPN_rt_shared: 
	mkdir -p shared
	$(CXX) $(CFLAGS) -shared -fPIC $(SRCS) -o shared/libFPN.so -ldl -lpthread -lrt

clean:
	rm -rf *.o *.a *.so *~ shared/ static/