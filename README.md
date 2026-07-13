# FPN: Fast Pointer Nullification

FPN is a compiler-based defense against use-after-free and double-free bugs in C/C++.
An LLVM 18 pass instruments pointer stores and allocator calls; the runtime library
tracks where heap pointers are stored and invalidates dangling pointers when their
object is freed. Source code for our NDSS 2026 paper.

## Requirements

Linux x86-64, LLVM/Clang 18 (installed via `sudo make install`, so headers are under
/usr/local), CMake, GNU Make.

## Building the compiler pass

1. git clone https://github.com/duyubo/Fast-Pointer-Nullification-NDSS-2026.git
2. cd Fast-Pointer-Nullification-NDSS-2026/compiler_pass
3. cmake .        # if LLVM is installed elsewhere: cmake -DCMAKE_CXX_FLAGS="$(llvm-config --cxxflags)" .
4. make           # produces libFPNPass.so

## Building the runtime library

1. cd ../runtime
2. make           # produces shared/libFPN.so

## Running FPN

From the repository root:

    ./vcc-FPN source_code.c -o program
    ./program

For C++ sources, use `./v++FPN` instead (same options, drives `clang++`).

## Citation

```bibtex
@inproceedings{fpn-ndss26,
  title     = {Fast Pointer Nullification for Use-After-Free Prevention},
  author    = {Yubo Du, Youtao Zhang, Jun Yang},
  booktitle = {Network and Distributed System Security Symposium (NDSS)},
  year      = {2026}
}
```
