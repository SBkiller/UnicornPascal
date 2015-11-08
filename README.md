# UnicornPascal

Pascal language binding for the [Unicorn emulator](http://www.unicorn-engine.org/)
([GitHub](https://github.com/unicorn-engine/unicorn)).

*Unicorn* is a lightweight multi-platform, multi-architecture CPU emulator framework
based on [QEMU](http://www.qemu.org/).

## License

GPL

## Compatibility

OS
: Windows, Linux

Compiler
: Delphi, Free Pascal

## Features

* Same API as the C core 
  - with some workarounds for Pascals case insensitivity: 
    `uc_mem_write()` -> `uc_mem_write_()`, `uc_mem_read()` -> `uc_mem_read_()`
  - and the missing feature passing variable number of arguments to functions (`...`): 
    `uc_hook_add()` -> `uc_hook_add_0()`, `uc_hook_add_1()`, `uc_hook_add_2()`
* Compiler agnostic, as long as it is some sort of modern Pascal
* Multiplatform (Windows and Linux are tested)

## Examples

* `SampleArm64` Emulate ARM64
* `SampleX86` Emulate 16, 32, 64 Bit x86
* `SampleSparc` Emulate SPARC
* `SampleMips` Emulate MIPS
* `SampleM68k` Emulate m68k


