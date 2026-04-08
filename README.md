# slnk

A linker for ELF (Linux) and PE (Windows) executables and shared libraries, written in Rust.

## features

**ELF executable (`.elf`)**
- links x86-64 `.o` object files into static executables
- all standard x86-64 relocations: `PC32`, `PLT32`, `64`, `32/32S`, `GOTPCREL`, `REX_GOTPCRELX`
- TLS: `TPOFF32/64`, `GOTTPOFF`, `PT_TLS` segment, local-exec model
- GOT construction and GOTPCRELX relaxation for PIC code
- `.bss`, `SHN_COMMON`, weak symbols, COMDAT deduplication
- `__init_array`/`__fini_array` with linker-defined boundary symbols
- `PT_GNU_STACK`, `PT_GNU_RELRO`
- `.a` archive linking with lazy symbol resolution

**ELF shared library (`.so`)**
- produces `ET_DYN` position-independent shared objects
- `.dynsym`, `.dynstr`, `.gnu.hash` with correct bucket-sorted symbol order
- `PT_DYNAMIC`, `PT_GNU_STACK`, per-permission `PT_LOAD` segments
- `R_X86_64_RELATIVE` base relocations via `.rela.dyn`
- `--soname` for `DT_SONAME`
- `dlopen`/`dlsym` compatible

**PE executable (`.exe`)**
- links x86-64 COFF `.obj` files into PE32+ executables
- all standard x86-64 COFF relocations: `REL32`, `REL32_1..5`, `ADDR64`, `ADDR32`, `ADDR32NB`, `SECTION`, `SECREL`
- import table (`.idata`) built from `__imp_XXX` references and `.idata$*` sections
- reads DLL names and hints from mingw import libraries (`.a`/`.lib`)
- weak external symbols (`IMAGE_SYM_CLASS_WEAK_EXTERNAL`)
- COMDAT deduplication (`.text$X` etc.)
- `.bss`, `SHN_COMMON`, `.reloc` base relocations
- `.rsrc` resource section for icons and version metadata
- `.a`/`.lib` archive linking with lazy symbol resolution

**PE DLL (`.dll`)**
- sets `IMAGE_FILE_DLL` characteristic
- `.edata` export directory with EAT, NPT, and ordinal table
- `.reloc` base relocation section (required for DLL rebasing)

## usage

```
slnk [options] file.o ...          # ELF executable (auto-detected)
slnk --shared [options] file.o ... # ELF shared library
slnk --pe [options] file.obj ...   # PE executable
slnk --dll [options] file.obj ...  # PE DLL
```

**options**
```
-o <file>                output file (default: a.out / a.exe / a.so / a.dll)
-e <symbol>              entry point (default: _start / mainCRTStartup)
--elf                    force ELF output
--pe                     force PE output
--shared                 produce a shared library (.so)
--dll                    produce a DLL (PE shared library)
--soname <name>          set DT_SONAME for .so / DLL name for .dll
--icon <file.ico>        embed icon into PE binary
--pe-version <M.m.p.b>   version number (e.g. 1.2.3.0)
--pe-description <str>   file description (written to VS_VERSIONINFO)
--pe-company <str>       company name
--pe-product <str>       product name
--pe-copyright <str>     copyright string
--pe-subsystem <s>       console | windows (default: console)
```

## build

```
cargo build --release
```

binary at `target/release/slnk` on Linux or `target/release/slnk.exe` on Windows.

requirements: Rust 1.75+

## examples

**ELF executable**
```bash
gcc -c -O0 -ffreestanding main.c -o main.o
slnk -o program main.o
./program
```

**ELF shared library**
```bash
gcc -c -fPIC -O0 mylib.c -o mylib.o
slnk --shared --soname libmylib.so.1 -o libmylib.so.1 mylib.o

# link an executable against it
gcc -o app main.o -L. -lmylib -Wl,-rpath,.
./app

# or load at runtime
# dlopen("./libmylib.so.1", RTLD_NOW)
```

**PE executable (from Linux with mingw)**
```bash
x86_64-w64-mingw32-gcc -c -O0 -ffreestanding -nostdlib main.c -o main.obj
slnk --pe -e mainCRTStartup -o program.exe main.obj
```

**PE executable (from Windows)**
```
cl /c /GS- /nologo main.c
slnk --pe -o program.exe main.obj
```

**PE DLL**
```bash
x86_64-w64-mingw32-gcc -c -O0 mylib.c -o mylib.obj
x86_64-w64-mingw32-gcc -c -O0 dllmain.c -o dllmain.obj
slnk --dll -e DllMain -o mylib.dll mylib.obj dllmain.obj
```

**PE with icon and metadata**
```bash
slnk --pe \
  --icon app.ico \
  --pe-version 1.0.0.0 \
  --pe-description "My Application" \
  --pe-company "Example Corp" \
  --pe-subsystem windows \
  -o app.exe main.obj
```

## architecture

```
slnk-workspace/
  slnk-common/        shared types: ObjectFile, Symbol, Relocation, MergedSection, ...
  slnk-elf/           ELF backend
    types.rs           ELF64 constants and byte-read helpers
    parser.rs          ELF64 .o parser (sections, symbols, RELA)
    linker.rs          section merging, GOT, TLS, symbol resolution, relocations
    emitter.rs         ELF64 executable writer
    so_linker.rs       shared library linker (PI layout, export collection)
    so_emitter.rs      ET_DYN writer (dynsym, gnu.hash, dynamic, LOAD segments)
  slnk-pe/            PE/COFF backend
    types.rs           COFF/PE constants and byte-read helpers
    parser.rs          COFF .obj parser (symbols with aux records, sections, relocs)
    linker.rs          section merging, import table, weak symbols, COMDAT
    emitter.rs         PE32+ writer for EXE and DLL (edata, reloc, rsrc)
    rsrc.rs            PE resource section builder (RT_ICON, VS_VERSIONINFO)
  slnk/               CLI binary
    main.rs            argument parsing, archive loading, format dispatch
```

## license

GPL v3.
