// ELF format constants and raw struct helpers

// ELF identification bytes
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_REL: u16 = 1;
pub const EM_X86_64: u16 = 62;
pub const EV_CURRENT: u8 = 1;

// section header types
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;

// section header flags
pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;
pub const SHF_TLS: u64 = 0x400;

// program header type
pub const PT_LOAD: u32 = 1;

// program header flags
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// symbol binding
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

// symbol type
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;

// x86-64 relocation types
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_GOTPCRELX: u32 = 41;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

// TLS relocation types
pub const R_X86_64_TPOFF32: u32 = 23;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_GOTTPOFF: u32 = 22;

// default base address for ELF executables
pub const DEFAULT_BASE: u64 = 0x400000;
pub const PAGE_SIZE: u64 = 0x1000;

// read helpers
pub fn read_u8(buf: &[u8], off: usize) -> u8 { buf[off] }
pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap())
}
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}
pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap())
}
pub fn read_i64(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(buf[off..off+8].try_into().unwrap())
}
pub fn read_str(strtab: &[u8], offset: usize) -> String {
    let end = strtab[offset..].iter().position(|&b| b == 0)
        .unwrap_or(strtab.len() - offset);
    String::from_utf8_lossy(&strtab[offset..offset+end]).into_owned()
}
