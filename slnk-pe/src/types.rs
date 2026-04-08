// PE/COFF format constants

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

pub const IMAGE_SCN_CNT_CODE: u32               = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32   = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32        = 0x02000000;
pub const IMAGE_SCN_MEM_EXECUTE: u32            = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32               = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32              = 0x80000000;
pub const IMAGE_SCN_LNK_COMDAT: u32             = 0x00001000;

pub const IMAGE_SYM_CLASS_EXTERNAL: u8      = 2;
pub const IMAGE_SYM_CLASS_STATIC: u8        = 3;
pub const IMAGE_SYM_CLASS_FILE: u8          = 103;
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;

pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
pub const IMAGE_REL_AMD64_ADDR64: u16   = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32: u16   = 0x0002;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u16    = 0x0004;
pub const IMAGE_REL_AMD64_REL32_1: u16  = 0x0005;
pub const IMAGE_REL_AMD64_REL32_2: u16  = 0x0006;
pub const IMAGE_REL_AMD64_REL32_3: u16  = 0x0007;
pub const IMAGE_REL_AMD64_REL32_4: u16  = 0x0008;
pub const IMAGE_REL_AMD64_REL32_5: u16  = 0x0009;
pub const IMAGE_REL_AMD64_SECTION: u16  = 0x000A;
pub const IMAGE_REL_AMD64_SECREL: u16   = 0x000B;

pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16   = 3;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16   = 2;

pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16    = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16       = 0x0100;

pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16    = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

pub const DEFAULT_IMAGE_BASE: u64 = 0x140000000;
pub const SECTION_ALIGN: u32      = 0x1000;
pub const FILE_ALIGN: u32         = 0x200;

pub fn read_u8(buf: &[u8], off: usize) -> u8 { buf[off] }
pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap())
}
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}
pub fn read_i16(buf: &[u8], off: usize) -> i16 {
    i16::from_le_bytes(buf[off..off+2].try_into().unwrap())
}
pub fn read_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}
pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap())
}

pub fn read_coff_name(buf: &[u8], strtab: &[u8]) -> String {
    if buf[0..4] == [0u8; 4] {
        let off = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        if off < strtab.len() {
            let end = strtab[off..].iter().position(|&b| b == 0)
                .unwrap_or(strtab.len() - off);
            return String::from_utf8_lossy(&strtab[off..off+end]).into_owned();
        }
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
