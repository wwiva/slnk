// shared types used by all linker backends

use std::collections::HashMap;

// a symbol from an object file
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub section_index: usize,
    pub sym_type: SymbolType,
    pub binding: SymbolBinding,
    pub defined: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
    File,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
}

// a single relocation entry
#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u64,
    // index into the object file's symbol table
    pub sym_index: usize,
    // cached name - empty for unnamed section/local symbols
    pub symbol_name: String,
    pub reloc_type: u32,
    pub addend: i64,
}

// one section from a parsed object file
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub data: Vec<u8>,
    pub vaddr: u64,
    pub align: u64,
    pub flags: SectionFlags,
    pub relocations: Vec<Relocation>,
}

#[derive(Debug, Clone, Default)]
pub struct SectionFlags {
    pub write: bool,
    pub alloc: bool,
    pub exec: bool,
}

// a fully parsed object file
#[derive(Debug, Clone)]
pub struct ObjectFile {
    pub path: String,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

// the resolved, laid-out output ready for a backend to emit
#[derive(Debug)]
pub struct LinkedOutput {
    pub sections: Vec<MergedSection>,
    pub symbols: HashMap<String, ResolvedSymbol>,
    pub entry_point: u64,
}

// a merged output section (many input sections combined into one)
#[derive(Debug)]
pub struct MergedSection {
    pub name: String,
    pub data: Vec<u8>,
    pub vaddr: u64,
    pub align: u64,
    pub flags: SectionFlags,
}

// a symbol after full address resolution
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub name: String,
    pub vaddr: u64,
}

// links multiple object files and returns a LinkedOutput
// this is the entry point called by format-specific backends
pub fn align_up(val: u64, align: u64) -> u64 {
    if align <= 1 { return val; }
    (val + align - 1) & !(align - 1)
}
