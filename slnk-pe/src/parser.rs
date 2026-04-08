// COFF object file parser - produces ObjectFile structs identical to ELF parser output

use slnk_common::{ObjectFile, Relocation, Section, SectionFlags, Symbol, SymbolBinding, SymbolType};
use crate::types::*;

pub fn parse(path: &str, data: &[u8]) -> Result<ObjectFile, String> {
    if data.len() < 20 {
        return Err(format!("{}: file too small to be COFF", path));
    }

    let machine = read_u16(data, 0);
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(format!("{}: unsupported COFF machine {:#06x} (only AMD64 supported)", path, machine));
    }

    let num_sections   = read_u16(data, 2) as usize;
    let sym_table_off  = read_u32(data, 8) as usize;
    let num_symbols    = read_u32(data, 12) as usize;
    let opt_hdr_size   = read_u16(data, 16) as usize;

    // section headers start after COFF header (20 bytes) + optional header
    let sec_hdr_start = 20 + opt_hdr_size;

    // string table immediately follows symbol table (each symbol is 18 bytes)
    let strtab_start = sym_table_off + num_symbols * 18;
    let strtab = if strtab_start + 4 <= data.len() {
        let strtab_size = read_u32(data, strtab_start) as usize;
        if strtab_start + strtab_size <= data.len() {
            &data[strtab_start..strtab_start + strtab_size]
        } else { &data[strtab_start..] }
    } else { &[] };

    // parse section headers (40 bytes each)
    let mut sections: Vec<Section> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sec_hdr_start + i * 40;
        if off + 40 > data.len() { break; }

        let name       = read_coff_name(&data[off..off+8], strtab);
        let virt_size  = read_u32(data, off + 8);
        let raw_size   = read_u32(data, off + 16) as usize;
        let raw_off    = read_u32(data, off + 20) as usize;
        let rel_off    = read_u32(data, off + 24) as usize;
        let num_relocs = read_u16(data, off + 32) as usize;
        let flags      = read_u32(data, off + 36);

        let sec_data = if raw_size > 0 && raw_off + raw_size <= data.len() {
            // BSS-like: uninitialized data may have raw_size=0 but virt_size>0
            data[raw_off..raw_off + raw_size].to_vec()
        } else {
            vec![0u8; virt_size as usize]
        };

        // if virt_size > raw_size, zero-extend (common for BSS-like sections)
        let mut sec_data = sec_data;
        if (virt_size as usize) > sec_data.len() {
            sec_data.resize(virt_size as usize, 0);
        }

        let sec_flags = SectionFlags {
            exec:  flags & IMAGE_SCN_MEM_EXECUTE != 0,
            write: flags & IMAGE_SCN_MEM_WRITE   != 0,
            alloc: flags & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA
                          | IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0,
        };

        // extract alignment from flags bits 20-23: value = 2^(n-1), n=1..16
        let align_bits = (flags >> 20) & 0xF;
        let align = if align_bits == 0 { 1u64 } else { 1u64 << (align_bits - 1) };

        // parse COFF relocations for this section (10 bytes each)
        let mut relocations: Vec<Relocation> = Vec::new();
        for r in 0..num_relocs {
            let roff = rel_off + r * 10;
            if roff + 10 > data.len() { break; }
            let r_vaddr   = read_u32(data, roff) as u64;
            let r_sym_idx = read_u32(data, roff + 4) as usize;
            let r_type    = read_u16(data, roff + 8) as u32;

            // resolve symbol name now (will be re-resolved during linking)
            let sym_name = resolve_sym_name(data, sym_table_off, r_sym_idx, strtab);

            relocations.push(Relocation {
                offset: r_vaddr,
                sym_index: r_sym_idx,
                symbol_name: sym_name,
                reloc_type: r_type,
                addend: 0, // COFF uses inline addends, not explicit
            });
        }

        sections.push(Section {
            name,
            data: sec_data,
            vaddr: 0,
            align,
            flags: sec_flags,
            relocations,
        });
    }

    // parse symbol table (18 bytes per record)
    let mut symbols: Vec<Symbol> = Vec::new();
    let mut i = 0;
    while i < num_symbols {
        let off = sym_table_off + i * 18;
        if off + 18 > data.len() { break; }

        let name      = read_coff_name(&data[off..off+8], strtab);
        let value     = read_u32(data, off + 8) as u64;
        let section   = read_i16(data, off + 12);
        let _typ      = read_u16(data, off + 14);
        let storage   = read_u8(data, off + 16);
        let num_aux   = read_u8(data, off + 17) as usize;

        let binding = match storage {
            IMAGE_SYM_CLASS_EXTERNAL      => SymbolBinding::Global,
            IMAGE_SYM_CLASS_WEAK_EXTERNAL => SymbolBinding::Weak,
            _ => SymbolBinding::Local,
        };
        let sym_type = SymbolType::NoType;
        let (defined, sec_idx) = match section {
            0  => (false, 0usize),
            -1 => (true, 0xfff1usize),
            n if n > 0 => (true, (n - 1) as usize),
            _  => (false, 0usize),
        };

        // WEAK_EXTERNAL with aux: if undefined (sec=0), resolve to fallback symbol via tag_idx
        let (binding, defined, sec_idx, value) =
            if storage == IMAGE_SYM_CLASS_WEAK_EXTERNAL && section == 0 && num_aux > 0 {
                let aux_off = sym_table_off + (i + 1) * 18;
                if aux_off + 4 <= data.len() {
                    let tag_idx = read_u32(data, aux_off) as usize;
                    // tag_idx points to the fallback symbol - look it up
                    let fallback_off = sym_table_off + tag_idx * 18;
                    if fallback_off + 18 <= data.len() {
                        let fb_sec  = read_i16(data, fallback_off + 12);
                        let fb_val  = read_u32(data, fallback_off + 8) as u64;
                        if fb_sec > 0 {
                            // fallback is defined in a section - use it
                            (SymbolBinding::Weak, true, (fb_sec - 1) as usize, fb_val)
                        } else {
                            (SymbolBinding::Weak, false, 0usize, 0u64)
                        }
                    } else { (SymbolBinding::Weak, false, 0usize, 0u64) }
                } else { (SymbolBinding::Weak, false, 0usize, 0u64) }
            } else {
                (binding, defined, sec_idx, value)
            };

        if storage != IMAGE_SYM_CLASS_FILE {
            symbols.push(Symbol {
                name,
                value,
                size: 0,
                section_index: sec_idx,
                sym_type,
                binding,
                defined,
            });
        } else {
            // push placeholder to keep indices aligned
            symbols.push(Symbol {
                name: String::new(),
                value: 0, size: 0,
                section_index: 0,
                sym_type: SymbolType::File,
                binding: SymbolBinding::Local,
                defined: false,
            });
        }

        // push placeholders for aux records
        for _ in 0..num_aux {
            symbols.push(Symbol {
                name: String::new(), value: 0, size: 0,
                section_index: 0, sym_type: SymbolType::NoType,
                binding: SymbolBinding::Local, defined: false,
            });
        }

        i += 1 + num_aux;
    }

    Ok(ObjectFile { path: path.to_string(), sections, symbols })
}

fn resolve_sym_name(data: &[u8], sym_table_off: usize, sym_idx: usize, strtab: &[u8]) -> String {
    let off = sym_table_off + sym_idx * 18;
    if off + 8 > data.len() { return String::new(); }
    read_coff_name(&data[off..off+8], strtab)
}
