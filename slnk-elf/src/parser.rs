// parses ELF64 relocatable (.o) files into ObjectFile structs

use slnk_common::{ObjectFile, Relocation, Section, SectionFlags, Symbol, SymbolBinding, SymbolType};
use crate::types::*;

pub fn parse(path: &str, data: &[u8]) -> Result<ObjectFile, String> {
    validate_magic(data)?;

    let e_type = read_u16(data, 16);
    if e_type != ET_REL {
        return Err(format!("{}: not a relocatable object (e_type={})", path, e_type));
    }

    let e_machine = read_u16(data, 18);
    if e_machine != EM_X86_64 {
        return Err(format!("{}: unsupported machine type {}", path, e_machine));
    }

    let e_shoff = read_u64(data, 40) as usize;
    let e_shnum = read_u16(data, 60) as usize;
    let e_shentsize = read_u16(data, 58) as usize;
    let e_shstrndx = read_u16(data, 62) as usize;

    if e_shoff == 0 || e_shnum == 0 {
        return Err(format!("{}: no section headers", path));
    }

    let shstrtab = read_section_data(data, e_shoff, e_shentsize, e_shstrndx);

    let mut sections: Vec<Section> = Vec::with_capacity(e_shnum);
    let mut symtab_idx: Option<usize> = None;

    for i in 0..e_shnum {
        let shdr_off = e_shoff + i * e_shentsize;
        let sh_name = read_u32(data, shdr_off) as usize;
        let sh_type = read_u32(data, shdr_off + 4);
        let sh_flags = read_u64(data, shdr_off + 8);
        let sh_offset = read_u64(data, shdr_off + 24) as usize;
        let sh_size = read_u64(data, shdr_off + 32) as usize;
        let sh_addralign = read_u64(data, shdr_off + 56);

        let name = read_str(&shstrtab, sh_name);

        if sh_type == SHT_SYMTAB {
            symtab_idx = Some(i);
        }

        let sec_data = if sh_type == SHT_NOBITS || sh_size == 0 {
            vec![0u8; sh_size]
        } else {
            data[sh_offset..sh_offset + sh_size].to_vec()
        };

        sections.push(Section {
            name,
            data: sec_data,
            vaddr: 0,
            align: sh_addralign.max(1),
            flags: SectionFlags {
                write: sh_flags & SHF_WRITE != 0,
                alloc: sh_flags & SHF_ALLOC != 0,
                exec: sh_flags & SHF_EXECINSTR != 0,
            },
            relocations: Vec::new(),
        });
    }

    let mut symbols: Vec<Symbol> = Vec::new();
    let mut strtab_data: Vec<u8> = Vec::new();

    if let Some(sym_idx) = symtab_idx {
        let shdr_off = e_shoff + sym_idx * e_shentsize;
        let sh_link = read_u32(data, shdr_off + 40) as usize;
        let sh_offset = read_u64(data, shdr_off + 24) as usize;
        let sh_size = read_u64(data, shdr_off + 32) as usize;

        strtab_data = read_section_data(data, e_shoff, e_shentsize, sh_link);

        let sym_count = sh_size / 24;
        for s in 0..sym_count {
            let soff = sh_offset + s * 24;
            let st_name = read_u32(data, soff) as usize;
            let st_info = read_u8(data, soff + 4);
            let st_shndx = read_u16(data, soff + 6) as usize;
            let st_value = read_u64(data, soff + 8);
            let st_size = read_u64(data, soff + 16);

            let name = read_str(&strtab_data, st_name);
            let binding = match st_info >> 4 {
                STB_GLOBAL => SymbolBinding::Global,
                STB_WEAK => SymbolBinding::Weak,
                _ => SymbolBinding::Local,
            };
            let sym_type = match st_info & 0xf {
                STT_FUNC => SymbolType::Func,
                STT_OBJECT => SymbolType::Object,
                STT_SECTION => SymbolType::Section,
                STT_FILE => SymbolType::File,
                _ => SymbolType::NoType,
            };
            // SHN_UNDEF=0, SHN_ABS=0xfff1, SHN_COMMON=0xfff2
            let defined = st_shndx != 0 && st_shndx != 0xffff;

            symbols.push(Symbol {
                name,
                value: st_value,
                size: st_size,
                section_index: st_shndx,
                sym_type,
                binding,
                defined,
            });
        }
    }

    // parse RELA sections and attach relocations to their target sections
    for i in 0..e_shnum {
        let shdr_off = e_shoff + i * e_shentsize;
        let sh_type = read_u32(data, shdr_off + 4);
        if sh_type != SHT_RELA {
            continue;
        }

        let sh_info = read_u32(data, shdr_off + 44) as usize;
        let sh_offset = read_u64(data, shdr_off + 24) as usize;
        let sh_size = read_u64(data, shdr_off + 32) as usize;

        if sh_info >= sections.len() {
            continue;
        }

        let rela_count = sh_size / 24;
        for r in 0..rela_count {
            let roff = sh_offset + r * 24;
            let r_offset = read_u64(data, roff);
            let r_info = read_u64(data, roff + 8);
            let r_addend = read_i64(data, roff + 16);

            let sym_idx = (r_info >> 32) as usize;
            let reloc_type = (r_info & 0xffffffff) as u32;

            let sym_name = if sym_idx < symbols.len() {
                symbols[sym_idx].name.clone()
            } else {
                String::new()
            };

            sections[sh_info].relocations.push(Relocation {
                offset: r_offset,
                sym_index: sym_idx,
                symbol_name: sym_name,
                reloc_type,
                addend: r_addend,
            });
        }
    }

    Ok(ObjectFile { path: path.to_string(), sections, symbols })
}

fn validate_magic(data: &[u8]) -> Result<(), String> {
    if data.len() < 64 {
        return Err("file too small to be ELF".into());
    }
    if &data[0..4] != ELFMAG {
        return Err("not an ELF file".into());
    }
    if data[4] != ELFCLASS64 {
        return Err("only ELF64 is supported".into());
    }
    if data[5] != ELFDATA2LSB {
        return Err("only little-endian ELF is supported".into());
    }
    Ok(())
}

fn read_section_data(data: &[u8], shoff: usize, shentsize: usize, idx: usize) -> Vec<u8> {
    let off = shoff + idx * shentsize;
    let sh_offset = read_u64(data, off + 24) as usize;
    let sh_size = read_u64(data, off + 32) as usize;
    if sh_size == 0 { return Vec::new(); }
    data[sh_offset..sh_offset + sh_size].to_vec()
}
