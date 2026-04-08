// core ELF linker: section merging, symbol resolution, GOT building, relocation application

use std::collections::HashMap;
use slnk_common::{
    align_up, LinkedOutput, MergedSection, ObjectFile, ResolvedSymbol, SectionFlags, Symbol,
    SymbolBinding, SymbolType,
};
use crate::types::*;

const BASE: u64 = DEFAULT_BASE;
const PAGE: u64 = 0x1000;

// maps input section name prefixes to canonical output section names
fn output_section_name(input: &str) -> Option<&'static str> {
    if input.starts_with(".text") { return Some(".text"); }
    if input.starts_with(".rodata") { return Some(".rodata"); }
    if input.starts_with(".data.rel.ro") { return Some(".data.rel.ro"); }
    if input.starts_with(".tdata") { return Some(".tdata"); }
    if input.starts_with(".tbss") { return Some(".tbss"); }
    if input.starts_with(".data") { return Some(".data"); }
    if input.starts_with(".bss") { return Some(".bss"); }
    if input.starts_with(".init_array") { return Some(".init_array"); }
    if input.starts_with(".fini_array") { return Some(".fini_array"); }
    None
}

struct OutputSectionDef {
    name: &'static str,
    flags: SectionFlags,
    tls: bool,
}

fn output_section_defs() -> Vec<OutputSectionDef> {
    vec![
        OutputSectionDef { name: ".text",         flags: SectionFlags { alloc: true, exec: true,  write: false }, tls: false },
        OutputSectionDef { name: ".rodata",        flags: SectionFlags { alloc: true, exec: false, write: false }, tls: false },
        OutputSectionDef { name: ".data.rel.ro",   flags: SectionFlags { alloc: true, exec: false, write: false }, tls: false },
        OutputSectionDef { name: ".tdata",         flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: true  },
        OutputSectionDef { name: ".tbss",          flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: true  },
        OutputSectionDef { name: ".init_array",    flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: false },
        OutputSectionDef { name: ".fini_array",    flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: false },
        OutputSectionDef { name: ".data",          flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: false },
        OutputSectionDef { name: ".got",           flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: false },
        OutputSectionDef { name: ".bss",           flags: SectionFlags { alloc: true, exec: false, write: true  }, tls: false },
    ]
}

// maps (obj_path, section_index) -> vaddr after layout
pub struct LinkContext {
    pub section_vaddrs: HashMap<(String, usize), u64>,
    pub got_offsets: HashMap<String, u64>,
    pub got_vaddr: u64,
    // TLS segment: vaddr and total size (tdata filesz + tbss memsz)
    pub tls_vaddr: u64,
    pub tls_filesz: u64,
    pub tls_memsz: u64,
    pub tls_align: u64,
}

pub fn link(objects: Vec<ObjectFile>, entry: &str) -> Result<(LinkedOutput, LinkContext), String> {
    let defs = output_section_defs();

    // step 1: merge input sections into output sections
    let mut merged: HashMap<&'static str, MergedSection> = HashMap::new();
    for def in &defs {
        merged.insert(def.name, MergedSection {
            name: def.name.to_string(),
            data: Vec::new(),
            vaddr: 0,
            align: 1,
            flags: def.flags.clone(),
        });
    }

    // (obj_path, section_index) -> (output_section_name, byte_offset_within_it)
    let mut section_offsets: HashMap<(String, usize), (&'static str, u64)> = HashMap::new();

    for obj in &objects {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            let out_name = match output_section_name(&sec.name) {
                Some(n) => n,
                None => continue,
            };
            let ms = merged.get_mut(out_name).unwrap();

            let align = sec.align.max(1);
            let cur_len = ms.data.len() as u64;
            let aligned = align_up(cur_len, align);
            ms.data.resize(aligned as usize, 0);
            ms.align = ms.align.max(align);

            let offset_in_merged = ms.data.len() as u64;
            ms.data.extend_from_slice(&sec.data);
            section_offsets.insert((obj.path.clone(), sec_idx), (out_name, offset_in_merged));
        }
    }

    // step 2: allocate SHN_COMMON symbols into .bss
    // COMMON: st_shndx == 0xfff2, st_value = required alignment, st_size = byte size
    // multiple definitions of the same COMMON symbol take the largest size (C tentative rule)
    let mut common_syms: HashMap<String, (u64, u64)> = HashMap::new(); // name -> (size, align)
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.section_index != 0xfff2 { continue; }
            if sym.name.is_empty() { continue; }
            let entry = common_syms.entry(sym.name.clone()).or_insert((0, 1));
            entry.0 = entry.0.max(sym.size);
            entry.1 = entry.1.max(sym.value); // st_value is alignment for COMMON
        }
    }
    // append each COMMON symbol to .bss and record its offset
    let mut common_offsets: HashMap<String, u64> = HashMap::new();
    {
        let bss = merged.get_mut(".bss").unwrap();
        for (name, (size, align)) in &common_syms {
            let cur = bss.data.len() as u64;
            let aligned = align_up(cur, *align);
            bss.data.resize(aligned as usize, 0);
            bss.align = bss.align.max(*align);
            common_offsets.insert(name.clone(), bss.data.len() as u64);
            bss.data.resize(bss.data.len() + *size as usize, 0);
        }
    }

    // step 3: resolve symbol table - collect all globals, detect duplicates
    let mut global_syms: HashMap<String, ResolvedSymbol> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    // first pass: collect defined globals (strong beats weak, COMMON loses to strong)
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local { continue; }
            if sym.name.is_empty() { continue; }
            // COMMON symbols are handled separately below
            if sym.section_index == 0xfff2 { continue; }
            if !sym.defined { continue; }

            if let Some(existing) = global_syms.get(&sym.name) {
                if sym.binding != SymbolBinding::Weak {
                    let _ = existing;
                    errors.push(format!("duplicate symbol: {}", sym.name));
                }
                continue;
            }

            global_syms.insert(sym.name.clone(), ResolvedSymbol { name: sym.name.clone(), vaddr: 0 });
        }
    }
    // insert COMMON symbols (only if not already defined by a strong symbol)
    for (name, _) in &common_syms {
        global_syms.entry(name.clone()).or_insert(ResolvedSymbol { name: name.clone(), vaddr: 0 });
    }

    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }

    // step 4: determine which symbols need GOT entries
    // any symbol referenced by GOTPCREL* needs a GOT slot
    let mut got_symbols: Vec<String> = Vec::new();
    for obj in &objects {
        for sec in &obj.sections {
            for rel in &sec.relocations {
                match rel.reloc_type {
                    R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX | R_X86_64_GOT32 => {
                        if !rel.symbol_name.is_empty() && !got_symbols.contains(&rel.symbol_name) {
                            got_symbols.push(rel.symbol_name.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // build .got section: 8 bytes per entry
    let got_ms = merged.get_mut(".got").unwrap();
    let mut got_offsets: HashMap<String, u64> = HashMap::new();

    // first slot is _GLOBAL_OFFSET_TABLE_ itself (conventionally zero in static)
    got_ms.data.extend_from_slice(&0u64.to_le_bytes());
    got_ms.align = 8;

    for sym_name in &got_symbols {
        let off = got_ms.data.len() as u64;
        got_offsets.insert(sym_name.clone(), off);
        // placeholder - filled in after layout
        got_ms.data.extend_from_slice(&0u64.to_le_bytes());
    }

    // step 4: layout - assign page-aligned vaddrs to each output section
    // first page (0x400000-0x401000) is header-only, sections start at 0x401000
    let mut current_vaddr = BASE + PAGE;
    let mut ordered: Vec<MergedSection> = Vec::new();

    for def in &defs {
        let ms = merged.remove(def.name).unwrap();
        if ms.data.is_empty() { continue; }
        current_vaddr = align_up(current_vaddr, PAGE);
        let mut placed = ms;
        placed.vaddr = current_vaddr;
        current_vaddr += placed.data.len() as u64;
        ordered.push(placed);
    }

    // build vaddr lookup maps
    let sec_vaddr_map: HashMap<&str, u64> = ordered.iter().map(|ms| (ms.name.as_str(), ms.vaddr)).collect();
    let got_vaddr = sec_vaddr_map.get(".got").copied().unwrap_or(0);

    // compute TLS segment bounds (tdata + tbss contiguous)
    let tls_vaddr  = sec_vaddr_map.get(".tdata").copied().unwrap_or(0);
    let tls_filesz = ordered.iter().find(|s| s.name == ".tdata").map(|s| s.data.len() as u64).unwrap_or(0);
    let tbss_size  = ordered.iter().find(|s| s.name == ".tbss").map(|s| s.data.len() as u64).unwrap_or(0);
    let tls_memsz  = tls_filesz + tbss_size;
    let tls_align  = ordered.iter()
        .filter(|s| s.name == ".tdata" || s.name == ".tbss")
        .map(|s| s.align).max().unwrap_or(1);

    // step 5: assign vaddrs to all (obj, sec_idx) pairs
    let mut ctx = LinkContext {
        section_vaddrs: HashMap::new(),
        got_offsets: got_offsets.clone(),
        got_vaddr,
        tls_vaddr,
        tls_filesz,
        tls_memsz,
        tls_align,
    };
    for ((path, idx), (out_name, offset)) in &section_offsets {
        if let Some(&base) = sec_vaddr_map.get(*out_name) {
            ctx.section_vaddrs.insert((path.clone(), *idx), base + offset);
        }
    }

    // step 7: resolve final symbol vaddrs using context
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local { continue; }
            if sym.section_index == 0xfff2 { continue; } // COMMON handled below
            if !sym.defined { continue; }
            if sym.name.is_empty() { continue; }
            if let Some(entry) = global_syms.get_mut(&sym.name) {
                entry.vaddr = compute_symbol_vaddr(sym, obj, &ctx);
            }
        }
    }

    // fix up COMMON symbol vaddrs: they live at their offset inside .bss
    let bss_vaddr = sec_vaddr_map.get(".bss").copied().unwrap_or(0);
    for (name, off) in &common_offsets {
        if let Some(entry) = global_syms.get_mut(name) {
            entry.vaddr = bss_vaddr + off;
        }
    }

    // inject synthetic linker-defined symbols
    // _GLOBAL_OFFSET_TABLE_: address of GOT
    global_syms.entry("_GLOBAL_OFFSET_TABLE_".into()).or_insert(ResolvedSymbol {
        name: "_GLOBAL_OFFSET_TABLE_".into(),
        vaddr: got_vaddr,
    });

    // section boundary symbols - used by crt0 to call constructors/destructors
    for sec in &ordered {
        let start_name = format!("__start_{}", sec.name.replace('.', "_").trim_start_matches('_'));
        let stop_name  = format!("__stop_{}", sec.name.replace('.', "_").trim_start_matches('_'));
        // also provide the traditional __init_array_start / __init_array_end form
        let (alt_start, alt_stop) = match sec.name.as_str() {
            ".init_array" => (Some("__init_array_start"), Some("__init_array_end")),
            ".fini_array" => (Some("__fini_array_start"), Some("__fini_array_end")),
            ".bss"        => (Some("__bss_start"), Some("__bss_end")),
            _             => (None, None),
        };

        let start_vaddr = sec.vaddr;
        let stop_vaddr  = sec.vaddr + sec.data.len() as u64;

        global_syms.entry(start_name.clone()).or_insert(ResolvedSymbol { name: start_name, vaddr: start_vaddr });
        global_syms.entry(stop_name.clone()).or_insert(ResolvedSymbol  { name: stop_name,  vaddr: stop_vaddr  });

        if let Some(n) = alt_start {
            global_syms.entry(n.into()).or_insert(ResolvedSymbol { name: n.into(), vaddr: start_vaddr });
        }
        if let Some(n) = alt_stop {
            global_syms.entry(n.into()).or_insert(ResolvedSymbol { name: n.into(), vaddr: stop_vaddr });
        }
    }
    // _end: first address past all loaded sections
    let end_vaddr = ordered.last().map(|s| s.vaddr + s.data.len() as u64).unwrap_or(0);
    global_syms.entry("_end".into()).or_insert(ResolvedSymbol { name: "_end".into(), vaddr: end_vaddr });
    global_syms.entry("end".into()).or_insert(ResolvedSymbol  { name: "end".into(),  vaddr: end_vaddr });

    // check entry point exists
    let entry_vaddr = match global_syms.get(entry) {
        Some(s) => s.vaddr,
        None => return Err(format!("entry point '{}' not found", entry)),
    };

    // check all undefined references are satisfied
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local { continue; }
            if sym.defined { continue; }
            if sym.name.is_empty() { continue; }
            // _GLOBAL_OFFSET_TABLE_ is synthetic, always satisfied
            if sym.name == "_GLOBAL_OFFSET_TABLE_" { continue; }
            if !global_syms.contains_key(&sym.name) {
                errors.push(format!("undefined symbol: {} (in {})", sym.name, obj.path));
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }

    Ok((LinkedOutput { sections: ordered, symbols: global_syms, entry_point: entry_vaddr }, ctx))
}

// applies all RELA relocations and fills in GOT entries
pub fn apply_relocations(
    objects: &[ObjectFile],
    output: &mut LinkedOutput,
    ctx: &LinkContext,
) -> Result<(), String> {
    // fill GOT entries with resolved symbol vaddrs
    if let Some(got_sec) = output.sections.iter_mut().find(|s| s.name == ".got") {
        for (sym_name, &got_off) in &ctx.got_offsets {
            if let Some(sym) = output.symbols.get(sym_name) {
                let off = got_off as usize;
                got_sec.data[off..off + 8].copy_from_slice(&sym.vaddr.to_le_bytes());
            }
        }
    }

    for obj in objects {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            if sec.relocations.is_empty() { continue; }

            let sec_vaddr = match ctx.section_vaddrs.get(&(obj.path.clone(), sec_idx)) {
                Some(&v) => v,
                None => continue,
            };

            let out_sec_name = match output_section_name(&sec.name) {
                Some(n) => n,
                None => continue,
            };
            let out_sec_idx = match output.sections.iter().position(|s| s.name == out_sec_name) {
                Some(i) => i,
                None => continue,
            };
            let data_offset = (sec_vaddr - output.sections[out_sec_idx].vaddr) as usize;

            for rel in &sec.relocations {
                let sym_vaddr = resolve_reloc_sym(obj, rel, ctx, &output.symbols)?;
                let patch_pos = data_offset + rel.offset as usize;
                let place_vaddr = sec_vaddr + rel.offset;

                match rel.reloc_type {
                    R_X86_64_64 => {
                        let val = sym_vaddr.wrapping_add_signed(rel.addend) as u64;
                        write_u64(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_32 => {
                        let val = sym_vaddr.wrapping_add_signed(rel.addend) as u32;
                        write_u32(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_32S => {
                        let val = sym_vaddr.wrapping_add_signed(rel.addend) as i32;
                        write_i32(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_PC32 | R_X86_64_PLT32 => {
                        let val = sym_vaddr.wrapping_add_signed(rel.addend)
                            .wrapping_sub(place_vaddr) as i32;
                        write_i32(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_GOTPCREL => {
                        let got_entry_vaddr = got_entry_vaddr(rel, ctx)?;
                        let val = (got_entry_vaddr.wrapping_add_signed(rel.addend))
                            .wrapping_sub(place_vaddr) as i32;
                        write_i32(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => {
                        relax_gotpcrelx(
                            &mut output.sections[out_sec_idx].data,
                            patch_pos,
                            sym_vaddr,
                            place_vaddr,
                            got_entry_vaddr(rel, ctx).ok(),
                            rel.addend,
                        )?;
                    }
                    // TLS relocations for static executables (local-exec model)
                    // TPOFF32: signed 32-bit offset from the thread pointer to the TLS variable
                    // in local-exec model: tpoff = sym_vaddr - (tls_segment_end aligned to tls_align)
                    R_X86_64_TPOFF32 => {
                        let tpoff = tls_tpoff(sym_vaddr, ctx) as i32;
                        let val = tpoff.wrapping_add(rel.addend as i32);
                        write_i32(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_TPOFF64 => {
                        let tpoff = tls_tpoff(sym_vaddr, ctx) as i64;
                        let val = tpoff.wrapping_add(rel.addend as i64);
                        write_i64(&mut output.sections[out_sec_idx].data, patch_pos, val as u64);
                    }
                    // GOTTPOFF: pc-relative reference to a GOT slot holding TPOFF64
                    // in static executable we can relax this to direct TPOFF if possible
                    R_X86_64_GOTTPOFF => {
                        // write tpoff directly as a 32-bit pc-relative value
                        let tpoff = tls_tpoff(sym_vaddr, ctx) as i64;
                        let val = (tpoff.wrapping_add(rel.addend as i64))
                            .wrapping_sub(place_vaddr as i64) as i32;
                        write_i32(&mut output.sections[out_sec_idx].data, patch_pos, val);
                    }
                    R_X86_64_NONE => {}
                    t => {
                        return Err(format!(
                            "unsupported relocation type {} for '{}' in {}",
                            t, rel.symbol_name, obj.path
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

// returns the vaddr of a symbol's GOT entry, or error if it has none
fn got_entry_vaddr(rel: &slnk_common::Relocation, ctx: &LinkContext) -> Result<u64, String> {
    match ctx.got_offsets.get(&rel.symbol_name) {
        Some(&off) => Ok(ctx.got_vaddr + off),
        None => Err(format!("no GOT entry for '{}'", rel.symbol_name)),
    }
}

// handles GOTPCRELX and REX_GOTPCRELX relocations
// for PIC code that has a GOT entry: keep the instruction as GOT-indirect (correct semantics)
// for non-PIC code without a GOT entry: relax MOV->LEA to avoid indirection overhead
pub fn relax_gotpcrelx_pub(
    data: &mut [u8],
    patch_pos: usize,
    sym_vaddr: u64,
    place_vaddr: u64,
    got_entry: Option<u64>,
    addend: i64,
) -> Result<(), String> {
    relax_gotpcrelx(data, patch_pos, sym_vaddr, place_vaddr, got_entry, addend)
}

fn relax_gotpcrelx(
    data: &mut [u8],
    patch_pos: usize,
    sym_vaddr: u64,
    place_vaddr: u64,
    got_entry: Option<u64>,
    addend: i64,
) -> Result<(), String> {
    if patch_pos < 2 {
        return Err("GOTPCRELX: patch_pos too small".into());
    }

    // if a GOT entry was allocated for this symbol, always go through it
    // the GOT was already filled with the symbol's vaddr, so the code's double-indirection works
    if let Some(got) = got_entry {
        let val = got.wrapping_add_signed(addend).wrapping_sub(place_vaddr) as i32;
        write_i32(data, patch_pos, val);
        return Ok(());
    }

    // no GOT entry - try to relax the instruction in-place
    let b1 = data[patch_pos - 2];
    let b2 = data[patch_pos - 1];
    let is_rex = b1 & 0xf0 == 0x40;

    if is_rex && b2 == 0x8b {
        // REX.W + MOV r64,[rip+...] -> REX.W + LEA r64,[rip+sym]
        data[patch_pos - 1] = 0x8d;
    }
    // for any other pattern just write the direct pc-relative value
    let val = sym_vaddr.wrapping_add_signed(addend).wrapping_sub(place_vaddr) as i32;
    write_i32(data, patch_pos, val);
    Ok(())
}

// resolves the final vaddr for a relocation's referenced symbol
fn resolve_reloc_sym(
    obj: &ObjectFile,
    rel: &slnk_common::Relocation,
    ctx: &LinkContext,
    globals: &HashMap<String, ResolvedSymbol>,
) -> Result<u64, String> {
    let sym = obj.symbols.get(rel.sym_index);

    if let Some(s) = sym {
        // section symbol - resolves to base of the section
        if s.sym_type == SymbolType::Section {
            let sec_idx = s.section_index;
            return match ctx.section_vaddrs.get(&(obj.path.clone(), sec_idx)) {
                Some(&v) => Ok(v),
                None => Err(format!("section symbol {} references unmapped section {}", rel.sym_index, sec_idx)),
            };
        }

        // local named symbol
        if !s.name.is_empty() {
            if let Some(r) = globals.get(&s.name) { return Ok(r.vaddr); }
            // local not in global table - compute from its section base
            if s.section_index != 0 && s.section_index != 0xfff1 {
                if let Some(&base) = ctx.section_vaddrs.get(&(obj.path.clone(), s.section_index)) {
                    return Ok(base + s.value);
                }
            }
        }
    }

    // global symbol lookup by name
    if !rel.symbol_name.is_empty() {
        if let Some(r) = globals.get(&rel.symbol_name) { return Ok(r.vaddr); }
        return Err(format!("undefined symbol '{}' in {}", rel.symbol_name, obj.path));
    }

    Err(format!("cannot resolve relocation sym_index={} name='{}' in {}", rel.sym_index, rel.symbol_name, obj.path))
}

fn compute_symbol_vaddr(sym: &Symbol, obj: &ObjectFile, ctx: &LinkContext) -> u64 {
    let sec_idx = sym.section_index;
    if sec_idx == 0 || sec_idx == 0xfff1 { return sym.value; }
    match ctx.section_vaddrs.get(&(obj.path.clone(), sec_idx)) {
        Some(&base) => base + sym.value,
        None => sym.value,
    }
}

fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_i32(buf: &mut [u8], off: usize, val: i32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn write_i64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

// computes the thread-pointer-relative offset for a TLS variable (local-exec model)
// in x86-64 static executables, FS:0 points to the end of the TLS block (tp)
// tls variables are at negative offsets: tpoff = sym_vaddr - tp_base
// tp_base = align_up(tls_vaddr + tls_memsz, tls_align)
fn tls_tpoff(sym_vaddr: u64, ctx: &LinkContext) -> i64 {
    if ctx.tls_memsz == 0 { return 0; }
    let tp_base = align_up(ctx.tls_vaddr + ctx.tls_memsz, ctx.tls_align.max(1));
    sym_vaddr as i64 - tp_base as i64
}
