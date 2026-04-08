// ELF shared library linker - produces ET_DYN (.so)
// handles: position-independent code, dynsym/dynstr/gnu.hash, PT_DYNAMIC, R_X86_64_RELATIVE

use std::collections::HashMap;
use slnk_common::{
    align_up, LinkedOutput, MergedSection, ObjectFile, ResolvedSymbol, SectionFlags,
    Symbol, SymbolBinding, SymbolType,
};
use crate::types::*;

// SO sections start at RVA 0 (position-independent)
const SO_BASE: u64 = 0;
const PAGE: u64 = 0x1000;

fn output_section_name(input: &str) -> Option<&'static str> {
    if input.starts_with(".text")   { return Some(".text"); }
    if input.starts_with(".rodata") { return Some(".rodata"); }
    if input.starts_with(".data.rel.ro") { return Some(".data.rel.ro"); }
    if input.starts_with(".tdata")  { return Some(".tdata"); }
    if input.starts_with(".tbss")   { return Some(".tbss"); }
    if input.starts_with(".data")   { return Some(".data"); }
    if input.starts_with(".bss")    { return Some(".bss"); }
    if input.starts_with(".init_array") { return Some(".init_array"); }
    if input.starts_with(".fini_array") { return Some(".fini_array"); }
    None
}

struct OutSecDef { name: &'static str, flags: SectionFlags }
fn out_sec_defs() -> Vec<OutSecDef> {
    vec![
        OutSecDef { name: ".text",       flags: SectionFlags { alloc: true, exec: true,  write: false } },
        OutSecDef { name: ".rodata",     flags: SectionFlags { alloc: true, exec: false, write: false } },
        OutSecDef { name: ".data.rel.ro",flags: SectionFlags { alloc: true, exec: false, write: false } },
        OutSecDef { name: ".tdata",      flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".tbss",       flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".init_array", flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".fini_array", flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".data",       flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".got",        flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".bss",        flags: SectionFlags { alloc: true, exec: false, write: true  } },
        // synthetic sections added later: .dynsym .dynstr .gnu.hash .rela.dyn .dynamic
    ]
}

pub struct SoLinkContext {
    pub section_vaddrs: HashMap<(String, usize), u64>,
    pub got_offsets:    HashMap<String, u64>,
    pub got_vaddr:      u64,
    // all R_X86_64_RELATIVE fixup locations (absolute refs inside the SO)
    pub relative_relocs: Vec<u64>,
    // exported symbols name -> vaddr
    pub exports: Vec<(String, u64, u64)>, // name, vaddr, size
    // soname for .dynamic DT_SONAME
    pub soname: String,
}

pub fn link(
    objects: Vec<ObjectFile>,
    soname: &str,
) -> Result<(LinkedOutput, SoLinkContext), String> {
    let defs = out_sec_defs();
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

    let mut section_offsets: HashMap<(String, usize), (&'static str, u64)> = HashMap::new();

    // step 1: COMMON symbols into .bss
    let mut common_offsets: HashMap<String, u64> = HashMap::new();
    {
        let bss = merged.get_mut(".bss").unwrap();
        let mut seen: HashMap<String, (u64, u64)> = HashMap::new();
        for obj in &objects {
            for sym in &obj.symbols {
                if sym.section_index != 0xfff2 { continue; }
                if sym.name.is_empty() { continue; }
                let e = seen.entry(sym.name.clone()).or_insert((0, 1));
                e.0 = e.0.max(sym.size);
                e.1 = e.1.max(sym.value.max(1));
            }
        }
        for (name, (size, align)) in &seen {
            let cur = bss.data.len() as u64;
            bss.data.resize(align_up(cur, *align) as usize, 0);
            bss.align = bss.align.max(*align);
            common_offsets.insert(name.clone(), bss.data.len() as u64);
            bss.data.resize(bss.data.len() + *size as usize, 0);
        }
    }

    // step 2: merge input sections
    for obj in &objects {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            let out_name = match output_section_name(&sec.name) {
                Some(n) => n,
                None => continue,
            };
            let ms = merged.get_mut(out_name).unwrap();
            let align = sec.align.max(1);
            let cur = ms.data.len() as u64;
            ms.data.resize(align_up(cur, align) as usize, 0);
            ms.align = ms.align.max(align);
            let offset = ms.data.len() as u64;
            ms.data.extend_from_slice(&sec.data);
            section_offsets.insert((obj.path.clone(), sec_idx), (out_name, offset));
        }
    }

    // step 3: GOT - same as executable linker
    let mut got_syms: Vec<String> = Vec::new();
    for obj in &objects {
        for sec in &obj.sections {
            for rel in &sec.relocations {
                match rel.reloc_type {
                    R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX | R_X86_64_GOT32 => {
                        if !rel.symbol_name.is_empty() && !got_syms.contains(&rel.symbol_name) {
                            got_syms.push(rel.symbol_name.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let got_ms = merged.get_mut(".got").unwrap();
    let mut got_offsets: HashMap<String, u64> = HashMap::new();
    got_ms.data.extend_from_slice(&0u64.to_le_bytes()); // slot 0
    got_ms.align = 8;
    for name in &got_syms {
        let off = got_ms.data.len() as u64;
        got_offsets.insert(name.clone(), off);
        got_ms.data.extend_from_slice(&0u64.to_le_bytes());
    }

    // step 4: layout - all sections at RVA 0 base (position-independent)
    // page 0: ELF header + phdrs (virtual, not mapped as separate segment but in first LOAD)
    // page 1: synthetic sections (.gnu.hash, .dynsym, .dynstr, .rela.dyn) - built by emitter
    // page 2+: regular merged sections
    let mut current_vaddr = 2 * PAGE;
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

    let sec_vaddr_map: HashMap<&str, u64> = ordered.iter()
        .map(|ms| (ms.name.as_str(), ms.vaddr)).collect();
    let got_vaddr = sec_vaddr_map.get(".got").copied().unwrap_or(0);

    let mut ctx = SoLinkContext {
        section_vaddrs: HashMap::new(),
        got_offsets: got_offsets.clone(),
        got_vaddr,
        relative_relocs: Vec::new(),
        exports: Vec::new(),
        soname: soname.to_string(),
    };
    for ((path, idx), (out_name, offset)) in &section_offsets {
        if let Some(&base) = sec_vaddr_map.get(*out_name) {
            ctx.section_vaddrs.insert((path.clone(), *idx), base + offset);
        }
    }

    // step 5: symbol resolution
    let mut global_syms: HashMap<String, ResolvedSymbol> = HashMap::new();
    let mut weak_syms:   HashMap<String, ResolvedSymbol> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local { continue; }
            if sym.section_index == 0xfff2 { continue; }
            if !sym.defined || sym.name.is_empty() { continue; }
            let vaddr = compute_sym_vaddr(sym, obj, &ctx);
            if sym.binding == SymbolBinding::Weak {
                weak_syms.entry(sym.name.clone())
                    .or_insert(ResolvedSymbol { name: sym.name.clone(), vaddr });
            } else {
                if global_syms.contains_key(&sym.name) {
                    errors.push(format!("duplicate symbol: {}", sym.name));
                    continue;
                }
                global_syms.insert(sym.name.clone(), ResolvedSymbol { name: sym.name.clone(), vaddr });
            }
        }
    }
    for (name, sym) in weak_syms { global_syms.entry(name).or_insert(sym); }

    // COMMON
    let bss_vaddr = sec_vaddr_map.get(".bss").copied().unwrap_or(0);
    for (name, off) in &common_offsets {
        global_syms.entry(name.clone()).or_insert(ResolvedSymbol { name: name.clone(), vaddr: bss_vaddr + off });
    }

    // synthetic
    global_syms.entry("_GLOBAL_OFFSET_TABLE_".into()).or_insert(ResolvedSymbol {
        name: "_GLOBAL_OFFSET_TABLE_".into(), vaddr: got_vaddr,
    });

    // collect exports (all global defined symbols)
    let mut exports: Vec<(String, u64, u64)> = Vec::new();
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local { continue; }
            if sym.section_index == 0xfff2 { continue; }
            if !sym.defined || sym.name.is_empty() { continue; }
            if sym.sym_type == SymbolType::File || sym.sym_type == SymbolType::Section { continue; }
            if let Some(r) = global_syms.get(&sym.name) {
                exports.push((sym.name.clone(), r.vaddr, sym.size));
            }
        }
    }
    exports.sort_by(|a, b| a.0.cmp(&b.0));
    exports.dedup_by(|a, b| a.0 == b.0);
    ctx.exports = exports;

    // check undefs (in SO, undefined symbols are allowed - resolved at load time)
    // but warn about them
    if !errors.is_empty() { return Err(errors.join("\n")); }

    Ok((LinkedOutput { sections: ordered, symbols: global_syms, entry_point: 0 }, ctx))
}

pub fn apply_relocations(
    objects: &[ObjectFile],
    output: &mut LinkedOutput,
    ctx: &mut SoLinkContext,
) -> Result<(), String> {
    // fill GOT
    if let Some(got_sec) = output.sections.iter_mut().find(|s| s.name == ".got") {
        for (sym_name, &got_off) in &ctx.got_offsets {
            if let Some(sym) = output.symbols.get(sym_name) {
                let off = got_off as usize;
                got_sec.data[off..off+8].copy_from_slice(&sym.vaddr.to_le_bytes());
            }
        }
    }

    let mut relative_relocs: Vec<u64> = Vec::new();

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
            let out_idx = match output.sections.iter().position(|s| s.name == out_sec_name) {
                Some(i) => i,
                None => continue,
            };
            let data_off = (sec_vaddr - output.sections[out_idx].vaddr) as usize;

            for rel in &sec.relocations {
                let sym_vaddr = resolve_reloc_sym(obj, rel, ctx, &output.symbols)?;
                let patch = data_off + rel.offset as usize;
                let place_vaddr = sec_vaddr + rel.offset;

                match rel.reloc_type {
                    R_X86_64_64 => {
                        let val = sym_vaddr.wrapping_add_signed(rel.addend);
                        write_u64(&mut output.sections[out_idx].data, patch, val);
                        // needs R_X86_64_RELATIVE at load time
                        relative_relocs.push(place_vaddr);
                    }
                    R_X86_64_32 => {
                        write_u32(&mut output.sections[out_idx].data, patch,
                            sym_vaddr.wrapping_add_signed(rel.addend) as u32);
                    }
                    R_X86_64_32S => {
                        write_i32(&mut output.sections[out_idx].data, patch,
                            sym_vaddr.wrapping_add_signed(rel.addend) as i32);
                    }
                    R_X86_64_PC32 | R_X86_64_PLT32 => {
                        let val = sym_vaddr.wrapping_add_signed(rel.addend)
                            .wrapping_sub(place_vaddr) as i32;
                        write_i32(&mut output.sections[out_idx].data, patch, val);
                    }
                    R_X86_64_GOTPCREL => {
                        if let Some(&off) = ctx.got_offsets.get(&rel.symbol_name) {
                            let got_entry = ctx.got_vaddr + off;
                            let val = got_entry.wrapping_add_signed(rel.addend)
                                .wrapping_sub(place_vaddr) as i32;
                            write_i32(&mut output.sections[out_idx].data, patch, val);
                        }
                    }
                    R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => {
                        let got_entry = ctx.got_offsets.get(&rel.symbol_name)
                            .map(|&off| ctx.got_vaddr + off);
                        crate::linker::relax_gotpcrelx_pub(
                            &mut output.sections[out_idx].data,
                            patch, sym_vaddr, place_vaddr, got_entry, rel.addend,
                        )?;
                    }
                    R_X86_64_TPOFF32 => {
                        // TLS - simplified
                        write_i32(&mut output.sections[out_idx].data, patch, 0);
                    }
                    R_X86_64_NONE => {}
                    t => {
                        return Err(format!("unsupported SO reloc {} for '{}' in {}",
                            t, rel.symbol_name, obj.path));
                    }
                }
            }
        }
    }

    ctx.relative_relocs = relative_relocs;
    Ok(())
}

fn resolve_reloc_sym(
    obj: &ObjectFile,
    rel: &slnk_common::Relocation,
    ctx: &SoLinkContext,
    globals: &HashMap<String, ResolvedSymbol>,
) -> Result<u64, String> {
    let sym = obj.symbols.get(rel.sym_index);
    if let Some(s) = sym {
        if s.sym_type == SymbolType::Section {
            if let Some(&v) = ctx.section_vaddrs.get(&(obj.path.clone(), s.section_index)) {
                return Ok(v);
            }
        }
        if !s.name.is_empty() {
            if let Some(r) = globals.get(&s.name) { return Ok(r.vaddr); }
            if s.section_index != 0 && s.section_index != 0xfff1 {
                if let Some(&base) = ctx.section_vaddrs.get(&(obj.path.clone(), s.section_index)) {
                    return Ok(base + s.value);
                }
            }
        }
    }
    if !rel.symbol_name.is_empty() {
        if let Some(r) = globals.get(&rel.symbol_name) { return Ok(r.vaddr); }
        // in SO, undefined symbols resolve to 0 (filled by dynamic linker)
        return Ok(0);
    }
    Ok(0)
}

fn compute_sym_vaddr(sym: &Symbol, obj: &ObjectFile, ctx: &SoLinkContext) -> u64 {
    if sym.section_index == 0xfff1 { return sym.value; }
    if let Some(&base) = ctx.section_vaddrs.get(&(obj.path.clone(), sym.section_index)) {
        return base + sym.value;
    }
    sym.value
}

fn write_u32(data: &mut [u8], off: usize, val: u32) { data[off..off+4].copy_from_slice(&val.to_le_bytes()); }
fn write_i32(data: &mut [u8], off: usize, val: i32) { data[off..off+4].copy_from_slice(&val.to_le_bytes()); }
fn write_u64(data: &mut [u8], off: usize, val: u64) { data[off..off+8].copy_from_slice(&val.to_le_bytes()); }
