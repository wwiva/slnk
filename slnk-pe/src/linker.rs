// PE linker: section merging, symbol resolution, import table, relocations

use std::collections::HashMap;
use slnk_common::{
    align_up, LinkedOutput, MergedSection, ObjectFile, ResolvedSymbol, SectionFlags,
    Symbol, SymbolBinding, SymbolType,
};
use crate::types::*;

const BASE: u64   = DEFAULT_IMAGE_BASE;
const SALIGN: u64 = SECTION_ALIGN as u64;

// maps COFF input section name to canonical output section name
fn output_section_name(input: &str) -> Option<&'static str> {
    // strip COMDAT suffix (.text$foo -> .text)
    let base = input.split('$').next().unwrap_or(input);
    match base {
        ".text"   => Some(".text"),
        ".data"   => Some(".data"),
        ".rdata"  => Some(".rdata"),
        ".bss"    => Some(".bss"),
        ".pdata"  => Some(".pdata"),
        ".xdata"  => Some(".xdata"),
        _ => None,
    }
    // .idata$* handled separately for import table construction
}

struct OutSecDef { name: &'static str, flags: SectionFlags }

fn out_sec_defs() -> Vec<OutSecDef> {
    vec![
        OutSecDef { name: ".text",  flags: SectionFlags { alloc: true, exec: true,  write: false } },
        OutSecDef { name: ".rdata", flags: SectionFlags { alloc: true, exec: false, write: false } },
        OutSecDef { name: ".pdata", flags: SectionFlags { alloc: true, exec: false, write: false } },
        OutSecDef { name: ".xdata", flags: SectionFlags { alloc: true, exec: false, write: false } },
        OutSecDef { name: ".data",  flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".idata", flags: SectionFlags { alloc: true, exec: false, write: true  } },
        OutSecDef { name: ".reloc", flags: SectionFlags { alloc: true, exec: false, write: false } },
        OutSecDef { name: ".bss",   flags: SectionFlags { alloc: true, exec: false, write: true  } },
    ]
}

pub struct LinkContext {
    pub section_vaddrs: HashMap<(String, usize), u64>,
    pub imports: Vec<ImportDll>,
    pub image_base: u64,
    // all absolute 64-bit fixup locations for .reloc section
    pub base_relocs: Vec<u64>,
}

pub struct ImportDll {
    pub dll_name: String,
    pub funcs: Vec<ImportFunc>,
}

pub struct ImportFunc {
    pub name: String,
    pub hint: u16,
    pub iat_rva: u32, // RVA of this IAT slot within the image
}

pub fn link(objects: Vec<ObjectFile>, entry: &str) -> Result<(LinkedOutput, LinkContext), String> {
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

    // --- step 1: extract import info from .idata$* sections ---
    // .idata$7 = DLL name, .idata$6 = hint+funcname, .idata$5 = IAT slot ptr
    // each import lib member contributes one function; group by DLL
    let mut dll_funcs: HashMap<String, Vec<(u16, String)>> = HashMap::new(); // dll -> [(hint, name)]

    for obj in &objects {
        // find DLL name from .idata$7
        let dll_name = obj.sections.iter()
            .find(|s| s.name == ".idata$7")
            .and_then(|s| {
                let end = s.data.iter().position(|&b| b == 0).unwrap_or(s.data.len());
                if end > 0 { Some(String::from_utf8_lossy(&s.data[..end]).to_string()) }
                else { None }
            });

        if let Some(dll) = dll_name {
            // find function name+hint from .idata$6
            if let Some(hnsec) = obj.sections.iter().find(|s| s.name == ".idata$6") {
                if hnsec.data.len() >= 3 {
                    let hint = u16::from_le_bytes([hnsec.data[0], hnsec.data[1]]);
                    let end = hnsec.data[2..].iter().position(|&b| b == 0)
                        .unwrap_or(hnsec.data.len() - 2);
                    let name = String::from_utf8_lossy(&hnsec.data[2..2+end]).to_string();
                    if !name.is_empty() {
                        dll_funcs.entry(dll).or_default().push((hint, name));
                    }
                }
            }
        }
    }

    // also collect __imp_XXX undefined references not covered by .idata sections
    // these come from inline __declspec(dllimport) with no import lib
    let mut covered: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, funcs) in &dll_funcs {
        for (_, name) in funcs { covered.insert(format!("__imp_{}", name)); }
    }
    let mut extra_imports: Vec<String> = Vec::new();
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.defined || sym.name.is_empty() { continue; }
            if sym.name.starts_with("__imp_") && !covered.contains(&sym.name) {
                extra_imports.push(sym.name.trim_start_matches("__imp_").to_string());
            }
        }
    }
    if !extra_imports.is_empty() {
        let entry = dll_funcs.entry("kernel32.dll".to_string()).or_default();
        for name in extra_imports { entry.push((0, name)); }
    }

    // deduplicate functions per DLL
    for funcs in dll_funcs.values_mut() {
        funcs.dedup_by(|a, b| a.1 == b.1);
    }

    // --- step 2: COMMON symbols -> allocate in .bss ---
    let mut common_offsets: HashMap<String, u64> = HashMap::new();
    {
        let bss = merged.get_mut(".bss").unwrap();
        let mut seen: HashMap<String, (u64, u64)> = HashMap::new(); // name -> (size, align)
        for obj in &objects {
            for sym in &obj.symbols {
                if sym.section_index != 0xfff2 { continue; } // SHN_COMMON equivalent in COFF is COMMON
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

    // --- step 3: merge input sections ---
    // track COMDAT: only include first definition of each COMDAT group
    let mut comdat_seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for obj in &objects {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            if sec.name.starts_with(".idata") { continue; } // handled separately

            let out_name = match output_section_name(&sec.name) {
                Some(n) => n,
                None => continue,
            };

            // COMDAT dedup: if section name has $ (e.g. .text$_ZN3foo...) deduplicate
            if sec.name.contains('$') {
                let key = format!("{}:{}", obj.path, sec.name);
                // use symbol name for proper dedup if available
                let sym_key = obj.symbols.iter()
                    .find(|s| s.section_index == sec_idx && !s.name.is_empty())
                    .map(|s| s.name.clone())
                    .unwrap_or(key);
                if !comdat_seen.insert(sym_key) { continue; }
            }

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

    // --- step 4: build .idata with correct DLL names ---
    let (idata_bytes, imports_tmp) = build_idata(&dll_funcs, 0);
    merged.get_mut(".idata").unwrap().data = idata_bytes;
    merged.get_mut(".idata").unwrap().align = 8;

    // --- step 5: layout ---
    let mut current_rva: u32 = SECTION_ALIGN;
    let mut ordered: Vec<MergedSection> = Vec::new();

    for def in &defs {
        let ms = merged.remove(def.name).unwrap();
        if ms.data.is_empty() { continue; }
        let rva = current_rva as u64;
        let mut placed = ms;
        placed.vaddr = BASE + rva;
        current_rva = (rva + align_up(placed.data.len() as u64, SALIGN)) as u32;
        ordered.push(placed);
    }

    // rebuild .idata with correct RVAs now that we know layout
    let idata_rva = ordered.iter().find(|s| s.name == ".idata")
        .map(|s| (s.vaddr - BASE) as u32).unwrap_or(0);
    let (idata_bytes2, imports) = build_idata(&dll_funcs, idata_rva);
    if let Some(ms) = ordered.iter_mut().find(|s| s.name == ".idata") {
        ms.data = idata_bytes2;
    }

    // --- step 6: symbol resolution ---
    let sec_vaddr_map: HashMap<&str, u64> = ordered.iter()
        .map(|ms| (ms.name.as_str(), ms.vaddr)).collect();

    let mut ctx = LinkContext {
        section_vaddrs: HashMap::new(),
        imports,
        image_base: BASE,
        base_relocs: Vec::new(),
    };
    for ((path, idx), (out_name, offset)) in &section_offsets {
        if let Some(&base) = sec_vaddr_map.get(*out_name) {
            ctx.section_vaddrs.insert((path.clone(), *idx), base + offset);
        }
    }

    let mut global_syms: HashMap<String, ResolvedSymbol> = HashMap::new();
    let mut weak_syms:   HashMap<String, ResolvedSymbol> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    // collect strong definitions
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local || sym.name.is_empty() { continue; }
            if !sym.defined { continue; }
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
    // weak fills in gaps
    for (name, sym) in weak_syms {
        global_syms.entry(name).or_insert(sym);
    }

    if !errors.is_empty() { return Err(errors.join("\n")); }

    // inject __imp_XXX -> IAT slot addresses
    if let Some(idata_sec) = ordered.iter().find(|s| s.name == ".idata") {
        for dll in &ctx.imports {
            for func in &dll.funcs {
                let iat_va = BASE + func.iat_rva as u64;
                let imp_name = format!("__imp_{}", func.name);
                global_syms.entry(imp_name.clone())
                    .or_insert(ResolvedSymbol { name: imp_name, vaddr: iat_va });
            }
        }
        let _ = idata_sec;
    }

    // inject COMMON symbol vaddrs
    let bss_vaddr = sec_vaddr_map.get(".bss").copied().unwrap_or(0);
    for (name, off) in &common_offsets {
        global_syms.entry(name.clone()).or_insert(ResolvedSymbol {
            name: name.clone(), vaddr: bss_vaddr + off,
        });
    }

    // inject boundary symbols
    for sec in &ordered {
        let start_rva = sec.vaddr - BASE;
        let stop_rva  = start_rva + sec.data.len() as u64;
        // __start_SECNAME / __stop_SECNAME
        let sname = sec.name.trim_start_matches('.');
        let start_sym = format!("__start_{}", sname);
        let stop_sym  = format!("__stop_{}", sname);
        global_syms.entry(start_sym.clone()).or_insert(ResolvedSymbol { name: start_sym, vaddr: sec.vaddr });
        global_syms.entry(stop_sym.clone()).or_insert(ResolvedSymbol { name: stop_sym, vaddr: BASE + stop_rva });
    }

    let entry_vaddr = match global_syms.get(entry) {
        Some(s) => s.vaddr,
        None => return Err(format!("entry point '{}' not found", entry)),
    };

    // check undefined (skip __imp_ - covered by IAT)
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.binding == SymbolBinding::Local || sym.defined || sym.name.is_empty() { continue; }
            if sym.name.starts_with("__imp_") { continue; }
            if sym.name.starts_with("_head_") || sym.name.starts_with("_fmode")
                || sym.name == "__CTOR_LIST__" || sym.name == "__DTOR_LIST__" { continue; }
            if !global_syms.contains_key(&sym.name) {
                errors.push(format!("undefined symbol: {} (in {})", sym.name, obj.path));
            }
        }
    }
    if !errors.is_empty() { return Err(errors.join("\n")); }

    Ok((LinkedOutput { sections: ordered, symbols: global_syms, entry_point: entry_vaddr }, ctx))
}

// apply COFF relocations and collect base reloc fixups
pub fn apply_relocations(
    objects: &[ObjectFile],
    output: &mut LinkedOutput,
    ctx: &mut LinkContext,
) -> Result<(), String> {
    let mut base_relocs: Vec<u64> = Vec::new();

    for obj in objects {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            if sec.relocations.is_empty() { continue; }
            if sec.name.starts_with(".idata") { continue; }

            let sec_vaddr = match ctx.section_vaddrs.get(&(obj.path.clone(), sec_idx)) {
                Some(&v) => v,
                None => continue,
            };
            let out_name = match output_section_name(&sec.name) {
                Some(n) => n,
                None => continue,
            };
            let out_idx = match output.sections.iter().position(|s| s.name == out_name) {
                Some(i) => i,
                None => continue,
            };
            let data_off = (sec_vaddr - output.sections[out_idx].vaddr) as usize;

            for rel in &sec.relocations {
                let sym_vaddr = resolve_sym(obj, rel, ctx, &output.symbols)?;
                let patch = data_off + rel.offset as usize;
                let place_vaddr = sec_vaddr + rel.offset;

                match rel.reloc_type as u16 {
                    IMAGE_REL_AMD64_ADDR64 => {
                        let addend = read_inline_i64(&output.sections[out_idx].data, patch);
                        let va = sym_vaddr.wrapping_add_signed(addend as i64);
                        write_u64(&mut output.sections[out_idx].data, patch, va);
                        base_relocs.push(place_vaddr); // needs fixup if rebased
                    }
                    IMAGE_REL_AMD64_ADDR32 => {
                        let addend = read_inline_i32(&output.sections[out_idx].data, patch) as i64;
                        write_u32(&mut output.sections[out_idx].data, patch,
                            sym_vaddr.wrapping_add_signed(addend) as u32);
                        base_relocs.push(place_vaddr);
                    }
                    IMAGE_REL_AMD64_ADDR32NB => {
                        // RVA = VA - ImageBase
                        let addend = read_inline_i32(&output.sections[out_idx].data, patch) as i64;
                        let rva = sym_vaddr.wrapping_add_signed(addend)
                            .wrapping_sub(ctx.image_base) as u32;
                        write_u32(&mut output.sections[out_idx].data, patch, rva);
                    }
                    IMAGE_REL_AMD64_REL32   => apply_rel32(&mut output.sections[out_idx].data, patch, sym_vaddr, place_vaddr, 0),
                    IMAGE_REL_AMD64_REL32_1 => apply_rel32(&mut output.sections[out_idx].data, patch, sym_vaddr, place_vaddr, 1),
                    IMAGE_REL_AMD64_REL32_2 => apply_rel32(&mut output.sections[out_idx].data, patch, sym_vaddr, place_vaddr, 2),
                    IMAGE_REL_AMD64_REL32_3 => apply_rel32(&mut output.sections[out_idx].data, patch, sym_vaddr, place_vaddr, 3),
                    IMAGE_REL_AMD64_REL32_4 => apply_rel32(&mut output.sections[out_idx].data, patch, sym_vaddr, place_vaddr, 4),
                    IMAGE_REL_AMD64_REL32_5 => apply_rel32(&mut output.sections[out_idx].data, patch, sym_vaddr, place_vaddr, 5),
                    IMAGE_REL_AMD64_SECTION => {
                        let sec_num = find_section_num(output, sym_vaddr) as u16;
                        write_u16(&mut output.sections[out_idx].data, patch, sec_num);
                    }
                    IMAGE_REL_AMD64_SECREL => {
                        let sec_base = find_section_base(output, sym_vaddr);
                        write_u32(&mut output.sections[out_idx].data, patch,
                            sym_vaddr.wrapping_sub(sec_base) as u32);
                    }
                    IMAGE_REL_AMD64_ABSOLUTE => {}
                    t => return Err(format!(
                        "unsupported COFF reloc {:#06x} for '{}' in {}", t, rel.symbol_name, obj.path)),
                }
            }
        }
    }

    // build .reloc section from collected fixups
    ctx.base_relocs = base_relocs;
    let reloc_data = build_base_relocs(&ctx.base_relocs, ctx.image_base);
    if let Some(ms) = output.sections.iter_mut().find(|s| s.name == ".reloc") {
        ms.data = reloc_data;
    }

    Ok(())
}

// apply_relocations takes &mut ctx - fix the linker signature
pub fn apply_relocations_mut(
    objects: &[ObjectFile],
    output: &mut LinkedOutput,
    ctx: &mut LinkContext,
) -> Result<(), String> {
    apply_relocations(objects, output, ctx)
}

fn apply_rel32(data: &mut [u8], patch: usize, sym: u64, place: u64, extra: u64) {
    let addend = read_inline_i32(data, patch) as i64;
    let val = sym.wrapping_add_signed(addend)
        .wrapping_sub(place + 4 + extra) as i32;
    write_i32(data, patch, val);
}

// build PE base relocation (.reloc) section
// groups fixups by 4KB page, each block: RVA(4) + BlockSize(4) + entries(2 each)
fn build_base_relocs(fixups: &[u64], image_base: u64) -> Vec<u8> {
    if fixups.is_empty() { return Vec::new(); }

    let mut sorted = fixups.to_vec();
    sorted.sort_unstable();

    let mut buf: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let page_rva = (sorted[i] - image_base) & !0xFFF;
        let mut entries: Vec<u16> = Vec::new();
        while i < sorted.len() {
            let rva = sorted[i] - image_base;
            if rva & !0xFFF != page_rva { break; }
            let offset = (rva & 0xFFF) as u16;
            entries.push(0xA000 | offset); // type 0xA = DIR64
            i += 1;
        }
        // pad to 4-byte alignment
        if entries.len() % 2 != 0 { entries.push(0); }
        let block_size = 8 + entries.len() * 2;
        write_u32_vec(&mut buf, page_rva as u32);
        write_u32_vec(&mut buf, block_size as u32);
        for e in entries { buf.extend_from_slice(&e.to_le_bytes()); }
    }
    buf
}

fn resolve_sym(
    obj: &ObjectFile,
    rel: &slnk_common::Relocation,
    ctx: &LinkContext,
    globals: &HashMap<String, ResolvedSymbol>,
) -> Result<u64, String> {
    let sym = obj.symbols.get(rel.sym_index);
    if let Some(s) = sym {
        if (s.sym_type == SymbolType::Section || s.binding == SymbolBinding::Local) && s.defined {
            let sec_idx = s.section_index;
            if let Some(&v) = ctx.section_vaddrs.get(&(obj.path.clone(), sec_idx)) {
                return Ok(v + s.value);
            }
        }
        if !s.name.is_empty() {
            if let Some(r) = globals.get(&s.name) { return Ok(r.vaddr); }
        }
    }
    if !rel.symbol_name.is_empty() {
        if let Some(r) = globals.get(&rel.symbol_name) { return Ok(r.vaddr); }
        return Err(format!("undefined symbol '{}' in {}", rel.symbol_name, obj.path));
    }
    Err(format!("cannot resolve reloc sym_index={} '{}' in {}",
        rel.sym_index, rel.symbol_name, obj.path))
}

fn compute_sym_vaddr(sym: &Symbol, obj: &ObjectFile, ctx: &LinkContext) -> u64 {
    if sym.section_index == 0xfff1 { return sym.value; } // ABS
    if let Some(&base) = ctx.section_vaddrs.get(&(obj.path.clone(), sym.section_index)) {
        return base + sym.value;
    }
    sym.value
}

fn find_section_num(output: &LinkedOutput, vaddr: u64) -> usize {
    for (i, sec) in output.sections.iter().enumerate() {
        if vaddr >= sec.vaddr && vaddr < sec.vaddr + sec.data.len() as u64 { return i + 1; }
    }
    0
}

fn find_section_base(output: &LinkedOutput, vaddr: u64) -> u64 {
    for sec in &output.sections {
        if vaddr >= sec.vaddr && vaddr < sec.vaddr + sec.data.len() as u64 { return sec.vaddr; }
    }
    0
}

// build synthetic .idata section with correct DLL names from parsed .idata$* sections
fn build_idata(
    dll_funcs: &HashMap<String, Vec<(u16, String)>>,
    idata_rva: u32,
) -> (Vec<u8>, Vec<ImportDll>) {
    if dll_funcs.is_empty() { return (Vec::new(), Vec::new()); }

    let num_dlls = dll_funcs.len();
    let idt_size = (num_dlls + 1) * 20;
    let ilts_size: usize = dll_funcs.values().map(|v| (v.len() + 1) * 8).sum();
    let iats_size = ilts_size;

    // build HNT
    let mut hnt: Vec<u8> = Vec::new();
    let mut hnt_off: HashMap<String, u32> = HashMap::new();
    for (_, funcs) in dll_funcs {
        for (hint, name) in funcs {
            let off = hnt.len() as u32;
            hnt_off.insert(name.clone(), off);
            hnt.extend_from_slice(&hint.to_le_bytes());
            hnt.extend_from_slice(name.as_bytes());
            hnt.push(0);
            if hnt.len() % 2 != 0 { hnt.push(0); }
        }
    }

    // build DLL name table
    let mut dnt: Vec<u8> = Vec::new();
    let mut dnt_off: HashMap<String, u32> = HashMap::new();
    for dll in dll_funcs.keys() {
        let off = dnt.len() as u32;
        dnt_off.insert(dll.clone(), off);
        dnt.extend_from_slice(dll.as_bytes());
        dnt.push(0);
        if dnt.len() % 2 != 0 { dnt.push(0); }
    }

    let idt_off  = 0u32;
    let ilt_off  = idt_off + idt_size as u32;
    let iat_off  = ilt_off + ilts_size as u32;
    let hnt_base = iat_off + iats_size as u32;
    let dnt_base = hnt_base + hnt.len() as u32;
    let total    = dnt_base + dnt.len() as u32;

    let mut buf = vec![0u8; total as usize];
    buf[hnt_base as usize..hnt_base as usize + hnt.len()].copy_from_slice(&hnt);
    buf[dnt_base as usize..dnt_base as usize + dnt.len()].copy_from_slice(&dnt);

    let mut imports: Vec<ImportDll> = Vec::new();
    let mut idt_cur = idt_off as usize;
    let mut ilt_cur = ilt_off as usize;
    let mut iat_cur = iat_off as usize;

    // sort DLLs for deterministic output
    let mut dll_names: Vec<&String> = dll_funcs.keys().collect();
    dll_names.sort();

    for dll_name in dll_names {
        let funcs = &dll_funcs[dll_name];
        let dll_rva = idata_rva + dnt_base + dnt_off[dll_name];
        let ilt_rva = idata_rva + ilt_cur as u32;
        let iat_rva = idata_rva + iat_cur as u32;

        // IDT entry
        write_u32_at(&mut buf, idt_cur,      ilt_rva);
        write_u32_at(&mut buf, idt_cur + 4,  0);
        write_u32_at(&mut buf, idt_cur + 8,  0);
        write_u32_at(&mut buf, idt_cur + 12, dll_rva);
        write_u32_at(&mut buf, idt_cur + 16, iat_rva);
        idt_cur += 20;

        let mut import_funcs: Vec<ImportFunc> = Vec::new();
        for (hint, name) in funcs {
            let hnt_rva = idata_rva + hnt_base + hnt_off[name];
            write_u64_at(&mut buf, ilt_cur, hnt_rva as u64);
            write_u64_at(&mut buf, iat_cur, hnt_rva as u64);
            import_funcs.push(ImportFunc {
                name: name.clone(),
                hint: *hint,
                iat_rva: iat_rva + import_funcs.len() as u32 * 8,
            });
            ilt_cur += 8;
            iat_cur += 8;
        }
        // null terminators
        ilt_cur += 8;
        iat_cur += 8;

        imports.push(ImportDll { dll_name: dll_name.clone(), funcs: import_funcs });
    }

    (buf, imports)
}

fn read_inline_i32(data: &[u8], off: usize) -> i32 {
    if off + 4 > data.len() { return 0; }
    i32::from_le_bytes(data[off..off+4].try_into().unwrap())
}

fn read_inline_i64(data: &[u8], off: usize) -> i64 {
    if off + 8 > data.len() { return 0; }
    i64::from_le_bytes(data[off..off+8].try_into().unwrap())
}

fn write_u16(data: &mut [u8], off: usize, val: u16) { data[off..off+2].copy_from_slice(&val.to_le_bytes()); }
fn write_u32(data: &mut [u8], off: usize, val: u32) { data[off..off+4].copy_from_slice(&val.to_le_bytes()); }
fn write_i32(data: &mut [u8], off: usize, val: i32) { data[off..off+4].copy_from_slice(&val.to_le_bytes()); }
fn write_u64(data: &mut [u8], off: usize, val: u64) { data[off..off+8].copy_from_slice(&val.to_le_bytes()); }
fn write_u32_at(buf: &mut [u8], off: usize, val: u32) { if off+4<=buf.len() { buf[off..off+4].copy_from_slice(&val.to_le_bytes()); } }
fn write_u64_at(buf: &mut [u8], off: usize, val: u64) { if off+8<=buf.len() { buf[off..off+8].copy_from_slice(&val.to_le_bytes()); } }
fn write_u32_vec(buf: &mut Vec<u8>, val: u32) { buf.extend_from_slice(&val.to_le_bytes()); }
