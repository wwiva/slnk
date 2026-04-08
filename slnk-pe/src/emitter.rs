// PE64 executable emitter

use slnk_common::{LinkedOutput, align_up};
use crate::types::*;
use crate::linker::LinkContext;

pub const SUBSYSTEM_CONSOLE: u16 = IMAGE_SUBSYSTEM_WINDOWS_CUI;
pub const SUBSYSTEM_WINDOWS: u16 = IMAGE_SUBSYSTEM_WINDOWS_GUI;

pub fn emit(output: &LinkedOutput, ctx: &LinkContext) -> Vec<u8> {
    emit_full(output, ctx, SUBSYSTEM_CONSOLE, false, "")
}

fn sec_flags(flags: &slnk_common::SectionFlags, name: &str) -> u32 {
    match name {
        ".text"  => IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ".bss"   => IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ".reloc" => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
        ".idata" => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ".rsrc"  => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        _ if flags.write => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        _ => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    }
}

fn w16(b: &mut [u8], o: usize, v: u16) { b[o..o+2].copy_from_slice(&v.to_le_bytes()); }
fn w32(b: &mut [u8], o: usize, v: u32) { b[o..o+4].copy_from_slice(&v.to_le_bytes()); }
fn w64(b: &mut [u8], o: usize, v: u64) { b[o..o+8].copy_from_slice(&v.to_le_bytes()); }

// builds PE .edata (export directory) section
fn build_edata(dll_name: &str, exports: &[(String, u32)], base_rva: u32) -> Vec<u8> {
    // exports: sorted (name, rva) pairs
    let mut sorted = exports.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let n = sorted.len() as u32;

    // layout within .edata:
    // export dir (40 bytes)
    // EAT: n * 4 bytes  (export address table - RVAs of functions)
    // NPT: n * 4 bytes  (name pointer table - RVAs of name strings)
    // OT:  n * 2 bytes  (ordinal table)
    // dll name string
    // function name strings

    let eat_off  = 40u32;
    let npt_off  = eat_off + n * 4;
    let ot_off   = npt_off + n * 4;
    let names_off = ot_off + n * 2;

    // compute name offsets
    let dll_name_off = names_off;
    let mut name_data: Vec<u8> = Vec::new();
    name_data.extend_from_slice(dll_name.as_bytes()); name_data.push(0);
    while name_data.len() % 2 != 0 { name_data.push(0); }

    let mut fn_name_offsets: Vec<u32> = Vec::new();
    for (name, _) in &sorted {
        fn_name_offsets.push(names_off + name_data.len() as u32);
        name_data.extend_from_slice(name.as_bytes()); name_data.push(0);
        while name_data.len() % 2 != 0 { name_data.push(0); }
    }

    let total = names_off as usize + name_data.len();
    let mut buf = vec![0u8; total];

    // export directory (40 bytes)
    // +0  Characteristics (0)
    // +4  TimeDateStamp
    // +8  MajorVersion, MinorVersion
    // +12 Name RVA
    // +16 OrdinalBase
    // +20 AddressTableEntries
    // +24 NumberOfNamePointers
    // +28 ExportAddressTableRVA
    // +32 NamePointerRVA
    // +36 OrdinalTableRVA
    w32(&mut buf, 12, base_rva + dll_name_off);  // Name RVA
    w32(&mut buf, 16, 1);                          // OrdinalBase = 1
    w32(&mut buf, 20, n);                          // AddressTableEntries
    w32(&mut buf, 24, n);                          // NumberOfNamePointers
    w32(&mut buf, 28, base_rva + eat_off);         // EAT RVA
    w32(&mut buf, 32, base_rva + npt_off);         // NPT RVA
    w32(&mut buf, 36, base_rva + ot_off);          // OT RVA

    // EAT: function RVAs
    for (i, (_, rva)) in sorted.iter().enumerate() {
        w32(&mut buf, eat_off as usize + i * 4, *rva);
    }
    // NPT: name RVAs
    for (i, off) in fn_name_offsets.iter().enumerate() {
        w32(&mut buf, npt_off as usize + i * 4, base_rva + off);
    }
    // OT: ordinals (0-based)
    for i in 0..n as usize {
        buf[ot_off as usize + i * 2]     = i as u8;
        buf[ot_off as usize + i * 2 + 1] = (i >> 8) as u8;
    }
    // name strings
    buf[names_off as usize..names_off as usize + name_data.len()]
        .copy_from_slice(&name_data);

    buf
}

// builds PE .reloc section from absolute VA fixup list
fn build_reloc(fixups: &[u64], image_base: u64) -> Vec<u8> {
    if fixups.is_empty() { return Vec::new(); }
    let mut sorted = fixups.to_vec();
    sorted.sort_unstable();
    let mut buf: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let page_rva = ((sorted[i] - image_base) & !0xFFF) as u32;
        let mut entries: Vec<u16> = Vec::new();
        while i < sorted.len() {
            let rva = (sorted[i] - image_base) as u32;
            if rva & !0xFFF != page_rva { break; }
            entries.push(0xA000 | ((rva & 0xFFF) as u16)); // DIR64
            i += 1;
        }
        if entries.len() % 2 != 0 { entries.push(0); }
        let block_size = 8 + entries.len() * 2;
        buf.extend_from_slice(&page_rva.to_le_bytes());
        buf.extend_from_slice(&(block_size as u32).to_le_bytes());
        for e in entries { buf.extend_from_slice(&e.to_le_bytes()); }
    }
    buf
}

/// Full PE emitter supporting both EXE and DLL modes.
/// For DLL: sets IMAGE_FILE_DLL, adds .edata export table, adds .reloc section.
pub fn emit_full(output: &LinkedOutput, ctx: &LinkContext, subsystem: u16, is_dll: bool, dll_name: &str) -> Vec<u8> {
    let image_base  = ctx.image_base;
    let sec_align   = SECTION_ALIGN as u64;
    let file_align  = FILE_ALIGN as u64;

    // collect __declspec(dllexport) symbols = all defined global symbols for DLL
    let mut exports: Vec<(String, u32)> = Vec::new(); // (name, function_rva)
    if is_dll {
        for (name, sym) in &output.symbols {
            if name.starts_with("__imp_") || name.starts_with("__start_")
                || name.starts_with("__stop_") || name.starts_with("_GLOBAL")
                || name == "_end" || name == "end" { continue; }
            if sym.vaddr >= image_base {
                exports.push((name.clone(), (sym.vaddr - image_base) as u32));
            }
        }
        exports.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // compute next RVA after current sections for .edata and .reloc
    let next_rva = |secs: &[slnk_common::MergedSection]| -> u32 {
        secs.last().map(|s| {
            let end = (s.vaddr - image_base) as u32;
            let sz  = slnk_common::align_up(s.data.len() as u64, sec_align) as u32;
            end + sz
        }).unwrap_or(SECTION_ALIGN)
    };

    let edata_rva = next_rva(&output.sections);
    let edata_bytes = if is_dll && !exports.is_empty() {
        build_edata(dll_name, &exports, edata_rva)
    } else { Vec::new() };

    let reloc_rva = edata_rva + slnk_common::align_up(edata_bytes.len() as u64, sec_align) as u32;
    let reloc_bytes = if is_dll {
        build_reloc(&ctx.base_relocs, image_base)
    } else { Vec::new() };

    // build extra sections list
    let mut extra_secs: Vec<(&str, &[u8], u32)> = Vec::new(); // (name, data, rva)
    if !edata_bytes.is_empty()  { extra_secs.push((".edata",  &edata_bytes,  edata_rva)); }
    if !reloc_bytes.is_empty()  { extra_secs.push((".reloc",  &reloc_bytes,  reloc_rva)); }

    let num_sections = (output.sections.len() + extra_secs.len()) as u16;

    let mz_size    = 64usize;
    let coff_size  = 20usize;
    let opt_size   = 240usize;
    let headers_raw = mz_size + 4 + coff_size + opt_size + num_sections as usize * 40;
    let headers_size = slnk_common::align_up(headers_raw as u64, file_align) as usize;

    // file offsets for regular sections
    let mut file_offsets: Vec<u32> = Vec::new();
    let mut cur_file = headers_size as u32;
    for sec in &output.sections {
        file_offsets.push(cur_file);
        let raw = if sec.name == ".bss" { 0 } else { slnk_common::align_up(sec.data.len() as u64, file_align) as u32 };
        cur_file += raw;
    }
    // file offsets for extra sections
    let mut extra_offsets: Vec<u32> = Vec::new();
    for (_, data, _) in &extra_secs {
        extra_offsets.push(cur_file);
        cur_file += slnk_common::align_up(data.len() as u64, file_align) as u32;
    }

    let total_file = cur_file as usize;

    let size_of_image = {
        let last_rva = extra_secs.last().map(|(_, d, r)| *r + slnk_common::align_up(d.len() as u64, sec_align) as u32)
            .or_else(|| output.sections.last().map(|s| {
                (s.vaddr - image_base) as u32 + slnk_common::align_up(s.data.len() as u64, sec_align) as u32
            })).unwrap_or(SECTION_ALIGN);
        slnk_common::align_up(last_rva as u64, sec_align) as u32
    };

    let text_sec  = output.sections.iter().find(|s| s.name == ".text");
    let idata_sec = output.sections.iter().find(|s| s.name == ".idata");
    let pdata_sec = output.sections.iter().find(|s| s.name == ".pdata");

    let entry_rva = if output.entry_point >= image_base { (output.entry_point - image_base) as u32 } else { 0 };
    let code_rva  = text_sec.map(|s| (s.vaddr - image_base) as u32).unwrap_or(0);
    let code_size = text_sec.map(|s| slnk_common::align_up(s.data.len() as u64, file_align) as u32).unwrap_or(0);

    let import_rva  = idata_sec.map(|s| (s.vaddr - image_base) as u32).unwrap_or(0);
    let import_size = idata_sec.map(|s| s.data.len() as u32).unwrap_or(0);
    let except_rva  = pdata_sec.map(|s| (s.vaddr - image_base) as u32).unwrap_or(0);
    let except_size = pdata_sec.map(|s| s.data.len() as u32).unwrap_or(0);
    let rsrc_sec    = output.sections.iter().find(|s| s.name == ".rsrc");
    let rsrc_rva    = rsrc_sec.map(|s| (s.vaddr - image_base) as u32).unwrap_or(0);
    let rsrc_size   = rsrc_sec.map(|s| s.data.len() as u32).unwrap_or(0);
    let export_dir_rva  = if !edata_bytes.is_empty() { edata_rva } else { 0 };
    let export_dir_size = edata_bytes.len() as u32;
    let reloc_dir_rva   = if !reloc_bytes.is_empty() { reloc_rva } else { 0 };
    let reloc_dir_size  = reloc_bytes.len() as u32;

    let iat_rva  = if !ctx.imports.is_empty() {
        let ilts: usize = ctx.imports.iter().map(|d| (d.funcs.len()+1)*8).sum();
        import_rva + (ctx.imports.len()+1) as u32 * 20 + ilts as u32
    } else { 0 };
    let iat_size: u32 = ctx.imports.iter().map(|d| (d.funcs.len()+1) as u32 * 8).sum();

    let mut buf = vec![0u8; total_file];

    // MZ
    buf[0..2].copy_from_slice(b"MZ");
    w16(&mut buf, 0x3c, mz_size as u16);
    buf[mz_size..mz_size+4].copy_from_slice(b"PE\0\0");

    let ch = mz_size + 4;
    let file_chars = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
        | if is_dll { 0x2000u16 } else { 0 }; // IMAGE_FILE_DLL = 0x2000
    w16(&mut buf, ch,    IMAGE_FILE_MACHINE_AMD64);
    w16(&mut buf, ch+2,  num_sections);
    w16(&mut buf, ch+16, opt_size as u16);
    w16(&mut buf, ch+18, file_chars);

    let oh = ch + coff_size;
    w16(&mut buf, oh,    IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    buf[oh+2] = 2; buf[oh+3] = 41;
    w32(&mut buf, oh+4,  code_size);
    w32(&mut buf, oh+16, entry_rva);
    w32(&mut buf, oh+20, code_rva);
    w64(&mut buf, oh+24, image_base);
    w32(&mut buf, oh+32, SECTION_ALIGN);
    w32(&mut buf, oh+36, FILE_ALIGN);
    buf[oh+40] = 4; buf[oh+48] = 5; buf[oh+50] = 2;
    w32(&mut buf, oh+56, size_of_image);
    w32(&mut buf, oh+60, headers_size as u32);
    w16(&mut buf, oh+68, subsystem);
    w16(&mut buf, oh+70,
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE    |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
    w64(&mut buf, oh+72,  0x200000);
    w64(&mut buf, oh+80,  0x1000);
    w64(&mut buf, oh+88,  0x100000);
    w64(&mut buf, oh+96,  0x1000);
    w32(&mut buf, oh+108, 16);

    let dd = oh + 112;
    w32(&mut buf, dd+0*8,    export_dir_rva);  w32(&mut buf, dd+0*8+4,  export_dir_size);
    w32(&mut buf, dd+1*8,    import_rva);      w32(&mut buf, dd+1*8+4,  import_size);
    w32(&mut buf, dd+2*8,    rsrc_rva);        w32(&mut buf, dd+2*8+4,  rsrc_size);
    w32(&mut buf, dd+3*8,    except_rva);      w32(&mut buf, dd+3*8+4,  except_size);
    w32(&mut buf, dd+5*8,    reloc_dir_rva);   w32(&mut buf, dd+5*8+4,  reloc_dir_size);
    w32(&mut buf, dd+12*8,   iat_rva);         w32(&mut buf, dd+12*8+4, iat_size);

    // section headers - regular
    let mut shoff = oh + opt_size;
    for (i, sec) in output.sections.iter().enumerate() {
        let is_bss  = sec.name == ".bss";
        let rva     = (sec.vaddr - image_base) as u32;
        let virt_sz = slnk_common::align_up(sec.data.len() as u64, sec_align) as u32;
        let raw_sz  = if is_bss { 0 } else { slnk_common::align_up(sec.data.len() as u64, file_align) as u32 };
        let nb = sec.name.as_bytes();
        buf[shoff..shoff+nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
        w32(&mut buf, shoff+8,  virt_sz);
        w32(&mut buf, shoff+12, rva);
        w32(&mut buf, shoff+16, raw_sz);
        w32(&mut buf, shoff+20, file_offsets[i]);
        w32(&mut buf, shoff+36, sec_flags(&sec.flags, &sec.name));
        shoff += 40;
    }
    // section headers - extra
    for (i, (name, data, rva)) in extra_secs.iter().enumerate() {
        let virt_sz = slnk_common::align_up(data.len() as u64, sec_align) as u32;
        let raw_sz  = slnk_common::align_up(data.len() as u64, file_align) as u32;
        let flags   = match *name {
            ".edata" => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            ".reloc" => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
            _        => IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        };
        let nb = name.as_bytes();
        buf[shoff..shoff+nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
        w32(&mut buf, shoff+8,  virt_sz);
        w32(&mut buf, shoff+12, *rva);
        w32(&mut buf, shoff+16, raw_sz);
        w32(&mut buf, shoff+20, extra_offsets[i]);
        w32(&mut buf, shoff+36, flags);
        shoff += 40;
    }

    // section data - regular
    for (i, sec) in output.sections.iter().enumerate() {
        if sec.name == ".bss" || sec.data.is_empty() { continue; }
        let off = file_offsets[i] as usize;
        buf[off..off+sec.data.len()].copy_from_slice(&sec.data);
    }
    // section data - extra
    for (i, (_, data, _)) in extra_secs.iter().enumerate() {
        if data.is_empty() { continue; }
        let off = extra_offsets[i] as usize;
        buf[off..off+data.len()].copy_from_slice(data);
    }

    buf
}

pub fn emit_with_opts(output: &LinkedOutput, ctx: &LinkContext, subsystem: u16) -> Vec<u8> {
    emit_full(output, ctx, subsystem, false, "")
}

pub fn emit_dll(output: &LinkedOutput, ctx: &LinkContext, subsystem: u16) -> Vec<u8> {
    emit_full(output, ctx, subsystem, true, "a.dll")
}
