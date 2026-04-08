// slnk - ELF and PE linker

use std::collections::HashSet;
use std::env;
use std::fs;
use std::process;

use slnk_common::{ObjectFile, SymbolBinding};

struct Args {
    inputs:     Vec<Input>,
    output:     String,
    entry:      String,
    format:     Format,
    shared:     bool,   // --shared / --dll
    soname:     Option<String>,
    // PE metadata
    icon:       Option<String>,
    pe_version: Option<(u16,u16,u16,u16)>,
    pe_desc:    Option<String>,
    pe_company: Option<String>,
    pe_product: Option<String>,
    pe_copy:    Option<String>,
    pe_sub:     Subsystem,
}

enum Input { Object(String), Archive(String) }

#[derive(Clone, Copy, PartialEq)]
enum Format { Elf, Pe }

#[derive(Clone, Copy)]
enum Subsystem { Console, Windows }

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = env::args().collect();
    if raw.len() < 2 { return Err(usage()); }

    let mut inputs    = Vec::new();
    let mut output    = String::from("a.out");
    let mut entry     = String::new();
    let mut format    = None::<Format>;
    let mut shared    = false;
    let mut soname    = None::<String>;
    let mut icon      = None::<String>;
    let mut pe_version = None;
    let mut pe_desc   = None;
    let mut pe_company = None;
    let mut pe_product = None;
    let mut pe_copy   = None;
    let mut pe_sub    = Subsystem::Console;

    let mut i = 1;
    while i < raw.len() {
        let arg = raw[i].as_str();
        match arg {
            "-o"             => { i += 1; output    = raw[i].clone(); }
            "-e"|"--entry"   => { i += 1; entry     = raw[i].clone(); }
            "--elf"          => { format = Some(Format::Elf); }
            "--pe"           => { format = Some(Format::Pe); }
            "--shared"       => { shared = true; }
            "--dll"          => { shared = true; format = Some(Format::Pe); }
            "--soname"       => { i += 1; soname = Some(raw[i].clone()); }
            "--format"       => { i += 1; format = Some(match raw[i].as_str() { "elf" => Format::Elf, "pe" => Format::Pe, f => return Err(format!("unknown format '{}'",f)) }); }
            "--icon"         => { i += 1; icon = Some(raw[i].clone()); }
            "--pe-version"   => { i += 1; pe_version = Some(parse_version(&raw[i])?); }
            "--pe-description"=> { i += 1; pe_desc    = Some(raw[i].clone()); }
            "--pe-company"   => { i += 1; pe_company  = Some(raw[i].clone()); }
            "--pe-product"   => { i += 1; pe_product  = Some(raw[i].clone()); }
            "--pe-copyright" => { i += 1; pe_copy     = Some(raw[i].clone()); }
            "--pe-subsystem"|"--subsystem" => {
                i += 1;
                pe_sub = match raw[i].as_str() {
                    "windows"|"gui" => Subsystem::Windows,
                    _ => Subsystem::Console,
                };
            }
            // ignore common linker flags
            "--as-needed"|"--no-as-needed"|"--start-group"|"--end-group" => {}
            a if a.starts_with("-m") || a.starts_with("-z") => {}
            a if a.starts_with("--rpath") || a.starts_with("--dynamic-linker") => { i += 1; }
            a if a.ends_with(".o") || a.ends_with(".obj") => { inputs.push(Input::Object(a.to_string())); }
            a if a.ends_with(".a") || a.ends_with(".lib") => { inputs.push(Input::Archive(a.to_string())); }
            a => return Err(format!("unknown argument: {}", a)),
        }
        i += 1;
    }

    if inputs.is_empty() { return Err("no input files given".into()); }

    let format = format.unwrap_or_else(|| {
        if output.ends_with(".exe") || output.ends_with(".dll") { Format::Pe }
        else if inputs.iter().any(|inp| matches!(inp, Input::Object(p) if p.ends_with(".obj"))) { Format::Pe }
        else { Format::Elf }
    });

    // auto-detect shared from output name
    let shared = shared
        || output.ends_with(".so") || output.contains(".so.")
        || output.ends_with(".dll");

    let entry = if entry.is_empty() {
        match (format, shared) {
            (Format::Pe, false) => "mainCRTStartup".into(),
            _ => "_start".into(),
        }
    } else { entry };

    let output = if output == "a.out" {
        match (format, shared) {
            (Format::Pe, true)  => "a.dll".into(),
            (Format::Pe, false) => "a.exe".into(),
            _ => output,
        }
    } else { output };

    // default soname = basename of output
    let soname = soname.unwrap_or_else(|| {
        std::path::Path::new(&output)
            .file_name().and_then(|n| n.to_str())
            .unwrap_or(&output).to_string()
    });

    Ok(Args { inputs, output, entry, format, shared, soname: Some(soname), icon, pe_version, pe_desc, pe_company, pe_product, pe_copy, pe_sub })
}

fn parse_version(s: &str) -> Result<(u16,u16,u16,u16), String> {
    let parts: Vec<&str> = s.split('.').collect();
    let p = |i: usize| -> Result<u16, String> {
        parts.get(i).unwrap_or(&"0").parse::<u16>()
            .map_err(|_| format!("invalid version component in '{}'", s))
    };
    Ok((p(0)?, p(1)?, p(2)?, p(3)?))
}

fn usage() -> String {
    "slnk - ELF and PE linker\n\
     usage: slnk [options] file.o|file.obj ... [file.a|file.lib ...]\n\
     \n\
     options:\n\
       -o <file>                output file (default: a.out / a.exe)\n\
       -e <symbol>              entry point\n\
       --elf                    force ELF output\n\
       --pe                     force PE output\n\
       --icon <file.ico>        embed icon (PE only)\n\
       --pe-version <M.m.p.b>   version number (e.g. 1.2.3.0)\n\
       --pe-description <str>   file description\n\
       --pe-company <str>       company name\n\
       --pe-product <str>       product name\n\
       --pe-copyright <str>     copyright string\n\
       --pe-subsystem <s>       console | windows (default: console)".into()
}

fn die(msg: &str) -> ! { eprintln!("slnk: {}", msg); process::exit(1); }

// ---- archive support ----

struct ArchiveMember { name: String, data: Vec<u8>, defined_syms: Vec<String> }

fn load_archive(path: &str, data: &[u8]) -> Result<Vec<ArchiveMember>, String> {
    if !data.starts_with(b"!<arch>\n") {
        return Err(format!("{}: not an ar/lib archive", path));
    }
    let mut members = Vec::new();
    let mut pos = 8usize;
    let mut name_table: Option<Vec<u8>> = None;

    while pos + 60 <= data.len() {
        let name_raw = std::str::from_utf8(&data[pos..pos+16]).unwrap_or("").to_string();
        let size: usize = std::str::from_utf8(&data[pos+48..pos+58]).unwrap_or("0")
            .trim().parse().unwrap_or(0);
        pos += 60;
        let mdata = if pos + size <= data.len() { data[pos..pos+size].to_vec() } else { break; };
        let name = name_raw.trim();

        if name == "//" {
            name_table = Some(mdata.clone());
        } else if name != "/" && name != "__.SYMDEF" && name != "__.SYMDEF SORTED" {
            let resolved = if name.starts_with('/') {
                if let Ok(off) = name[1..].trim().parse::<usize>() {
                    if let Some(ref nt) = name_table {
                        let end = nt[off..].iter().position(|&b| b==b'/'||b==b'\n').unwrap_or(nt.len()-off);
                        std::str::from_utf8(&nt[off..off+end]).unwrap_or("?").to_string()
                    } else { name.to_string() }
                } else { name.to_string() }
            } else { name.trim_end_matches('/').trim().to_string() };

            let is_elf  = mdata.starts_with(b"\x7fELF");
            let is_coff = mdata.len()>=2 && matches!(u16::from_le_bytes([mdata[0],mdata[1]]), 0x8664|0x014c);
            if is_elf || is_coff {
                let defined = peek_syms(&mdata);
                members.push(ArchiveMember { name: format!("{}({})", path, resolved), data: mdata, defined_syms: defined });
            }
        }
        pos += size;
        if size % 2 != 0 { pos += 1; }
    }
    Ok(members)
}

fn peek_syms(data: &[u8]) -> Vec<String> {
    if data.starts_with(b"\x7fELF") { peek_elf(data) } else { peek_coff(data) }
}

fn peek_elf(data: &[u8]) -> Vec<String> {
    use slnk_elf::types::{read_u16,read_u32,read_u64,read_u8,read_str,SHT_SYMTAB,STB_LOCAL};
    let mut syms = Vec::new();
    if data.len()<64 { return syms; }
    let shoff = read_u64(data,40) as usize;
    let shnum = read_u16(data,60) as usize;
    let shent = read_u16(data,58) as usize;
    for i in 0..shnum {
        let off = shoff + i*shent;
        if off+shent > data.len() { break; }
        if read_u32(data,off+4) != SHT_SYMTAB { continue; }
        let sh_link = read_u32(data,off+40) as usize;
        let sh_off  = read_u64(data,off+24) as usize;
        let sh_size = read_u64(data,off+32) as usize;
        let strtab = { let s=shoff+sh_link*shent; let so=read_u64(data,s+24) as usize; let ss=read_u64(data,s+32) as usize;
            if so+ss<=data.len() { &data[so..so+ss] } else { &[] } };
        for s in 0..sh_size/24 {
            let soff = sh_off+s*24;
            if soff+24>data.len() { break; }
            let st_name=read_u32(data,soff) as usize; let st_info=read_u8(data,soff+4); let st_shndx=read_u16(data,soff+6) as usize;
            if (st_info>>4)!=STB_LOCAL && st_shndx!=0 && st_shndx!=0xfff2 { let n=read_str(strtab,st_name); if !n.is_empty() { syms.push(n); } }
        }
        break;
    }
    syms
}

fn peek_coff(data: &[u8]) -> Vec<String> {
    use slnk_pe::types::{read_u32,read_u8,read_coff_name,IMAGE_SYM_CLASS_EXTERNAL,IMAGE_SYM_CLASS_WEAK_EXTERNAL};
    if data.len()<20 { return Vec::new(); }
    let sym_off=read_u32(data,8) as usize; let num_sym=read_u32(data,12) as usize;
    let strtab_start=sym_off+num_sym*18;
    let strtab = if strtab_start+4<=data.len() { let sz=read_u32(data,strtab_start) as usize; if strtab_start+sz<=data.len() { &data[strtab_start..strtab_start+sz] } else { &[] } } else { &[] };
    let mut syms=Vec::new(); let mut i=0;
    while i<num_sym {
        let off=sym_off+i*18; if off+18>data.len() { break; }
        let name=read_coff_name(&data[off..off+8],strtab);
        let sec=i16::from_le_bytes(data[off+12..off+14].try_into().unwrap());
        let cls=read_u8(data,off+16); let naux=read_u8(data,off+17) as usize;
        if (cls==IMAGE_SYM_CLASS_EXTERNAL||cls==IMAGE_SYM_CLASS_WEAK_EXTERNAL) && sec>0 && !name.is_empty() { syms.push(name); }
        i+=1+naux;
    }
    syms
}

fn collect_sym_sets(objects: &[ObjectFile]) -> (HashSet<String>, HashSet<String>) {
    let mut def=HashSet::new(); let mut undef=HashSet::new();
    for obj in objects {
        for sym in &obj.symbols {
            if sym.binding==SymbolBinding::Local||sym.name.is_empty() { continue; }
            if sym.defined { def.insert(sym.name.clone()); undef.remove(&sym.name); }
            else if !def.contains(&sym.name) { undef.insert(sym.name.clone()); }
        }
    }
    (def, undef)
}

fn parse_obj(path: &str, data: &[u8], fmt: Format) -> Result<ObjectFile, String> {
    match fmt {
        Format::Elf => slnk_elf::parser::parse(path, data),
        Format::Pe  => slnk_pe::parser::parse(path, data),
    }
}

fn write_output(path: &str, bytes: &[u8], executable: bool) {
    fs::write(path, bytes).unwrap_or_else(|e| die(&format!("cannot write '{}': {}", path, e)));
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    }
    eprintln!("slnk: wrote {} ({} bytes)", path, bytes.len());
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => { eprintln!("slnk: {}\n\n{}", e, usage()); process::exit(1); }
    };

    // load inputs
    let mut objects: Vec<ObjectFile> = Vec::new();
    let mut archives: Vec<Vec<ArchiveMember>> = Vec::new();

    for input in &args.inputs {
        match input {
            Input::Object(path) => {
                let data = fs::read(path).unwrap_or_else(|e| die(&format!("cannot read '{}': {}", path, e)));
                let obj  = parse_obj(path, &data, args.format).unwrap_or_else(|e| die(&e));
                objects.push(obj);
            }
            Input::Archive(path) => {
                let data    = fs::read(path).unwrap_or_else(|e| die(&format!("cannot read '{}': {}", path, e)));
                let members = load_archive(path, &data).unwrap_or_else(|e| die(&e));
                archives.push(members);
            }
        }
    }

    // archive resolution
    loop {
        let (def_before, _) = collect_sym_sets(&objects);
        let mut pulled = false;
        for archive in &mut archives {
            if archive.is_empty() { continue; }
            let members = std::mem::take(archive);
            let mut remaining = Vec::new();
            for member in members {
                let (_, undef) = collect_sym_sets(&objects);
                if member.defined_syms.iter().any(|s| undef.contains(s.as_str())) {
                    match parse_obj(&member.name, &member.data, args.format) {
                        Ok(obj) => { objects.push(obj); pulled = true; }
                        Err(e)  => eprintln!("slnk: warning: {}", e),
                    }
                } else { remaining.push(member); }
            }
            *archive = remaining;
        }
        let (def_after, _) = collect_sym_sets(&objects);
        if !pulled || def_after == def_before { break; }
    }

    // link and emit
    match (args.format, args.shared) {
        (Format::Elf, true) => {
            let soname = args.soname.as_deref().unwrap_or("a.so");
            let (mut out, mut ctx) = slnk_elf::so_linker::link(objects.clone(), soname)
                .unwrap_or_else(|e| die(&format!("link error:\n{}", e)));
            slnk_elf::so_linker::apply_relocations(&objects, &mut out, &mut ctx)
                .unwrap_or_else(|e| die(&format!("relocation error: {}", e)));
            let bytes = slnk_elf::so_emitter::emit(&out, &ctx);
            write_output(&args.output, &bytes, false);
        }
        (Format::Elf, false) => {
            let (mut out, ctx) = slnk_elf::linker::link(objects.clone(), &args.entry)
                .unwrap_or_else(|e| die(&format!("link error:\n{}", e)));
            slnk_elf::linker::apply_relocations(&objects, &mut out, &ctx)
                .unwrap_or_else(|e| die(&format!("relocation error: {}", e)));
            let bytes = slnk_elf::emitter::emit(&out, &ctx);
            write_output(&args.output, &bytes, true);
        }
        (Format::Pe, _) => {
            // for DLL entry point is optional (DllMain); use empty string to skip check
            let entry = if args.shared && args.entry == "_start" {
                "DllMain".to_string()
            } else {
                args.entry.clone()
            };

            let (mut out, mut ctx) = slnk_pe::linker::link(objects.clone(), &entry)
                .unwrap_or_else(|e| die(&format!("link error:\n{}", e)));
            slnk_pe::linker::apply_relocations(&objects, &mut out, &mut ctx)
                .unwrap_or_else(|e| die(&format!("relocation error: {}", e)));

            let icon_data = args.icon.as_ref().and_then(|p| fs::read(p).ok());
            let meta = slnk_pe::rsrc::PeMeta {
                description: args.pe_desc.clone(),
                company:     args.pe_company.clone(),
                product:     args.pe_product.clone(),
                copyright:   args.pe_copy.clone(),
                version:     args.pe_version,
            };
            let rsrc_rva = out.sections.last()
                .map(|s| {
                    let end = (s.vaddr - ctx.image_base) as u32
                        + slnk_common::align_up(s.data.len() as u64, 0x1000) as u32;
                    end
                }).unwrap_or(0x1000);
            let rsrc_bytes = slnk_pe::rsrc::build_rsrc(icon_data.as_deref(), &meta, rsrc_rva);
            if !rsrc_bytes.is_empty() {
                use slnk_common::{MergedSection, SectionFlags};
                out.sections.push(MergedSection {
                    name:  ".rsrc".to_string(),
                    data:  rsrc_bytes,
                    vaddr: ctx.image_base + rsrc_rva as u64,
                    align: 4,
                    flags: SectionFlags { alloc: true, exec: false, write: false },
                });
            }

            let subsystem = match args.pe_sub {
                Subsystem::Windows => slnk_pe::emitter::SUBSYSTEM_WINDOWS,
                Subsystem::Console => slnk_pe::emitter::SUBSYSTEM_CONSOLE,
            };
            let dll_name = args.soname.as_deref()
                .unwrap_or_else(|| std::path::Path::new(&args.output)
                    .file_name().and_then(|n| n.to_str()).unwrap_or("a.dll"));
            let bytes = slnk_pe::emitter::emit_full(&out, &ctx, subsystem, args.shared, dll_name);
            write_output(&args.output, &bytes, false);
        }
    }
}
