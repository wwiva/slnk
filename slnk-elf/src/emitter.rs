// emits a fully linked ELF64 executable from a LinkedOutput

use slnk_common::{LinkedOutput, align_up};
use crate::types::*;
use crate::linker::LinkContext;

const PAGE_ALIGN: u64 = 0x1000;

const PT_LOAD:      u32 = 1;
const PT_TLS:       u32 = 7;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;

struct Segment {
    seg_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

pub fn emit(output: &LinkedOutput, ctx: &LinkContext) -> Vec<u8> {
    let ehdr_size: u64 = 64;
    let phdr_size: u64 = 56;
    let shdr_size: u64 = 64;

    // --- compute file offsets for each section ---
    // rule: file_offset ≡ vaddr (mod PAGE_ALIGN) for each LOAD segment
    // .tbss and .bss have filesz=0 (not stored in file)
    let mut seg_file_offsets: Vec<u64> = Vec::new();
    {
        // header block will be at offset 0; sections start after
        // we don't know num_phdrs yet so we'll patch header after building segments
        let mut pos: u64 = 0; // placeholder, updated after phdr count known
        let _ = pos;
    }

    // build segment list first so we know phdr count, then assign offsets
    // pass 1: decide which LOAD segments to emit and their logical order
    // we emit one LOAD per output section (matching ld behavior)
    // plus: header LOAD, optional PT_TLS, PT_GNU_STACK, PT_GNU_RELRO
    let has_tls     = ctx.tls_memsz > 0;
    let has_relro   = output.sections.iter().any(|s| s.name == ".data.rel.ro");

    // count: 1 header + N section LOADs + PT_GNU_STACK + optional PT_TLS + optional PT_GNU_RELRO
    let extra = 1 + if has_tls { 1 } else { 0 } + if has_relro { 1 } else { 0 };
    let num_phdrs = (output.sections.len() as u64) + 1 + extra as u64;
    let num_shdrs = 1 + output.sections.len() as u64 + 1; // null + sections + shstrtab

    let headers_end = ehdr_size + phdr_size * num_phdrs;

    // assign file offsets per section
    let mut file_offsets: Vec<u64> = Vec::new();
    let mut cur = headers_end;
    for sec in &output.sections {
        let is_nobits = sec.name == ".bss" || sec.name == ".tbss";
        if is_nobits {
            // nobits sections don't occupy file space - reuse cur position
            file_offsets.push(cur);
            continue;
        }
        let vaddr = sec.vaddr;
        let page_off = vaddr % PAGE_ALIGN;
        let base = align_up(cur, PAGE_ALIGN);
        let mut off = base - (base % PAGE_ALIGN) + page_off;
        if off < cur { off += PAGE_ALIGN; }
        file_offsets.push(off);
        cur = off + sec.data.len() as u64;
    }

    // shstrtab + shdrs
    let mut shstrtab = vec![0u8];
    let mut sec_name_offsets: Vec<u32> = Vec::new();
    for sec in &output.sections {
        sec_name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(sec.name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let shstrtab_offset = cur;
    cur += shstrtab.len() as u64;
    let shoff = align_up(cur, 8);
    let total = shoff + shdr_size * num_shdrs;

    let mut buf = vec![0u8; total as usize];

    // --- build segment list ---
    let mut segs: Vec<Segment> = Vec::new();

    // header LOAD (offset=0, covers ELF header + phdrs)
    segs.push(Segment {
        seg_type: PT_LOAD,
        flags: PF_R,
        offset: 0,
        vaddr: DEFAULT_BASE,
        filesz: headers_end,
        memsz: headers_end,
        align: PAGE_ALIGN,
    });

    // one LOAD per output section
    for (i, sec) in output.sections.iter().enumerate() {
        let is_nobits = sec.name == ".bss" || sec.name == ".tbss";
        let filesz = if is_nobits { 0 } else { sec.data.len() as u64 };
        segs.push(Segment {
            seg_type: PT_LOAD,
            flags: section_flags_to_phdr(&sec.flags),
            offset: file_offsets[i],
            vaddr: sec.vaddr,
            filesz,
            memsz: sec.data.len() as u64,
            align: PAGE_ALIGN,
        });
    }

    // PT_TLS - covers .tdata + .tbss
    if has_tls {
        let tdata_off = output.sections.iter().position(|s| s.name == ".tdata")
            .map(|i| file_offsets[i]).unwrap_or(0);
        segs.push(Segment {
            seg_type: PT_TLS,
            flags: PF_R,
            offset: tdata_off,
            vaddr: ctx.tls_vaddr,
            filesz: ctx.tls_filesz,
            memsz: ctx.tls_memsz,
            align: ctx.tls_align.max(1),
        });
    }

    // PT_GNU_RELRO - covers .data.rel.ro (read-only after relocation)
    if has_relro {
        if let Some(sec) = output.sections.iter().find(|s| s.name == ".data.rel.ro") {
            let i = output.sections.iter().position(|s| s.name == ".data.rel.ro").unwrap();
            segs.push(Segment {
                seg_type: PT_GNU_RELRO,
                flags: PF_R,
                offset: file_offsets[i],
                vaddr: sec.vaddr,
                filesz: sec.data.len() as u64,
                memsz: sec.data.len() as u64,
                align: 1,
            });
        }
    }

    // PT_GNU_STACK - marks stack as non-executable
    segs.push(Segment {
        seg_type: PT_GNU_STACK,
        flags: PF_R | PF_W,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        align: 0x10,
    });

    // --- write ELF header ---
    write_elf_header(&mut buf, output.entry_point, ehdr_size, shoff,
        segs.len() as u16, num_shdrs as u16, (num_shdrs - 1) as u16);

    // --- write program headers ---
    for (i, seg) in segs.iter().enumerate() {
        write_phdr(&mut buf, (ehdr_size + phdr_size * i as u64) as usize, seg);
    }

    // --- write section data ---
    for (i, sec) in output.sections.iter().enumerate() {
        let is_nobits = sec.name == ".bss" || sec.name == ".tbss";
        if is_nobits || sec.data.is_empty() { continue; }
        let off = file_offsets[i] as usize;
        buf[off..off + sec.data.len()].copy_from_slice(&sec.data);
    }

    // --- write shstrtab ---
    buf[shstrtab_offset as usize..shstrtab_offset as usize + shstrtab.len()]
        .copy_from_slice(&shstrtab);

    // --- write section headers ---
    let mut shdr_off = shoff as usize;
    // null shdr
    shdr_off += shdr_size as usize;

    for (i, sec) in output.sections.iter().enumerate() {
        let is_tls   = sec.name == ".tdata" || sec.name == ".tbss";
        let is_nobits = sec.name == ".bss" || sec.name == ".tbss";
        let sh_type  = if is_nobits { SHT_NOBITS } else { SHT_PROGBITS };
        let mut sh_flags = section_flags_to_shflags(&sec.flags);
        if is_tls { sh_flags |= SHF_TLS; }
        // init_array / fini_array need SHT_INIT_ARRAY / SHT_FINI_ARRAY
        let sh_type = match sec.name.as_str() {
            ".init_array" => SHT_INIT_ARRAY,
            ".fini_array" => SHT_FINI_ARRAY,
            _ => sh_type,
        };
        let filesz = if is_nobits { sec.data.len() as u64 } else { sec.data.len() as u64 };
        write_shdr(&mut buf, shdr_off,
            sec_name_offsets[i], sh_type, sh_flags,
            sec.vaddr, file_offsets[i], filesz, sec.align.max(1));
        shdr_off += shdr_size as usize;
    }

    // shstrtab section header
    write_shdr(&mut buf, shdr_off,
        shstrtab_name_off, SHT_STRTAB, 0,
        0, shstrtab_offset, shstrtab.len() as u64, 1);

    buf
}

fn write_elf_header(buf: &mut [u8], entry: u64, phoff: u64, shoff: u64,
    phnum: u16, shnum: u16, shstrndx: u16) {
    buf[0..4].copy_from_slice(&ELFMAG);
    buf[4] = ELFCLASS64;
    buf[5] = ELFDATA2LSB;
    buf[6] = EV_CURRENT;
    // ident[7] = ELFOSABI_NONE (0), rest zero
    write_u16(buf, 16, ET_EXEC);
    write_u16(buf, 18, EM_X86_64);
    write_u32(buf, 20, 1);
    write_u64(buf, 24, entry);
    write_u64(buf, 32, phoff);
    write_u64(buf, 40, shoff);
    write_u32(buf, 48, 0);
    write_u16(buf, 52, 64);
    write_u16(buf, 54, 56);
    write_u16(buf, 56, phnum);
    write_u16(buf, 58, 64);
    write_u16(buf, 60, shnum);
    write_u16(buf, 62, shstrndx);
}

fn write_phdr(buf: &mut [u8], off: usize, seg: &Segment) {
    write_u32(buf, off,      seg.seg_type);
    write_u32(buf, off + 4,  seg.flags);
    write_u64(buf, off + 8,  seg.offset);
    write_u64(buf, off + 16, seg.vaddr);
    write_u64(buf, off + 24, seg.vaddr);  // p_paddr = p_vaddr
    write_u64(buf, off + 32, seg.filesz);
    write_u64(buf, off + 40, seg.memsz);
    write_u64(buf, off + 48, seg.align);
}

fn write_shdr(buf: &mut [u8], off: usize, name: u32, sh_type: u32, flags: u64,
    addr: u64, file_off: u64, size: u64, align: u64) {
    write_u32(buf, off,      name);
    write_u32(buf, off + 4,  sh_type);
    write_u64(buf, off + 8,  flags);
    write_u64(buf, off + 16, addr);
    write_u64(buf, off + 24, file_off);
    write_u64(buf, off + 32, size);
    write_u32(buf, off + 40, 0);  // sh_link
    write_u32(buf, off + 44, 0);  // sh_info
    write_u64(buf, off + 48, align);
    write_u64(buf, off + 56, 0);  // sh_entsize
}

fn write_null_shdr(_buf: &mut [u8], _off: usize) {}

fn section_flags_to_phdr(flags: &slnk_common::SectionFlags) -> u32 {
    let mut f = PF_R;
    if flags.write { f |= PF_W; }
    if flags.exec  { f |= PF_X; }
    f
}

fn section_flags_to_shflags(flags: &slnk_common::SectionFlags) -> u64 {
    let mut f: u64 = 0;
    if flags.alloc { f |= SHF_ALLOC; }
    if flags.write { f |= SHF_WRITE; }
    if flags.exec  { f |= SHF_EXECINSTR; }
    f
}

fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off+2].copy_from_slice(&val.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off+4].copy_from_slice(&val.to_le_bytes());
}
fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off+8].copy_from_slice(&val.to_le_bytes());
}
