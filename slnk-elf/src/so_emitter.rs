// ELF shared library (.so) emitter - produces ET_DYN

use slnk_common::{LinkedOutput, align_up};
use crate::types::*;
use crate::so_linker::SoLinkContext;

const PAGE: u64 = 0x1000;

const PT_DYNAMIC:   u32 = 2;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;

const DT_STRTAB:    u64 = 5;
const DT_SYMTAB:    u64 = 6;
const DT_RELA:      u64 = 7;
const DT_RELASZ:    u64 = 8;
const DT_RELAENT:   u64 = 9;
const DT_STRSZ:     u64 = 10;
const DT_SYMENT:    u64 = 11;
const DT_SONAME:    u64 = 14;
const DT_FLAGS_1:   u64 = 0x6ffffffb;
const DT_GNU_HASH:  u64 = 0x6ffffef5;
const DT_RELACOUNT: u64 = 0x6ffffff9;
const DT_NULL:      u64 = 0;

const SHT_DYNSYM:   u32 = 11;
const SHT_GNU_HASH: u32 = 0x6ffffff6;
const SHT_DYNAMIC:  u32 = 6;

pub fn emit(output: &LinkedOutput, ctx: &SoLinkContext) -> Vec<u8> {
    // build .gnu.hash first - it gives us the bucket-sorted export order
    let (gnu_hash, sorted_indices) = build_gnu_hash(&ctx.exports);

    // sorted_exports: exports reordered so same-bucket symbols are contiguous
    let sorted_exports: Vec<&(String, u64, u64)> = if sorted_indices.is_empty() {
        ctx.exports.iter().collect()
    } else {
        sorted_indices.iter().map(|&i| &ctx.exports[i]).collect()
    };

    // build .dynstr with sorted symbol names
    let mut dynstr: Vec<u8> = vec![0];
    let soname_idx = dynstr.len() as u32;
    dynstr.extend_from_slice(ctx.soname.as_bytes()); dynstr.push(0);

    let mut sym_name_idx: Vec<u32> = Vec::new();
    for (name, _, _) in &sorted_exports {
        sym_name_idx.push(dynstr.len() as u32);
        dynstr.extend_from_slice(name.as_bytes()); dynstr.push(0);
    }

    // build .dynsym in sorted order (shndx corrected after layout)
    let mut dynsym = vec![0u8; 24]; // null entry
    for (i, (_, vaddr, size)) in sorted_exports.iter().enumerate() {
        let mut e = [0u8; 24];
        e[0..4].copy_from_slice(&sym_name_idx[i].to_le_bytes());
        e[4] = (1u8 << 4) | 2u8; // STB_GLOBAL | STT_FUNC
        e[6..8].copy_from_slice(&5u16.to_le_bytes()); // placeholder shndx, fixed after layout
        e[8..16].copy_from_slice(&vaddr.to_le_bytes());
        e[16..24].copy_from_slice(&size.to_le_bytes());
        dynsym.extend_from_slice(&e);
    }

    // --- build .rela.dyn (R_X86_64_RELATIVE entries) ---
    let mut rela_dyn: Vec<u8> = Vec::new();
    for &place in &ctx.relative_relocs {
        rela_dyn.extend_from_slice(&place.to_le_bytes()); // r_offset
        rela_dyn.extend_from_slice(&8u64.to_le_bytes());  // r_info = R_X86_64_RELATIVE
        rela_dyn.extend_from_slice(&place.to_le_bytes()); // r_addend = value at place
    }

    // --- section list in layout order ---
    // each: (name, data, align, sh_type, sh_flags)
    let mut secs: Vec<(&str, Vec<u8>, u64, u32, u64)> = Vec::new();

    // read-only synthetic - indices 1..4 (1-based, null shdr is 0)
    secs.push((".gnu.hash", gnu_hash, 8, SHT_GNU_HASH, SHF_ALLOC));
    secs.push((".dynsym",   dynsym,   8, SHT_DYNSYM,   SHF_ALLOC));
    secs.push((".dynstr",   dynstr.clone(), 1, SHT_STRTAB, SHF_ALLOC));
    secs.push((".rela.dyn", rela_dyn, 8, SHT_RELA,     SHF_ALLOC));

    // regular sections from linker output - indices 5.. (1-based)
    let leaked_names: Vec<String> = output.sections.iter().map(|s| s.name.clone()).collect();
    for (i, sec) in output.sections.iter().enumerate() {
        let is_tls    = sec.name == ".tdata" || sec.name == ".tbss";
        let mut flags: u64 = SHF_ALLOC;
        if sec.flags.write { flags |= SHF_WRITE; }
        if sec.flags.exec  { flags |= SHF_EXECINSTR; }
        if is_tls          { flags |= SHF_TLS as u64; }
        let sh_type = match sec.name.as_str() {
            ".bss"|".tbss" => SHT_NOBITS,
            ".init_array"  => SHT_INIT_ARRAY,
            ".fini_array"  => SHT_FINI_ARRAY,
            _              => SHT_PROGBITS,
        };
        secs.push((&leaked_names[i], sec.data.clone(), PAGE, sh_type, flags));
    }

    // --- assign vaddrs ---
    // page 0: ELF header area (not explicitly mapped, covered by first LOAD at offset=0)
    // page 1: synthetic sections (.gnu.hash, .dynsym, .dynstr, .rela.dyn)
    // page 2+: regular sections from linker output (matching so_linker.rs layout)
    let mut vaddrs: Vec<u64> = Vec::new();
    let mut cur: u64 = PAGE; // synthetics start at page 1

    // synthetics (first 4 secs)
    let n_synthetic = 4usize;
    for (_, data, align, _, _) in secs.iter().take(n_synthetic) {
        cur = align_up(cur, *align);
        vaddrs.push(cur);
        cur += data.len() as u64;
    }

    // regular sections start at page 2 (matching so_linker which starts at 2*PAGE)
    cur = 2 * PAGE;
    for (_, data, align, _, _) in secs.iter().skip(n_synthetic) {
        cur = align_up(cur, *align);
        vaddrs.push(cur);
        cur += data.len() as u64;
    }

    // .dynamic goes after all regular sections, page-aligned
    cur = align_up(cur, 8);
    let dynamic_vaddr = cur;

    // fix dynsym shndx: find which output section contains each export symbol
    // in the emitter, regular sections are at secs[4..] (after 4 synthetic ones)
    // so shndx = 4 + output_section_index + 1 (null=0)
    {
        let shndxes: Vec<u16> = sorted_exports.iter()
            .map(|(_, sym_vaddr, _)| {
                output.sections.iter().enumerate()
                    .find(|(_, sec)| {
                        sec.vaddr <= *sym_vaddr &&
                        *sym_vaddr < sec.vaddr + sec.data.len() as u64
                    })
                    .map(|(i, _)| (4 + 1 + i) as u16)
                    .unwrap_or(5u16)
            })
            .collect();

        let dynsym_data = &mut secs[1].1;
        for (exp_idx, shndx) in shndxes.iter().enumerate() {
            let entry_off = 24 + exp_idx * 24;
            if entry_off + 8 <= dynsym_data.len() {
                dynsym_data[entry_off+6..entry_off+8].copy_from_slice(&shndx.to_le_bytes());
            }
        }
    }

    // build .dynamic with correct vaddrs
    let find_va = |name: &str| -> u64 {
        secs.iter().zip(vaddrs.iter())
            .find(|((n, _, _, _, _), _)| *n == name)
            .map(|(_, &v)| v)
            .unwrap_or(0)
    };
    let find_sz = |name: &str| -> u64 {
        secs.iter()
            .find(|(n, _, _, _, _)| *n == name)
            .map(|(_, d, _, _, _)| d.len() as u64)
            .unwrap_or(0)
    };

    let mut dyn_entries: Vec<(u64, u64)> = Vec::new();
    let gh = find_va(".gnu.hash");
    let ds = find_va(".dynsym");
    let dr = find_va(".dynstr");
    let ra = find_va(".rela.dyn");
    let rsz = find_sz(".rela.dyn");
    if gh != 0 { dyn_entries.push((DT_GNU_HASH, gh)); }
    if ds != 0 { dyn_entries.push((DT_SYMTAB,   ds)); }
    if dr != 0 { dyn_entries.push((DT_STRTAB,   dr)); }
    dyn_entries.push((DT_STRSZ,  dynstr.len() as u64));
    dyn_entries.push((DT_SYMENT, 24));
    if rsz > 0 {
        dyn_entries.push((DT_RELA,      ra));
        dyn_entries.push((DT_RELASZ,    rsz));
        dyn_entries.push((DT_RELAENT,   24));
        dyn_entries.push((DT_RELACOUNT, rsz / 24));
    }
    if soname_idx != 0 { dyn_entries.push((DT_SONAME, soname_idx as u64)); }
    dyn_entries.push((DT_FLAGS_1, 0));
    dyn_entries.push((DT_NULL,    0));

    let mut dynamic: Vec<u8> = Vec::new();
    for (tag, val) in &dyn_entries {
        dynamic.extend_from_slice(&tag.to_le_bytes());
        dynamic.extend_from_slice(&val.to_le_bytes());
    }
    let dynamic_size = dynamic.len() as u64;
    cur += dynamic_size;

    // shstrtab
    let mut shstrtab: Vec<u8> = vec![0];
    let mut shstr_offs: Vec<u32> = Vec::new();
    for (name, _, _, _, _) in &secs {
        shstr_offs.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes()); shstrtab.push(0);
    }
    // .dynamic
    let dynamic_shstr_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".dynamic\0");
    let shstrtab_shstr_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let shstrtab_va = align_up(cur, 8);
    cur = shstrtab_va + shstrtab.len() as u64;

    // section headers
    let num_shdrs = secs.len() as u64 + 3; // null + secs + .dynamic + .shstrtab
    let shoff = align_up(cur, 8);

    // --- compute LOAD segment groups ---
    // The first LOAD must be at vaddr=0, offset=0 so the kernel can pick a random base.
    // We include the ELF header + phdrs + read-only synthetic sections in LOAD[0].
    // Then one LOAD per additional permission group.
    struct LoadSeg { flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64 }
    let mut load_segs: Vec<LoadSeg> = Vec::new();

    // LOAD[0]: vaddr=0, offset=0, covers header area + read-only synthetics
    // find end of read-only (non-exec, non-write) sections
    let ro_end = secs.iter().zip(vaddrs.iter())
        .filter(|((_, _, _, _, f), _)| f & (SHF_WRITE | SHF_EXECINSTR) == 0)
        .map(|(( _, data, _, _, _), &va)| va + data.len() as u64)
        .max().unwrap_or(PAGE);
    load_segs.push(LoadSeg { flags: PF_R, offset: 0, vaddr: 0, filesz: ro_end, memsz: ro_end });

    // LOAD[1..]: exec, then RW - one per permission group
    let mut prev_perm: Option<u32> = None;
    for (i, (_, data, _, sh_type, sh_flags)) in secs.iter().enumerate() {
        if sh_flags & (SHF_WRITE | SHF_EXECINSTR) == 0 { continue; } // already in LOAD[0]
        let va  = vaddrs[i];
        let fsz = if *sh_type == SHT_NOBITS { 0 } else { data.len() as u64 };
        let msz = data.len() as u64;
        let perm = {
            let mut p = PF_R;
            if sh_flags & SHF_WRITE != 0     { p |= PF_W; }
            if sh_flags & SHF_EXECINSTR != 0 { p |= PF_X; }
            p
        };
        if Some(perm) == prev_perm {
            let last = load_segs.last_mut().unwrap();
            let end = (last.vaddr + last.filesz).max(va + fsz);
            last.filesz = end - last.vaddr;
            let mend = (last.vaddr + last.memsz).max(va + msz);
            last.memsz = mend - last.vaddr;
        } else {
            load_segs.push(LoadSeg { flags: perm, offset: va, vaddr: va, filesz: fsz, memsz: msz });
            prev_perm = Some(perm);
        }
    }
    // include .dynamic in last RW segment
    if let Some(last) = load_segs.last_mut() {
        if last.flags & PF_W != 0 {
            let end = (last.vaddr + last.filesz).max(dynamic_vaddr + dynamic_size);
            last.filesz = end - last.vaddr;
            last.memsz  = last.filesz;
        } else {
            load_segs.push(LoadSeg {
                flags: PF_R | PF_W,
                offset: dynamic_vaddr, vaddr: dynamic_vaddr,
                filesz: dynamic_size, memsz: dynamic_size,
            });
        }
    }

    let num_phdrs = (load_segs.len() + 2) as u16; // LOADs + DYNAMIC + GNU_STACK

    let total = shoff + 64 * num_shdrs;
    let mut buf = vec![0u8; total as usize];

    // ELF header
    buf[0..4].copy_from_slice(&ELFMAG);
    buf[4] = ELFCLASS64; buf[5] = ELFDATA2LSB; buf[6] = EV_CURRENT;
    w16(&mut buf, 16, 3);            // ET_DYN
    w16(&mut buf, 18, EM_X86_64);
    w32(&mut buf, 20, 1);
    w64(&mut buf, 24, 0);            // no entry point
    w64(&mut buf, 32, 64);           // phoff = right after ehdr
    w64(&mut buf, 40, shoff);
    w16(&mut buf, 52, 64); w16(&mut buf, 54, 56);
    w16(&mut buf, 56, num_phdrs);
    w16(&mut buf, 58, 64);
    w16(&mut buf, 60, num_shdrs as u16);
    w16(&mut buf, 62, (num_shdrs - 1) as u16); // shstrndx

    // write program headers
    let mut phoff = 64usize;
    for seg in &load_segs {
        w_phdr(&mut buf, phoff, PT_LOAD, seg.flags,
            seg.offset, seg.vaddr, seg.filesz, seg.memsz, PAGE);
        phoff += 56;
    }
    // DYNAMIC
    w_phdr(&mut buf, phoff, PT_DYNAMIC, PF_R|PF_W,
        dynamic_vaddr, dynamic_vaddr, dynamic_size, dynamic_size, 8);
    phoff += 56;
    // GNU_STACK
    w_phdr(&mut buf, phoff, PT_GNU_STACK, PF_R|PF_W, 0, 0, 0, 0, 0x10);

    // write section data at their vaddrs
    for (i, (_, data, _, sh_type, _)) in secs.iter().enumerate() {
        if *sh_type == SHT_NOBITS || data.is_empty() { continue; }
        let va = vaddrs[i] as usize;
        if va + data.len() <= buf.len() {
            buf[va..va + data.len()].copy_from_slice(data);
        }
    }
    // .dynamic
    if dynamic_vaddr as usize + dynamic.len() <= buf.len() {
        buf[dynamic_vaddr as usize..dynamic_vaddr as usize + dynamic.len()].copy_from_slice(&dynamic);
    }
    // .shstrtab
    if shstrtab_va as usize + shstrtab.len() <= buf.len() {
        buf[shstrtab_va as usize..shstrtab_va as usize + shstrtab.len()].copy_from_slice(&shstrtab);
    }

    // section headers
    let mut shpos = shoff as usize;
    shpos += 64; // null

    let dynsym_idx = secs.iter().position(|(n,_,_,_,_)| *n == ".dynsym").unwrap_or(0) + 1;
    let dynstr_idx = secs.iter().position(|(n,_,_,_,_)| *n == ".dynstr").unwrap_or(0) + 1;

    for (i, (_, data, align, sh_type, sh_flags)) in secs.iter().enumerate() {
        let link = if secs[i].0 == ".dynsym" { dynstr_idx as u32 }
                   else if secs[i].0 == ".rela.dyn" { dynsym_idx as u32 }
                   else { 0 };
        let info = if secs[i].0 == ".dynsym" { 1u32 } else { 0u32 };
        let entsz = if secs[i].0 == ".dynsym" || secs[i].0 == ".rela.dyn" { 24u64 } else { 0u64 };
        w_shdr(&mut buf, shpos, shstr_offs[i], *sh_type, *sh_flags,
            vaddrs[i], vaddrs[i], data.len() as u64, *align, link, info, entsz);
        shpos += 64;
    }
    // .dynamic shdr
    w_shdr(&mut buf, shpos, dynamic_shstr_off, SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE,
        dynamic_vaddr, dynamic_vaddr, dynamic_size, 8, dynstr_idx as u32, 0, 16);
    shpos += 64;
    // .shstrtab shdr
    w_shdr(&mut buf, shpos, shstrtab_shstr_off, SHT_STRTAB, SHF_ALLOC,
        shstrtab_va, shstrtab_va, shstrtab.len() as u64, 1, 0, 0, 0);

    buf
}

fn build_gnu_hash(exports: &[(String, u64, u64)]) -> (Vec<u8>, Vec<usize>) {
    // returns (gnu_hash_bytes, sorted_indices) where sorted_indices[i] = original export index
    let n = exports.len() as u32;
    let nbuckets = if n == 0 { 1 } else { (n / 4 + 1) };
    let sym_offset: u32 = 1; // dynsym index of first global (null is 0)
    let bloom_size: u32 = 1;
    let bloom_shift: u32 = 6;

    if n == 0 {
        let mut out = vec![
            1u8, 0, 0, 0,  // nbuckets=1
            1, 0, 0, 0,    // symoffset=1
            1, 0, 0, 0,    // bloom_size=1
            6, 0, 0, 0,    // bloom_shift=6
        ];
        out.extend_from_slice(&(!0u64).to_le_bytes()); // bloom
        out.extend_from_slice(&0u32.to_le_bytes());    // bucket[0]=0
        return (out, Vec::new());
    }

    // sort exports by bucket so all symbols in a bucket are contiguous
    let mut indexed: Vec<(usize, u32, u32)> = exports.iter().enumerate()
        .map(|(i, (name, _, _))| (i, gnu_hash(name), gnu_hash(name) % nbuckets))
        .collect();
    indexed.sort_by_key(|&(_, _, b)| b);
    let sorted_indices: Vec<usize> = indexed.iter().map(|&(i, _, _)| i).collect();

    // build buckets
    let mut buckets = vec![0u32; nbuckets as usize];
    for (pos, &(_, _, bucket)) in indexed.iter().enumerate() {
        if buckets[bucket as usize] == 0 {
            buckets[bucket as usize] = sym_offset + pos as u32;
        }
    }

    // build chains: hash & !1, set bit0=1 for last symbol in each bucket
    let mut chains = vec![0u32; n as usize];
    for (pos, &(_, h, bucket)) in indexed.iter().enumerate() {
        let is_last = pos + 1 >= indexed.len() || indexed[pos+1].2 != bucket;
        chains[pos] = (h & !1) | if is_last { 1 } else { 0 };
    }

    // bloom filter (all ones for simplicity)
    let bloom: u64 = !0u64;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&nbuckets.to_le_bytes());
    out.extend_from_slice(&sym_offset.to_le_bytes());
    out.extend_from_slice(&bloom_size.to_le_bytes());
    out.extend_from_slice(&bloom_shift.to_le_bytes());
    out.extend_from_slice(&bloom.to_le_bytes());
    for &b in &buckets { out.extend_from_slice(&b.to_le_bytes()); }
    for &c in &chains  { out.extend_from_slice(&c.to_le_bytes()); }
    (out, sorted_indices)
}

fn gnu_hash(s: &str) -> u32 {
    s.bytes().fold(5381u32, |h, b| h.wrapping_mul(33).wrapping_add(b as u32))
}

fn w_phdr(buf: &mut [u8], off: usize, ty: u32, fl: u32, foff: u64, va: u64, fsz: u64, msz: u64, al: u64) {
    w32(buf, off,    ty);  w32(buf, off+4,  fl);
    w64(buf, off+8,  foff); w64(buf, off+16, va);
    w64(buf, off+24, va);  w64(buf, off+32, fsz);
    w64(buf, off+40, msz); w64(buf, off+48, al);
}

fn w_shdr(buf: &mut [u8], off: usize, name: u32, ty: u32, fl: u64,
    va: u64, foff: u64, sz: u64, al: u64, link: u32, info: u32, entsz: u64) {
    w32(buf, off,    name); w32(buf, off+4,  ty);
    w64(buf, off+8,  fl);   w64(buf, off+16, va);
    w64(buf, off+24, foff); w64(buf, off+32, sz);
    w32(buf, off+40, link); w32(buf, off+44, info);
    w64(buf, off+48, al);   w64(buf, off+56, entsz);
}

fn w16(b: &mut [u8], o: usize, v: u16) { b[o..o+2].copy_from_slice(&v.to_le_bytes()); }
fn w32(b: &mut [u8], o: usize, v: u32) { b[o..o+4].copy_from_slice(&v.to_le_bytes()); }
fn w64(b: &mut [u8], o: usize, v: u64) { b[o..o+8].copy_from_slice(&v.to_le_bytes()); }
