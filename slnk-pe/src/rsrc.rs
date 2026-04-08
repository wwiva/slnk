// PE resource section (.rsrc) builder
// handles: RT_ICON (icon embedding) and RT_VERSION (metadata)

// Resource type IDs
const RT_ICON: u32       = 3;
const RT_GROUP_ICON: u32 = 14;
const RT_VERSION: u32    = 16;

pub struct PeMeta {
    pub description: Option<String>,
    pub company:     Option<String>,
    pub product:     Option<String>,
    pub copyright:   Option<String>,
    pub version:     Option<(u16, u16, u16, u16)>, // major.minor.patch.build
}

impl PeMeta {
    pub fn is_empty(&self) -> bool {
        self.description.is_none() && self.company.is_none() &&
        self.product.is_none() && self.copyright.is_none() && self.version.is_none()
    }
}

// build .rsrc section bytes and return them
// image_base_rva: the RVA where .rsrc will be placed in the final image
pub fn build_rsrc(icon_data: Option<&[u8]>, meta: &PeMeta, rsrc_rva: u32) -> Vec<u8> {
    // collect resource entries to include
    let mut resources: Vec<(u32, u32, Vec<u8>)> = Vec::new(); // (type, id, data)

    // version info
    if !meta.is_empty() {
        let ver_data = build_version_info(meta);
        resources.push((RT_VERSION, 1, ver_data));
    }

    // icon
    if let Some(ico) = icon_data {
        if let Some((icon_entries, group)) = parse_ico(ico) {
            for (idx, data) in icon_entries.into_iter().enumerate() {
                resources.push((RT_ICON, (idx + 1) as u32, data));
            }
            resources.push((RT_GROUP_ICON, 1, group));
        }
    }

    if resources.is_empty() { return Vec::new(); }

    build_rsrc_section(&resources, rsrc_rva)
}

// build the raw .rsrc section from a list of (type, id, data) resources
fn build_rsrc_section(resources: &[(u32, u32, Vec<u8>)], rsrc_rva: u32) -> Vec<u8> {
    // group by type
    let mut by_type: std::collections::HashMap<u32, Vec<(u32, &[u8])>> = std::collections::HashMap::new();
    for (rtype, rid, data) in resources {
        by_type.entry(*rtype).or_default().push((*rid, data.as_slice()));
    }

    let num_types = by_type.len();
    let type_ids: Vec<u32> = { let mut v: Vec<u32> = by_type.keys().copied().collect(); v.sort(); v };

    // layout:
    // root dir (16 + num_types*8)
    // per type: dir (16 + num_ids*8) + per id: dir (16 + 1*8) + leaf (16)
    // then data entries, then string table (empty), then actual data

    let root_size = 16 + num_types * 8;
    let type_dirs_size: usize = type_ids.iter().map(|t| 16 + by_type[t].len() * 8).sum();
    let id_dirs_size: usize = resources.len() * (16 + 8);
    let leaves_size  = resources.len() * 16;
    let dir_total    = root_size + type_dirs_size + id_dirs_size + leaves_size;

    // data: each resource padded to 4 bytes
    let mut data_parts: Vec<(u32, Vec<u8>)> = Vec::new(); // (rva_from_section_start, data)
    let mut data_offset = dir_total as u32;
    let mut all_data: Vec<u8> = Vec::new();

    // we need to know data offsets before writing dirs, so precompute
    let mut res_data_offsets: Vec<u32> = Vec::new(); // one per resource in original order
    let mut res_data_sizes: Vec<u32>   = Vec::new();

    for (_, _, data) in resources {
        let off = data_offset;
        let sz  = data.len() as u32;
        res_data_offsets.push(off);
        res_data_sizes.push(sz);
        all_data.extend_from_slice(data);
        let padded = (sz + 3) & !3;
        all_data.resize(all_data.len() + (padded - sz) as usize, 0);
        data_offset += padded;
    }

    let total = dir_total + all_data.len();
    let mut buf = vec![0u8; total];

    // write root directory
    let mut pos = 0usize;
    write_u32(&mut buf, pos,     0); // characteristics
    write_u32(&mut buf, pos+4,   0); // timestamp
    write_u16(&mut buf, pos+8,   0); // version major
    write_u16(&mut buf, pos+10,  0); // version minor
    write_u16(&mut buf, pos+12,  0); // named entries
    write_u16(&mut buf, pos+14,  num_types as u16); // id entries
    pos += 16;

    // root entries -> point to type dirs
    let mut type_dir_pos = root_size;
    for &tid in &type_ids {
        let num_ids = by_type[&tid].len();
        write_u32(&mut buf, pos,   tid);
        write_u32(&mut buf, pos+4, 0x80000000 | type_dir_pos as u32); // high bit = subdir
        pos += 8;
        type_dir_pos += 16 + num_ids * 8;
    }

    // type dirs
    let mut id_dir_pos = root_size + type_dirs_size;
    let mut res_idx = 0usize;
    for &tid in &type_ids {
        let ids = &by_type[&tid];
        let num_ids = ids.len();
        write_u16(&mut buf, pos+12, 0);
        write_u16(&mut buf, pos+14, num_ids as u16);
        pos += 16;

        for (i, &(rid, _)) in ids.iter().enumerate() {
            write_u32(&mut buf, pos,   rid);
            write_u32(&mut buf, pos+4, 0x80000000 | id_dir_pos as u32);
            pos += 8;
            id_dir_pos += 16 + 8;
        }
    }

    // id dirs (one entry each -> leaf)
    let mut leaf_pos = root_size + type_dirs_size + id_dirs_size;
    res_idx = 0;
    for &tid in &type_ids {
        let ids = &by_type[&tid];
        for (i, _) in ids.iter().enumerate() {
            // find original resource index for this (type, id)
            let orig_idx = resources.iter().position(|(rt, rid2, _)| *rt == tid && *rid2 == ids[i].0).unwrap();
            write_u16(&mut buf, pos+14, 1); // id entries = 1
            pos += 16;
            write_u32(&mut buf, pos,   0); // language = neutral
            write_u32(&mut buf, pos+4, leaf_pos as u32); // -> data entry
            pos += 8;
            leaf_pos += 16;
        }
    }

    // leaves (data entries)
    res_idx = 0;
    for &tid in &type_ids {
        for (_, (rid, _)) in by_type[&tid].iter().enumerate() {
            let orig_idx = resources.iter().position(|(rt, r2, _)| *rt == tid && r2 == rid).unwrap();
            let data_rva  = rsrc_rva + res_data_offsets[orig_idx];
            let data_size = res_data_sizes[orig_idx];
            write_u32(&mut buf, pos,     data_rva);
            write_u32(&mut buf, pos + 4, data_size);
            write_u32(&mut buf, pos + 8, 0);   // codepage
            write_u32(&mut buf, pos + 12, 0);  // reserved
            pos += 16;
        }
    }

    // copy data
    buf[dir_total..dir_total + all_data.len()].copy_from_slice(&all_data);

    buf
}

// parse .ico file, returns (individual icon bitmaps, GRPICONDIR data)
fn parse_ico(data: &[u8]) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
    if data.len() < 6 { return None; }
    let reserved = u16::from_le_bytes([data[0], data[1]]);
    let ico_type = u16::from_le_bytes([data[2], data[3]]);
    let count    = u16::from_le_bytes([data[4], data[5]]) as usize;
    if reserved != 0 || ico_type != 1 || count == 0 { return None; }
    if data.len() < 6 + count * 16 { return None; }

    let mut icon_data: Vec<Vec<u8>> = Vec::new();
    let mut group: Vec<u8> = Vec::new();

    // GRPICONDIR header
    group.extend_from_slice(&0u16.to_le_bytes()); // reserved
    group.extend_from_slice(&1u16.to_le_bytes()); // type=icon
    group.extend_from_slice(&(count as u16).to_le_bytes());

    for i in 0..count {
        let entry_off = 6 + i * 16;
        let width     = data[entry_off];
        let height    = data[entry_off + 1];
        let color_count = data[entry_off + 2];
        let reserved  = data[entry_off + 3];
        let planes    = u16::from_le_bytes([data[entry_off+4], data[entry_off+5]]);
        let bit_count = u16::from_le_bytes([data[entry_off+6], data[entry_off+7]]);
        let bytes_in_res = u32::from_le_bytes(data[entry_off+8..entry_off+12].try_into().ok()?);
        let image_offset = u32::from_le_bytes(data[entry_off+12..entry_off+16].try_into().ok()?) as usize;

        if image_offset + bytes_in_res as usize > data.len() { return None; }
        let img = data[image_offset..image_offset + bytes_in_res as usize].to_vec();
        icon_data.push(img);

        // GRPICONDIR entry (14 bytes)
        group.push(width);
        group.push(height);
        group.push(color_count);
        group.push(0); // reserved
        group.extend_from_slice(&planes.to_le_bytes());
        group.extend_from_slice(&bit_count.to_le_bytes());
        group.extend_from_slice(&bytes_in_res.to_le_bytes());
        group.extend_from_slice(&((i + 1) as u16).to_le_bytes()); // icon ID
    }

    Some((icon_data, group))
}

// build VS_VERSIONINFO block
fn build_version_info(meta: &PeMeta) -> Vec<u8> {
    let (maj, min, pat, bld) = meta.version.unwrap_or((1, 0, 0, 0));

    // fixed file info (52 bytes)
    let mut fixed = vec![0u8; 52];
    // signature
    fixed[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes());
    // struct version
    fixed[4..8].copy_from_slice(&0x00010000u32.to_le_bytes());
    // FileVersion
    let file_ver_ms = ((maj as u32) << 16) | (min as u32);
    let file_ver_ls = ((pat as u32) << 16) | (bld as u32);
    fixed[8..12].copy_from_slice(&file_ver_ms.to_le_bytes());
    fixed[12..16].copy_from_slice(&file_ver_ls.to_le_bytes());
    fixed[16..20].copy_from_slice(&file_ver_ms.to_le_bytes());
    fixed[20..24].copy_from_slice(&file_ver_ls.to_le_bytes());
    fixed[24..28].copy_from_slice(&0x00000000u32.to_le_bytes()); // flags mask
    fixed[28..32].copy_from_slice(&0x00000000u32.to_le_bytes()); // flags
    fixed[32..36].copy_from_slice(&0x00040004u32.to_le_bytes()); // OS: VOS_NT_WINDOWS32
    fixed[36..40].copy_from_slice(&0x00000001u32.to_le_bytes()); // type: VFT_APP
    // rest zero

    // StringFileInfo with one StringTable (lang=0409, codepage=04B0)
    let mut strings: Vec<(String, String)> = Vec::new();
    if let Some(ref v) = meta.description { strings.push(("FileDescription".into(), v.clone())); }
    if let Some(ref v) = meta.company     { strings.push(("CompanyName".into(), v.clone())); }
    if let Some(ref v) = meta.product     { strings.push(("ProductName".into(), v.clone())); }
    if let Some(ref v) = meta.copyright   { strings.push(("LegalCopyright".into(), v.clone())); }
    let ver_str = format!("{}.{}.{}.{}", maj, min, pat, bld);
    strings.push(("FileVersion".into(), ver_str.clone()));
    strings.push(("ProductVersion".into(), ver_str));

    // build StringTable block
    let mut str_table: Vec<u8> = Vec::new();
    for (key, val) in &strings {
        let key_w = to_utf16(key);
        let val_w = to_utf16(val);
        // String block: len(2) + val_len(2) + type(2) + key_w + pad + val_w
        let key_bytes = key_w.len() * 2 + 2; // + null
        let val_bytes = val_w.len() * 2 + 2;
        let hdr_size = 6 + key_bytes;
        let padded_hdr = align4(hdr_size);
        let total = padded_hdr + val_bytes;
        let mut entry = vec![0u8; total];
        write_u16_s(&mut entry, 0, total as u16);
        write_u16_s(&mut entry, 2, (val_w.len() + 1) as u16); // in words
        write_u16_s(&mut entry, 4, 1); // type = string
        // key
        for (i, &c) in key_w.iter().enumerate() {
            write_u16_s(&mut entry, 6 + i*2, c);
        }
        // null term + padding handled by zeroed vec
        // value at padded_hdr
        for (i, &c) in val_w.iter().enumerate() {
            write_u16_s(&mut entry, padded_hdr + i*2, c);
        }
        str_table.extend_from_slice(&entry);
        // pad to 4
        while str_table.len() % 4 != 0 { str_table.push(0); }
    }

    // StringTable wrapper (lang 0x0409, codepage 0x04B0)
    let lang_key = to_utf16("040904B0");
    let lang_key_bytes = lang_key.len() * 2 + 2;
    let st_hdr = 6 + lang_key_bytes;
    let st_hdr_pad = align4(st_hdr);
    let st_total = st_hdr_pad + str_table.len();
    let mut st = vec![0u8; st_total];
    write_u16_s(&mut st, 0, st_total as u16);
    write_u16_s(&mut st, 2, 0);
    write_u16_s(&mut st, 4, 1);
    for (i, &c) in lang_key.iter().enumerate() { write_u16_s(&mut st, 6 + i*2, c); }
    st[st_hdr_pad..].copy_from_slice(&str_table);

    // StringFileInfo wrapper
    let sfi_key = to_utf16("StringFileInfo");
    let sfi_key_bytes = sfi_key.len() * 2 + 2;
    let sfi_hdr = 6 + sfi_key_bytes;
    let sfi_hdr_pad = align4(sfi_hdr);
    let sfi_total = sfi_hdr_pad + st.len();
    let mut sfi = vec![0u8; sfi_total];
    write_u16_s(&mut sfi, 0, sfi_total as u16);
    write_u16_s(&mut sfi, 2, 0);
    write_u16_s(&mut sfi, 4, 1);
    for (i, &c) in sfi_key.iter().enumerate() { write_u16_s(&mut sfi, 6 + i*2, c); }
    sfi[sfi_hdr_pad..].copy_from_slice(&st);

    // VarFileInfo (translation table)
    let vfi_key = to_utf16("VarFileInfo");
    let var_key = to_utf16("Translation");
    let translation: [u8; 4] = [0x09, 0x04, 0xB0, 0x04]; // en-US, Unicode
    let var_inner_hdr = 6 + var_key.len() * 2 + 2;
    let var_inner_pad = align4(var_inner_hdr);
    let var_inner_total = var_inner_pad + 4;
    let mut var_inner = vec![0u8; var_inner_total];
    write_u16_s(&mut var_inner, 0, var_inner_total as u16);
    write_u16_s(&mut var_inner, 2, 4);
    write_u16_s(&mut var_inner, 4, 0);
    for (i, &c) in var_key.iter().enumerate() { write_u16_s(&mut var_inner, 6 + i*2, c); }
    var_inner[var_inner_pad..].copy_from_slice(&translation);

    let vfi_hdr = 6 + vfi_key.len() * 2 + 2;
    let vfi_hdr_pad = align4(vfi_hdr);
    let vfi_total = vfi_hdr_pad + var_inner.len();
    let mut vfi = vec![0u8; vfi_total];
    write_u16_s(&mut vfi, 0, vfi_total as u16);
    write_u16_s(&mut vfi, 2, 0);
    write_u16_s(&mut vfi, 4, 1);
    for (i, &c) in vfi_key.iter().enumerate() { write_u16_s(&mut vfi, 6 + i*2, c); }
    vfi[vfi_hdr_pad..].copy_from_slice(&var_inner);

    // VS_VERSIONINFO root
    let root_key = to_utf16("VS_VERSION_INFO");
    let root_key_bytes = root_key.len() * 2 + 2;
    let root_hdr = 6 + root_key_bytes;
    let root_hdr_pad = align4(root_hdr);
    let fixed_end = root_hdr_pad + 52;
    let fixed_end_pad = align4(fixed_end);
    let children_pad = align4(fixed_end_pad);
    let root_total = children_pad + sfi.len() + vfi.len();
    let mut root = vec![0u8; root_total];
    write_u16_s(&mut root, 0, root_total as u16);
    write_u16_s(&mut root, 2, 52); // fixed info size in bytes
    write_u16_s(&mut root, 4, 0);  // type = binary
    for (i, &c) in root_key.iter().enumerate() { write_u16_s(&mut root, 6 + i*2, c); }
    root[root_hdr_pad..root_hdr_pad + 52].copy_from_slice(&fixed);
    root[children_pad..children_pad + sfi.len()].copy_from_slice(&sfi);
    root[children_pad + sfi.len()..children_pad + sfi.len() + vfi.len()].copy_from_slice(&vfi);

    root
}

fn to_utf16(s: &str) -> Vec<u16> { s.encode_utf16().collect() }
fn align4(n: usize) -> usize { (n + 3) & !3 }
fn write_u16_s(buf: &mut [u8], off: usize, val: u16) {
    if off + 2 <= buf.len() { buf[off..off+2].copy_from_slice(&val.to_le_bytes()); }
}
fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    if off + 4 <= buf.len() { buf[off..off+4].copy_from_slice(&val.to_le_bytes()); }
}
fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    if off + 2 <= buf.len() { buf[off..off+2].copy_from_slice(&val.to_le_bytes()); }
}
