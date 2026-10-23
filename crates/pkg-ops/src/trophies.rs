//! Read-only trophy definitions from PS3 TRP and PS4 TRP/ESFM resources.

use aes::{
    Aes128,
    cipher::{
        BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, KeyInit, KeyIvInit,
        block_padding::NoPadding,
    },
};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader, Read, Seek},
    path::Path,
};

const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;
const MAX_XML: usize = 4 * 1024 * 1024;
// Published PS4 release trophy key: https://www.psdevwiki.com/ps4/Trophy00.trp
const TROPHY_KEY: [u8; 16] = [
    0x21, 0xf4, 0x1a, 0x6b, 0xad, 0x8a, 0x1d, 0x3e, 0xca, 0x7a, 0xd5, 0x86, 0xc1, 0x01, 0xb7, 0xa9,
];

#[derive(Clone, Debug)]
pub struct Trophy {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub grade: String,
    pub hidden: bool,
    pub group: u32,
    pub icon: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct TrophySet {
    pub path: String,
    pub title: String,
    pub trophies: Vec<Trophy>,
    /// An unreadable set does not hide other sets in the same package.
    pub error: Option<String>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn bounded(reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("trophy resource exceeds size limit"));
    }
    Ok(bytes)
}

fn is_archive(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".trp")
}

/// Enumerate sets without writing files. English definitions are preferred,
/// falling back to default/first available language. No player progress is stored.
pub fn read(source: &Path) -> Result<Vec<TrophySet>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(source)?);
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    reader.rewind()?;
    let mut sets = Vec::new();
    let mut total = 0;
    match &magic {
        b"\x7fPKG" => {
            let mut pkg = ps3_pkg::Package::open(reader)?;
            let entries: Vec<_> = pkg
                .entries()
                .iter()
                .enumerate()
                .filter(|(_, e)| e.kind() == ps3_pkg::FileKind::File && is_archive(e.path()))
                .map(|(i, e)| (i, e.path().to_owned(), e.size()))
                .collect();
            for (index, path, size) in entries {
                check_budget(size, &mut total)?;
                let data = bounded(pkg.read_entry(index)?, MAX_ARCHIVE)?;
                sets.push(parse_set(&path, &data, &[]));
            }
        }
        b"\x7fCNT" => {
            let mut game = ps4_pkg::Package::open(reader)?.open_game()?;
            let binding = game
                .entries()
                .iter()
                .position(|e| e.path().eq_ignore_ascii_case("sce_sys/npbind.dat"));
            let ids = if let Some(index) = binding {
                np_ids(&bounded(game.read_entry(index)?, MAX_XML as u64)?)?
            } else {
                Vec::new()
            };
            let entries: Vec<_> = game
                .entries()
                .iter()
                .enumerate()
                .filter(|(_, e)| e.kind() == ps4_pkg::FileKind::File && is_archive(e.path()))
                .map(|(i, e)| (i, e.path().to_owned(), e.size()))
                .collect();
            for (index, path, size) in entries {
                check_budget(size, &mut total)?;
                let data = bounded(game.read_entry(index)?, MAX_ARCHIVE)?;
                sets.push(parse_set(&path, &data, &ids));
            }
        }
        _ => return Err(invalid("not a PS3 or PS4 package").into()),
    }
    Ok(sets)
}

fn check_budget(size: u64, total: &mut u64) -> io::Result<()> {
    if size > MAX_ARCHIVE || *total + size > MAX_TOTAL {
        return Err(invalid("trophy archives exceed size limit"));
    }
    *total += size;
    Ok(())
}

fn be32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid("truncated trophy header"))?
            .try_into()
            .unwrap(),
    ))
}

fn be64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(|| invalid("truncated trophy header"))?
            .try_into()
            .unwrap(),
    ))
}

fn np_ids(bytes: &[u8]) -> io::Result<Vec<String>> {
    if be32(bytes, 0)? != 0xd294a018 || bytes.len() < 128 {
        return Err(invalid("invalid npbind.dat header"));
    }
    let count = be64(bytes, 24)?;
    if count > 100 {
        return Err(invalid("too many trophy bindings"));
    }
    let mut offset = 128;
    let mut ids = Vec::new();
    for _ in 0..count {
        for field in 0..4 {
            let header = bytes
                .get(offset..offset + 4)
                .ok_or_else(|| invalid("truncated trophy binding"))?;
            let kind = u16::from_be_bytes(header[..2].try_into().unwrap());
            let size = u16::from_be_bytes(header[2..].try_into().unwrap()) as usize;
            offset += 4;
            let data = bytes
                .get(offset..offset + size)
                .ok_or_else(|| invalid("truncated trophy binding"))?;
            if field == 0 {
                let id = data.split(|b| *b == 0).next().unwrap_or_default();
                if kind != 0x10
                    || id.len() != 12
                    || &id[..4] != b"NPWR"
                    || !id[4..9].iter().all(u8::is_ascii_digit)
                    || id[9] != b'_'
                    || !id[10..].iter().all(u8::is_ascii_digit)
                {
                    return Err(invalid("invalid trophy NP communication ID"));
                }
                ids.push(String::from_utf8(id.to_vec()).unwrap());
            }
            offset += size;
        }
        offset += 0x98;
    }
    Ok(ids)
}

struct Resource<'a> {
    name: &'a str,
    bytes: &'a [u8],
    encrypted: bool,
}

fn resources(bytes: &[u8]) -> io::Result<Vec<Resource<'_>>> {
    if be32(bytes, 0)? != 0xdca24d00 {
        return Err(invalid("invalid TRP magic"));
    }
    let header = match be32(bytes, 4)? {
        1 | 2 => 64,
        3 => 96,
        _ => return Err(invalid("unsupported TRP version")),
    };
    if be64(bytes, 8)? != bytes.len() as u64 {
        return Err(invalid("TRP size mismatch"));
    }
    let count = be32(bytes, 16)? as usize;
    let stride = be32(bytes, 20)? as usize;
    if count > 16384 || stride != 64 {
        return Err(invalid("invalid TRP entry table"));
    }
    let end = header + count * stride;
    if end > bytes.len() {
        return Err(invalid("truncated TRP entry table"));
    }
    let mut names = BTreeSet::new();
    let mut entries = Vec::new();
    let mut ranges = Vec::new();
    for entry in bytes[header..end].chunks_exact(stride) {
        let name = entry[..32].split(|b| *b == 0).next().unwrap();
        let name = std::str::from_utf8(name).map_err(|_| invalid("invalid TRP resource name"))?;
        if name.is_empty() || !names.insert(name.to_ascii_uppercase()) {
            return Err(invalid("duplicate/empty TRP resource name"));
        }
        let offset = be64(entry, 32)?;
        let size = be64(entry, 40)?;
        let finish = offset
            .checked_add(size)
            .ok_or_else(|| invalid("TRP resource range overflow"))?;
        if offset < end as u64 || finish > bytes.len() as u64 {
            return Err(invalid("TRP resource outside archive"));
        }
        if size != 0 {
            ranges.push((offset, finish));
        }
        entries.push(Resource {
            name,
            bytes: &bytes[offset as usize..finish as usize],
            encrypted: be32(entry, 48)? == 3,
        });
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("overlapping TRP resources"));
    }
    Ok(entries)
}

fn trophy_key(id: &str) -> aes::cipher::Block<Aes128> {
    let mut key = aes::cipher::Block::<Aes128>::default();
    key[..id.len()].copy_from_slice(id.as_bytes());
    Aes128::new(&TROPHY_KEY.into()).encrypt_block(&mut key);
    key
}

fn decrypt(bytes: &[u8], ids: &[String]) -> io::Result<Vec<u8>> {
    if bytes.len() < 32 || !bytes.len().is_multiple_of(16) || bytes.len() > MAX_XML + 32 {
        return Err(invalid("invalid ESFM size"));
    }
    let matches = |id: &str| {
        let key = trophy_key(id);
        let mut block = aes::cipher::Block::<Aes128>::try_from(&bytes[16..32]).unwrap();
        Aes128::new(&key).decrypt_block(&mut block);
        for (value, iv) in block.iter_mut().zip(&bytes[..16]) {
            *value ^= iv;
        }
        block.starts_with(b"<!--Sce-Np")
            || block.starts_with(b"<?xml")
            || block.starts_with(b"<trophyconf")
    };
    let known = ids.iter().find(|id| matches(id)).cloned();
    // Most FPKGs omit npbind.dat. Recover the public NPWR number using one XML block.
    // shortcut: fallback covers NPWR00000_00..NPWR99999_00; other suffixes need npbind.dat.
    let id = known
        .or_else(|| {
            (0..100_000)
                .map(|n| format!("NPWR{n:05}_00"))
                .find(|id| matches(id))
        })
        .ok_or_else(|| {
            invalid("trophy text decryption unavailable: no matching NP communication ID")
        })?;
    let key = trophy_key(&id);
    let mut data = bytes[16..].to_vec();
    cbc::Decryptor::<Aes128>::new_from_slices(&key, &bytes[..16])
        .map_err(|_| invalid("invalid ESFM key/IV"))?
        .decrypt_padded::<NoPadding>(&mut data)
        .map_err(|_| invalid("invalid ESFM encryption"))?;
    // Sony resources can include padding after the XML document.
    let close = b"</trophyconf>";
    let end = data
        .windows(close.len())
        .position(|w| w == close)
        .ok_or_else(|| invalid("ESFM decryption unavailable for package NP IDs"))?
        + close.len();
    data.truncate(end);
    Ok(data)
}

fn parse_set(path: &str, bytes: &[u8], ids: &[String]) -> TrophySet {
    match parse(bytes, ids) {
        Ok((title, trophies)) => TrophySet {
            path: path.into(),
            title,
            trophies,
            error: None,
        },
        Err(error) => TrophySet {
            path: path.into(),
            title: path.into(),
            trophies: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

fn parse(bytes: &[u8], ids: &[String]) -> io::Result<(String, Vec<Trophy>)> {
    let resources = resources(bytes)?;
    let mut definitions: Vec<_> = resources
        .iter()
        .filter(|r| {
            let name = r.name.to_ascii_uppercase();
            name.ends_with(".SFM") || name.ends_with(".ESFM") || name.ends_with(".XML")
        })
        .collect();
    definitions.sort_by_key(|r| {
        let name = r.name.to_ascii_uppercase();
        let rank = if name.starts_with("TROP_01.") {
            0
        } else if name.starts_with("TROP.") {
            1
        } else if name.starts_with("TROPCONF.") {
            2
        } else {
            3
        };
        (rank, name)
    });
    let resource = definitions
        .first()
        .ok_or_else(|| invalid("trophy definitions missing"))?;
    let decrypted;
    let xml = if resource.encrypted || resource.name.to_ascii_uppercase().ends_with(".ESFM") {
        decrypted = decrypt(resource.bytes, ids)?;
        &decrypted[..]
    } else {
        resource.bytes
    };
    if xml.len() > MAX_XML {
        return Err(invalid("trophy XML exceeds size limit"));
    }
    let xml = std::str::from_utf8(xml)
        .map_err(|_| invalid("trophy XML is not UTF-8"))?
        .trim_end_matches('\0');
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 100_000,
            ..Default::default()
        },
    )
    .map_err(|e| invalid(format!("invalid trophy XML: {e}")))?;
    let root = doc.root_element();
    if !root.has_tag_name("trophyconf") {
        return Err(invalid("missing trophyconf element"));
    }
    let text = |node: roxmltree::Node<'_, '_>, tag: &str| -> io::Result<String> {
        node.children()
            .find(|n| n.has_tag_name(tag))
            .map(|n| n.text().unwrap_or_default().to_owned())
            .ok_or_else(|| invalid(format!("missing trophy {tag}")))
    };
    let title = text(root, "title-name")?;
    let mut trophies = Vec::new();
    let mut seen = BTreeSet::new();
    for node in root.children().filter(|n| n.has_tag_name("trophy")) {
        if trophies.len() >= 4096 {
            return Err(invalid("too many trophies"));
        }
        let id: u32 = node
            .attribute("id")
            .ok_or_else(|| invalid("missing trophy ID"))?
            .parse()
            .map_err(|_| invalid("invalid trophy ID"))?;
        if !seen.insert(id) {
            return Err(invalid("duplicate trophy ID"));
        }
        let grade = match node.attribute("ttype") {
            Some("B") => "Bronze",
            Some("S") => "Silver",
            Some("G") => "Gold",
            Some("P") => "Platinum",
            _ => return Err(invalid("invalid trophy grade")),
        };
        let hidden = match node.attribute("hidden") {
            Some("yes") => true,
            Some("no") => false,
            _ => return Err(invalid("invalid trophy hidden flag")),
        };
        let group = node
            .attribute("gid")
            .unwrap_or("0")
            .parse()
            .map_err(|_| invalid("invalid trophy group"))?;
        let icon_name = format!("TROP{id:03}.PNG");
        let icon = resources
            .iter()
            .find(|r| {
                r.name.eq_ignore_ascii_case(&icon_name) && !r.encrypted && r.bytes.len() <= MAX_XML
            })
            .map(|r| r.bytes.to_vec());
        trophies.push(Trophy {
            id,
            name: text(node, "name")?,
            description: text(node, "detail")?,
            grade: grade.into(),
            hidden,
            group,
            icon,
        });
    }
    trophies.sort_by_key(|t| t.id);
    Ok((title, trophies))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeEncrypt, block_padding::Pkcs7};

    const XML: &str = "<?xml version=\"1.0\"?><trophyconf><title-name>Test &amp; Set</title-name><trophy id=\"001\" ttype=\"G\" hidden=\"yes\" gid=\"002\"><name>Win &lt;3</name><detail><![CDATA[Do <something>.]]></detail></trophy><trophy id=\"000\" ttype=\"P\" hidden=\"no\"><name>All</name><detail>Earn all.</detail></trophy></trophyconf>";

    fn archive(version: u32, files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let header = if version == 3 { 96 } else { 64 };
        let mut bytes = vec![0; header + files.len() * 64];
        bytes[..4].copy_from_slice(&0xdca24d00u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&version.to_be_bytes());
        bytes[16..20].copy_from_slice(&(files.len() as u32).to_be_bytes());
        bytes[20..24].copy_from_slice(&64u32.to_be_bytes());
        for (i, (name, data, flag)) in files.iter().enumerate() {
            let offset = bytes.len() as u64;
            let start = header + i * 64;
            bytes[start..start + name.len()].copy_from_slice(name.as_bytes());
            bytes[start + 32..start + 40].copy_from_slice(&offset.to_be_bytes());
            bytes[start + 40..start + 48].copy_from_slice(&(data.len() as u64).to_be_bytes());
            bytes[start + 48..start + 52].copy_from_slice(&flag.to_be_bytes());
            bytes.extend_from_slice(data);
        }
        let len = bytes.len() as u64;
        bytes[8..16].copy_from_slice(&len.to_be_bytes());
        bytes
    }

    fn encrypted(xml: &str, id: &str) -> Vec<u8> {
        let iv = [0x12; 16];
        let mut data = xml.as_bytes().to_vec();
        data.resize(data.len() + 16, 0);
        let key = trophy_key(id);
        let data = cbc::Encryptor::<Aes128>::new(&key, &iv.into())
            .encrypt_padded::<Pkcs7>(&mut data, xml.len())
            .unwrap();
        let mut bytes = iv.to_vec();
        bytes.extend_from_slice(data);
        bytes
    }

    #[test]
    fn ps3_plaintext_definitions_icons_and_english_preference() {
        for version in [1, 2] {
            let bytes = archive(
                version,
                &[
                    ("TROPCONF.SFM", b"invalid default", 0),
                    ("TROP_01.SFM", XML.as_bytes(), 0),
                    ("TROP001.PNG", b"icon", 0),
                ],
            );
            let (title, trophies) = parse(&bytes, &[]).unwrap();
            assert_eq!(title, "Test & Set");
            assert_eq!(trophies.len(), 2);
            assert_eq!(trophies[0].id, 0);
            assert_eq!(trophies[0].grade, "Platinum");
            assert!(!trophies[0].hidden);
            assert_eq!(trophies[1].name, "Win <3");
            assert_eq!(trophies[1].description, "Do <something>.");
            assert_eq!(trophies[1].group, 2);
            assert!(trophies[1].hidden);
            assert_eq!(trophies[1].icon.as_deref(), Some(b"icon".as_slice()));
        }
    }

    #[test]
    fn ps4_esfm_with_binding_and_missing_binding_recovery() {
        // Independent OpenSSL AES-128-ECB oracle for zero-padded NPWR00042_01.
        assert_eq!(
            trophy_key("NPWR00042_01").as_slice(),
            &[
                0xfe, 0x7b, 0x0f, 0x3b, 0xf3, 0xb4, 0xa5, 0x5a, 0x86, 0x94, 0x06, 0xb7, 0x7b, 0x54,
                0xfd, 0x65
            ]
        );
        for (id, ids) in [
            ("NPWR00007_00", vec![]),
            ("NPWR00042_01", vec!["NPWR00042_01".into()]),
        ] {
            let esfm = encrypted(XML, id);
            let bytes = archive(3, &[("TROP.ESFM", &esfm, 3)]);
            let (title, trophies) = parse(&bytes, &ids).unwrap();
            assert_eq!(title, "Test & Set");
            assert_eq!(trophies.len(), 2);
        }
        assert!(decrypt(&[0; 17], &[]).is_err());
        assert!(decrypt(&[0; 32], &[]).is_err());
    }

    #[test]
    fn malformed_trp_and_xml_are_errors_not_panics() {
        let good = archive(2, &[("TROP.SFM", XML.as_bytes(), 0)]);
        for end in 0..good.len() {
            assert!(parse(&good[..end], &[]).is_err());
        }
        for (offset, value) in [(4, 99u32), (16, u32::MAX), (20, 1), (96, u32::MAX)] {
            let mut bytes = good.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(parse(&bytes, &[]).is_err());
        }
        for xml in [XML.replace("id=\"001\"", "id=\"000\""), XML.replace("ttype=\"G\"", "ttype=\"X\""), XML.replace("hidden=\"yes\"", "hidden=\"maybe\""), "<!DOCTYPE trophyconf [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><trophyconf>&x;</trophyconf>".into()] {
            assert!(parse(&archive(2, &[("TROP.SFM", xml.as_bytes(), 0)]), &[]).is_err());
        }
        let mut overlap = archive(
            2,
            &[
                ("TROP.SFM", XML.as_bytes(), 0),
                ("TROP001.PNG", b"image", 0),
            ],
        );
        let offset = overlap[96..104].to_vec();
        overlap[160..168].copy_from_slice(&offset);
        assert!(parse(&overlap, &[]).is_err());
        let failed = parse_set("bad.trp", b"bad", &[]);
        assert!(failed.error.is_some());
        assert!(failed.trophies.is_empty());
    }

    #[test]
    fn binding_validation_and_resource_limits() {
        let mut binding = vec![0; 128];
        binding[..4].copy_from_slice(&0xd294a018u32.to_be_bytes());
        binding[24..32].copy_from_slice(&1u64.to_be_bytes());
        for (kind, data) in [
            (0x10u16, b"NPWR00042_01\0".as_slice()),
            (0x11, b"00"),
            (0x12, b""),
            (0x13, b""),
        ] {
            binding.extend_from_slice(&kind.to_be_bytes());
            binding.extend_from_slice(&(data.len() as u16).to_be_bytes());
            binding.extend_from_slice(data);
        }
        binding.resize(binding.len() + 0x98, 0);
        assert_eq!(np_ids(&binding).unwrap(), ["NPWR00042_01"]);
        assert!(np_ids(&binding[..135]).is_err());
        let mut total = MAX_TOTAL;
        assert!(check_budget(1, &mut total).is_err());
        assert!(bounded(b"12345".as_slice(), 4).is_err());
    }

    #[test]
    fn both_package_readers_report_no_sets_for_trophyless_fixtures() {
        for name in ["ps3-list-explicit.pkg", "ps4-selection.pkg"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(name);
            assert!(read(&path).unwrap().is_empty());
        }
    }
}
