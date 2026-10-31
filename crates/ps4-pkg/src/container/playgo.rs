use super::{BLOCK, BaseContainerLayout, invalid};

/// Default one-scenario manifest. XML semantics match pinned L, not its BOM/CRLF.
/// Use this exact byte length when planning record 0x1003.
pub const DEFAULT_PLAYGO_MANIFEST: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n",
    "<psproject fmt=\"playgo-manifest\" version=\"0990\"><volume>",
    "<chunk_info chunk_count=\"1\" scenario_count=\"1\"><scenarios default_id=\"0\">",
    "<scenario id=\"0\" type=\"sp\" initial_chunk_count=\"1\" label=\"Scenario #0\">0</scenario>",
    "</scenarios></chunk_info></volume></psproject>\n"
);

impl BaseContainerLayout {
    /// One default chunk/scenario only (Chunk #0 / Scenario #0). Caller must reject
    /// custom scheduling/labels, and ensure content ID agrees with final SFO/header.
    /// Physical size is the whole package; inner size is clear PFS, NOT PFSC.
    pub fn playgo_dat(&self, content_id: &str, inner_pfs_size: u64) -> std::io::Result<[u8; 416]> {
        if !crate::gp4::valid_content_id(content_id) {
            return Err(invalid("invalid PlayGo content ID"));
        }
        if inner_pfs_size == 0
            || !inner_pfs_size.is_multiple_of(BLOCK)
            || inner_pfs_size > self.pfs_range().end - self.pfs_range().start
        {
            return Err(invalid(
                "inner PFS size must be nonzero, 64-KiB aligned and fit outer image",
            ));
        }
        let mut dat = [0; 416];
        dat[..4].copy_from_slice(b"plgo");
        for offset in [8, 10, 12, 14, 22] {
            dat[offset..offset + 2].copy_from_slice(&1u16.to_le_bytes());
        }
        dat[16..20].copy_from_slice(&416u32.to_le_bytes());
        dat[32..64].fill(0xff);
        dat[64..100].copy_from_slice(content_id.as_bytes());
        for (index, value) in [
            256u32, 32, 288, 2, 304, 9, 320, 16, 352, 32, 384, 2, 400, 12, 336, 16,
        ]
        .into_iter()
        .enumerate()
        {
            let start = 0xc0 + index * 4;
            dat[start..start + 4].copy_from_slice(&value.to_le_bytes());
        }
        dat[0x100] = 0x80;
        dat[0x102] = 3;
        dat[0x10e..0x110].copy_from_slice(&1u16.to_le_bytes());
        dat[0x110..0x118].fill(0xff);
        dat[0x130..0x138].copy_from_slice(b"Chunk #0");
        dat[0x148..0x150].copy_from_slice(&self.package_size().to_le_bytes());
        dat[0x158..0x160].copy_from_slice(&inner_pfs_size.to_le_bytes());
        dat[0x160] = 1;
        dat[0x174..0x176].copy_from_slice(&1u16.to_le_bytes());
        dat[0x176..0x178].copy_from_slice(&1u16.to_le_bytes());
        dat[0x190..0x19b].copy_from_slice(b"Scenario #0");
        Ok(dat)
    }
}
