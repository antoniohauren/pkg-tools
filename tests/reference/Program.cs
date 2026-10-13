// Test adapter only. The independently checked-out reference sources are unmodified.
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using LibOrbisPkg.PKG;
using LibOrbisPkg.SFO;

using var stream = File.OpenRead(args[0]);
var reader = new PkgReader(stream);
var h = reader.ReadHeader();
stream.Position = h.entry_table_offset;
var entries = Enumerable.Range(0, checked((int)h.entry_count))
    .Select(_ => MetaEntry.Read(stream)).ToArray();
var sfoEntry = entries.Single(e => e.id == EntryId.PARAM_SFO);
if (sfoEntry.Encrypted) throw new NotSupportedException("Oracle expects plaintext SFO");
stream.Position = sfoEntry.DataOffset;
var sfo = ParamSfo.FromStream(stream);
Console.WriteLine(JsonSerializer.Serialize(new {
    header = new {
        flags = (uint)h.flags, content_id = h.content_id,
        drm_type = (uint)h.drm_type, content_type = (uint)h.content_type,
        content_flags = (uint)h.content_flags, entry_count = h.entry_count,
        entry_table_offset = h.entry_table_offset, body_offset = h.body_offset,
        body_size = h.body_size, pfs_flags = h.pfs_flags, pfs_offset = h.pfs_image_offset,
        pfs_size = h.pfs_image_size, package_size = h.package_size
    },
    entries = entries.Select(e => new {
        id = (uint)e.id, name_offset = e.NameTableOffset, flags1 = e.Flags1,
        flags2 = e.Flags2, offset = e.DataOffset, size = e.DataSize,
        encrypted = e.Encrypted, key_index = e.KeyIndex
    }),
    sfo = sfo.Values.Select(v => new {
        key = v.Name, format = (ushort)v.Type, max_length = v.MaxLength,
        raw_hex = Convert.ToHexString(v.ToByteArray()).ToLowerInvariant(),
        value = v is IntegerValue n ? (object)unchecked((uint)n.Value) :
            v is Utf8Value text ? text.Value : null
    })
}));
