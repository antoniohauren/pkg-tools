using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
using LibOrbisPkg.PKG;
using LibOrbisPkg.PFS;
using LibOrbisPkg.Util;

// .NET 8 supplies the same extension as upstream's .NET Framework shim.
namespace LibOrbisPkg.PFS
{
    static class Net8Tuple
    {
        public static void Deconstruct<T, U>(this Tuple<T, U> value, out T a, out U b)
        { a = value.Item1; b = value.Item2; }
    }
}

// Trusted fixtures only: upstream is an interoperability oracle, not a hardened parser.
class Extraction
{
    static readonly SortedDictionary<string, object> Files = new(StringComparer.Ordinal);
    static readonly SortedSet<string> Dirs = new(StringComparer.Ordinal);
    static void SelfTest()
    {
        // A >8 KiB compressed block reproduces .NET 8's permitted short Read.
        var raw = new byte[65536];
        new Random(12345).NextBytes(raw.AsSpan(0, 16384));
        for (int i = 1; i < 4; i++) raw.AsSpan(0, 16384).CopyTo(raw.AsSpan(i * 16384));
        using var compressed = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.Optimal, true)) z.Write(raw);
        if (compressed.Length <= 8192 || compressed.Length >= raw.Length) throw new Exception("Bad regression fixture");
        using var image = new MemoryStream();
        using (var w = new BinaryWriter(image, System.Text.Encoding.UTF8, true)) {
            w.Write(0x43534650); w.Write(0); w.Write(6); w.Write(65536);
            w.Write(65536L); w.Write(48L); w.Write(64L); w.Write(65536L);
            w.Write(64L); w.Write(64L + compressed.Length); w.Write(compressed.ToArray());
        }
        var decoded = new byte[65536];
        new PFSCReader(new LibOrbisPkg.Util.StreamReader(image)).Read(0, decoded, 0, decoded.Length);
        if (!decoded.SequenceEqual(raw)) throw new Exception("PFSC short-read regression");

        var key = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var seed = Enumerable.Repeat((byte)0x13, 16).ToArray();
        var keys = Crypto.PfsGenEncKey(key, seed);
        var ciphertext = new byte[65536 + 4096];
        for (int i = 0; i < 4096; i++) ciphertext[65536 + i] = (byte)(i % 251);
        var xts = new XtsDecryptReader(new LibOrbisPkg.Util.StreamReader(new MemoryStream(ciphertext)), keys.Item2, keys.Item1);
        var sector = new byte[4096]; xts.Read(65536, sector, 0, sector.Length);
        Console.WriteLine("XTS sector 16 SHA256: " + Convert.ToHexString(SHA256.HashData(sector)).ToLowerInvariant());
        Console.WriteLine("Reference self-test passed");
    }
    static void Walk(PfsReader.Dir dir, string path)
    {
        foreach (var node in dir.children)
        {
            string name = path + node.name;
            if (node is PfsReader.Dir d)
            {
                Dirs.Add(name);
                Walk(d, name + "/");
            }
            else if (node is PfsReader.File f)
            {
                if (f.size != f.compressed_size)
                    throw new Exception("Unresolved per-file compression: " + name);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buf = new byte[65536];
                var view = f.GetView();
                for (long pos = 0; pos < f.size; pos += buf.Length)
                {
                    int n = (int)Math.Min(buf.Length, f.size - pos);
                    view.Read(pos, buf, 0, n);
                    hash.AppendData(buf, 0, n);
                }
                Files.Add(name, new { size = f.size, sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant() });
            }
        }
    }
    static void Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test") { SelfTest(); return; }
        using var input = File.OpenRead(args[0]);
        var pkg = new PkgReader(input).ReadPkg();
        var key = pkg.GetEkpfs();
        if (key == null) throw new Exception("Fake key recovery failed");
        bool passcodeDigestMatches = pkg.CheckEkpfs(key);
        var dk3 = Crypto.RSA2048Decrypt(pkg.EntryKeys.Keys[3].key, RSAKeyset.PkgDerivedKey3Keyset);
        if (!pkg.CheckDerivedKey(dk3, 3)) throw new Exception("DK3 digest mismatch");
        using var mm = MemoryMappedFile.CreateFromFile(input, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, true);
        // Recovered IMAGE_KEY is already seed-transformed for new-crypt packages.
        // LibOrbisPkg's flag transform is for a passcode-derived key; see flatz keymgr.c.
        var outer = new PfsReader(mm.CreateViewAccessor((long)pkg.Header.pfs_image_offset, (long)pkg.Header.pfs_image_size, MemoryMappedFileAccess.Read), 0, key);
        var image = outer.GetFile("pfs_image.dat");
        var pfsc = new PFSCReader(image.GetView());
        var inner = new PfsReader(pfsc);
        Walk(inner.GetURoot(), "");
        // Application resources: retain runtime PlayGo files, omit container/license artifacts.
        foreach (var meta in pkg.Metas.Metas)
        {
            if ((uint)meta.id < 0x1000 || !EntryNames.IdToName.TryGetValue(meta.id, out var name)) continue;
            input.Position = meta.DataOffset;
            int stored = checked((int)meta.DataSize);
            byte[] bytes = new byte[stored];
            input.ReadExactly(bytes);
            if (meta.Encrypted) {
                if (stored % 16 != 0) throw new Exception("Oracle requires aligned encrypted application metadata");
                bytes = Entry.Decrypt(bytes, pkg, meta);
            }
            name = "sce_sys/" + name;
            string parent = name;
            while (parent.Contains('/')) { parent = parent.Substring(0, parent.LastIndexOf('/')); Dirs.Add(parent); }
            Files.Add(name, new { size = (long)meta.DataSize, sha256 = Convert.ToHexString(SHA256.HashData(bytes.AsSpan(0, (int)meta.DataSize))).ToLowerInvariant() });
        }
        Console.WriteLine(JsonSerializer.Serialize(new {
            passcodeDigestMatches, outerMode = (int)outer.Header.Mode, innerMode = (int)inner.Header.Mode,
            outerInodes = outer.Header.DinodeCount, innerInodes = inner.Header.DinodeCount,
            pfscBlockSize = pfsc.SectorSize, files = Files, directories = Dirs
        }));
    }
}
