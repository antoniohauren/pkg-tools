using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using LibOrbisPkg.PKG;
using LibOrbisPkg.PFS;
using LibOrbisPkg.SFO;

// Resolve upstream's .NET Framework tuple shim against .NET 8.
namespace LibOrbisPkg.PFS
{
    static class Net8Tuple
    {
        public static void Deconstruct<T, U>(this Tuple<T, U> value, out T a, out U b)
        { a = value.Item1; b = value.Item2; }
    }
}

namespace LibOrbisPkg.PKG
{
    static class Net8Tuple
    {
        public static void Deconstruct<T, U>(this Tuple<T, U> value, out T a, out U b)
        { a = value.Item1; b = value.Item2; }
    }
}

// Fixed synthetic inputs only. Never use this adapter to rebuild a game.
class Authoring
{
    static void ValidateSynthetic(string input, string output)
    {
        using var source = File.OpenRead(input);
        if (source.Length < 0x100000 || source.Length > 16 * 1024 * 1024)
            throw new Exception("Expected bounded synthetic package");
        var header = new byte[0x70];
        source.ReadExactly(header);
        if (System.Text.Encoding.ASCII.GetString(header, 0x40, 36) != "ZZ0000-CUSA00000_00-SYNTHETIC0000000")
            throw new Exception("Only the original synthetic fixture is accepted");
        source.Position = 0;
        var pkg = new PkgReader(source).ReadPkg();
        var results = new List<object>();
        bool failed = false;
        foreach (var validation in new PkgValidator(pkg).Validations(source))
        {
            var result = validation.Validate();
            results.Add(new { name = validation.Name, type = validation.Type.ToString(), location = validation.Location, result = result.ToString() });
            failed |= result != PkgValidator.ValidationResult.Ok;
        }
        using var destination = new FileStream(output, FileMode.CreateNew);
        JsonSerializer.Serialize(destination, new { results });
        if (failed || results.Count == 0)
        {
            Console.Error.WriteLine("Synthetic validator returned Fail/NoKey or no checks");
            Environment.ExitCode = 1;
            return;
        }
        Console.WriteLine("Every emitted pinned synthetic validation returned Ok");
    }

    // GP4 interchange only: constructing this tree does not build a package.
    static void CheckGp4(string input, string output)
    {
        using var source = File.OpenRead(input);
        var project = LibOrbisPkg.GP4.Gp4Project.ReadFrom(source);
        if (project.Format != "gp4" || project.version != 1000 ||
            project.volume.Type != LibOrbisPkg.GP4.VolumeType.pkg_ps4_app ||
            project.volume.Package.StorageType != "digital50" || project.volume.Package.AppType != "full" ||
            project.files.ImageNum != 0 || project.volume.chunk_info.chunk_count != 1 ||
            project.volume.chunk_info.scenario_count != 1)
            throw new Exception("Unexpected base GP4 profile");
        var tree = PfsProperties.BuildFSTree(project, Path.GetDirectoryName(input));
        var paths = new List<string>();
        var directories = new List<string>();
        void Walk(FSDir dir, string prefix)
        {
            foreach (var file in dir.Files) paths.Add(prefix + file.name);
            foreach (var child in dir.Dirs)
            {
                directories.Add(prefix + child.name);
                Walk(child, prefix + child.name + "/");
            }
        }
        Walk(tree, "");
        if (!paths.OrderBy(p => p).SequenceEqual(project.files.Items.Select(f => f.TargetPath).OrderBy(p => p)))
            throw new Exception("GP4 tree mapping mismatch");
        using var destination = new FileStream(output, FileMode.CreateNew);
        LibOrbisPkg.GP4.Gp4Project.WriteTo(project, destination);
        Console.WriteLine(JsonSerializer.Serialize(new { files = paths.Count, directories = directories.Count, profile = "base GP4 interchange only" }));
    }

    static void Main(string[] args)
    {
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
        if (args.Length == 3 && args[0] == "--validate-synthetic")
        {
            ValidateSynthetic(Path.GetFullPath(args[1]), Path.GetFullPath(args[2]));
            return;
        }
        if (args.Length == 2 && args[0] == "--crypto")
        {
            // Only the fixed 1184-byte synthetic vector artifact, never game/key files.
            using var vectorInput = File.OpenRead(args[1]);
            if (vectorInput.Length != 1184) throw new Exception("Expected synthetic crypto vectors");
            byte[] Read(int size) { var data = new byte[size]; vectorInput.ReadExactly(data); return data; }
            var modulus = Read(256);
            var message = Read(32);
            var padded = Read(256);
            var wrapped = Read(256);
            var native = LibOrbisPkg.Util.Crypto.RSA2048EncryptKey(modulus, message);
            if (!native.SequenceEqual(wrapped)) throw new Exception("Deterministic wrapping mismatch");
            // Separate raw public exponentiation checks all padding bytes, not roundtrip.
            var integer = new System.Numerics.BigInteger(padded, true, true);
            var n = new System.Numerics.BigInteger(modulus, true, true);
            var raw = System.Numerics.BigInteger.ModPow(integer, 65537, n).ToByteArray(true, true);
            if (!raw.SequenceEqual(wrapped.Skip(256 - raw.Length))) throw new Exception("Padding mismatch");
            for (int i = 0; i < 4; i++)
            {
                var record = Read(32);
                var plain = Read(32);
                var encrypted = Read(32);
                var index = (record[14] >> 4) & 15;
                var derived = LibOrbisPkg.Util.Crypto.ComputeKeys(
                    "ZZ0000-CUSA00000_00-SYNTHETIC0000000",
                    new string(Enumerable.Range(0x21, 32).Select(x => (char)x).ToArray()), (uint)index);
                var material = SHA256.HashData(record.Concat(derived).ToArray());
                var actual = new byte[32];
                LibOrbisPkg.Util.Crypto.AesCbcCfb128Encrypt(actual, plain, plain.Length,
                    material.Skip(16).ToArray(), material.Take(16).ToArray());
                if (!actual.SequenceEqual(encrypted)) throw new Exception("Metadata CBC mismatch");
            }
            Console.WriteLine("PASS: pinned deterministic wrapping/padding and four synthetic metadata CBC vectors");
            return;
        }
        if (args.Length == 3 && args[0] == "--gp4")
        {
            CheckGp4(Path.GetFullPath(args[1]), Path.GetFullPath(args[2]));
            return;
        }
        bool zeroSynthetic = args.Length == 2 && args[0] == "--synthetic-zero-passcode";
        if (args.Length != 1 && !zeroSynthetic) throw new ArgumentException("Expected new output directory or --synthetic-zero-passcode NEW_DIRECTORY");
        string output = Path.GetFullPath(args[zeroSynthetic ? 1 : 0]);
        if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Output already exists");
        Directory.CreateDirectory(output);
        var root = new FSDir();
        var system = new FSDir { name = "sce_sys", Parent = root };
        var data = new FSDir { name = "data", Parent = root };
        root.Dirs.AddRange(new[] { system, data, new FSDir { name = "empty-dir", Parent = root } });
        var expected = new SortedDictionary<string, object>(StringComparer.Ordinal);
        void Add(FSDir parent, string name, byte[] bytes)
        {
            parent.Files.Add(new FSFile(s => s.Write(bytes), name, bytes.Length) { Parent = parent });
            string path = parent == root ? name : parent.name + "/" + name;
            expected.Add(path, new { size = bytes.Length, sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() });
        }
        const string contentId = "ZZ0000-CUSA00000_00-SYNTHETIC0000000";
        var sfo = ParamSfo.DefaultGD;
        sfo["CONTENT_ID"] = new Utf8Value("CONTENT_ID", contentId, 48);
        sfo["TITLE_ID"] = new Utf8Value("TITLE_ID", "CUSA00000", 12);
        sfo["TITLE"] = new Utf8Value("TITLE", "Synthetic authoring oracle - not runnable", 128);
        Add(system, "param.sfo", sfo.Serialize());
        // A sentinel, deliberately NOT a SELF or executable; no launch claim.
        Add(root, "eboot.bin", System.Text.Encoding.ASCII.GetBytes("SYNTHETIC: NOT EXECUTABLE\n"));
        Add(data, "empty.bin", Array.Empty<byte>());
        Add(data, "boundary.bin", Enumerable.Range(0, 65537).Select(i => (byte)(i % 251)).ToArray());
        var properties = new PkgProperties {
            VolumeType = LibOrbisPkg.GP4.VolumeType.pkg_ps4_app,
            ContentId = contentId,
            // Zero override is synthetic-only; normal disposable input is never logged.
            Passcode = zeroSynthetic ? new string('0', 32) : Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            TimeStamp = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            CreationDate = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            RootDir = root,
        };
        using (var file = new FileStream(Path.Combine(output, "synthetic.pkg"), FileMode.CreateNew))
            new PkgBuilder(properties).Write(file, _ => { });
        // Read serialized bytes again; validating the builder's in-memory object is insufficient.
        using var input = File.OpenRead(Path.Combine(output, "synthetic.pkg"));
        var pkg = new PkgReader(input).ReadPkg();
        if (zeroSynthetic && !pkg.CheckPasscode(new string('0', 32)))
            throw new Exception("Synthetic zero-passcode source readback failed");
        var original = sfo.Values.ToDictionary(v => v.Name);
        var authored = pkg.ParamSfo.ParamSfo;
        if (!authored.Values.Select(v => v.Name).OrderBy(n => n).SequenceEqual(
            original.Keys.Union(new[] { "PUBTOOLINFO", "PUBTOOLVER" }).OrderBy(n => n)))
            throw new Exception("Unexpected SFO key changes");
        foreach (var value in authored.Values.Where(v => v.Name != "PUBTOOLINFO" && v.Name != "PUBTOOLVER"))
        {
            var before = original[value.Name];
            if (value.Type != before.Type || value.MaxLength != before.MaxLength || !value.ToByteArray().SequenceEqual(before.ToByteArray()))
                throw new Exception("Unexpected SFO value change: " + value.Name);
        }
        var results = new List<object>();
        bool failed = false;
        foreach (var validation in new PkgValidator(pkg).Validations(input))
        {
            var result = validation.Validate();
            results.Add(new { name = validation.Name, type = validation.Type.ToString(), location = validation.Location, result = result.ToString() });
            failed |= result != PkgValidator.ValidationResult.Ok;
        }
        File.WriteAllText(Path.Combine(output, "validation.json"), JsonSerializer.Serialize(new {
            results,
            unverified = new[] { "unset/unknown general digests", "all signed-PFS block HMACs", "console installation/launch", "NP/trophy/save identity" }
        }));
        File.WriteAllText(Path.Combine(output, "expected.json"), JsonSerializer.Serialize(new {
            files = expected, directories = new[] { "data", "empty-dir", "sce_sys" },
            generated = new[] { "sce_sys/keystone", "sce_sys/playgo-chunk.dat", "sce_sys/playgo-chunk.sha", "sce_sys/playgo-manifest.xml" },
            modified = new[] { "sce_sys/param.sfo: PUBTOOLINFO and PUBTOOLVER" }
        }));
        if (failed) throw new Exception("Validation contains Fail or NoKey; see validation.json");
        Console.WriteLine("Synthetic package built; every emitted validator returned Ok");
    }
}
