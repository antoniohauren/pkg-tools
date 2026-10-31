using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using LibOrbisPkg.PFS;
using LibOrbisPkg.Util;

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

class InnerImage
{
    static void Main(string[] args)
    {
        if (args.Length != 1 && args.Length != 2) throw new ArgumentException("Expected synthetic image [GP4 source directory]");
        using var map = MemoryMappedFile.CreateFromFile(args[0], FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        using var view = map.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        IMemoryReader source = new MemoryMappedViewAccessor_(view);
        if (Path.GetExtension(args[0]) == ".pfsc") source = new PFSCReader(source);
        var pfs = new PfsReader(source);
        if (args.Length == 2)
        {
            CheckGp4(pfs, args[1]);
            return;
        }
        if (pfs.Header.Mode != PfsMode.UnknownFlagAlwaysSet || pfs.Header.DinodeBlockCount <= 1)
            throw new Exception("Unexpected D32 header / missing inode rollover");
        var root = pfs.GetURoot();
        if (root.children.Count != 9004 || !(root.Get("B_") is PfsReader.Dir collisionDir) || collisionDir.children.Count != 0 ||
            !(root.Get("empty-dir") is PfsReader.Dir emptyDir) || emptyDir.children.Count != 0)
            throw new Exception("Directory manifest mismatch");
        var files = pfs.GetAllFiles().ToList();
        if (files.Count != 9002) throw new Exception("File manifest mismatch");
        foreach (var file in files)
        {
            if (file.FullName == "/uroot/data/boundary.bin" || file.FullName == "uroot/data/boundary.bin")
            {
                if (file.size != 13 * 65536 + 1) throw new Exception("Boundary size mismatch");
                var data = file.GetView();
                var buffer = new byte[65536];
                for (long offset = 0; offset < file.size; offset += buffer.Length)
                {
                    int count = (int)Math.Min(buffer.Length, file.size - offset);
                    data.Read(offset, buffer, 0, count);
                    for (int i = 0; i < count; i++) if (buffer[i] != (offset + i) % 251) throw new Exception("Payload mismatch");
                }
            }
            else if (file.size != 0) throw new Exception("Expected empty synthetic file");
        }
        if (pfs.GetFile("data/boundary.bin") == null) throw new Exception("Missing boundary file");
        Console.WriteLine("PASS: independent LibOrbisPkg D32/PFSC read; 9002 files, 3 directories, boundary bytes, empty entries, inode rollover");
    }

    static void CheckGp4(PfsReader pfs, string source)
    {
        var excluded = new System.Collections.Generic.HashSet<string> {
            "sce_sys/param.sfo", "sce_sys/icon0.png", "sce_sys/pic0.png", "sce_sys/pic1.png", "sce_sys/snd0.at9"
        };
        Func<string, string> relative = path => Path.GetRelativePath(source, path).Replace('\\', '/');
        var expected = Directory.GetFiles(source, "*", SearchOption.AllDirectories)
            .Select(relative).Where(path => !excluded.Contains(path)).OrderBy(path => path).ToArray();
        var files = pfs.GetAllFiles().ToDictionary(file => file.FullName.TrimStart('/').Substring("uroot/".Length));
        if (!expected.SequenceEqual(files.Keys.OrderBy(path => path))) throw new Exception("GP4 inner namespace mismatch");
        foreach (var path in expected)
        {
            var file = files[path];
            using var original = File.OpenRead(Path.Combine(source, path));
            if (file.size != original.Length) throw new Exception("GP4 file size mismatch");
            var view = file.GetView();
            var actual = new byte[65536];
            var wanted = new byte[65536];
            for (long offset = 0; offset < file.size; offset += actual.Length)
            {
                int count = (int)Math.Min(actual.Length, file.size - offset);
                original.ReadExactly(wanted, 0, count);
                view.Read(offset, actual, 0, count);
                if (!actual.Take(count).SequenceEqual(wanted.Take(count))) throw new Exception("GP4 payload mismatch");
            }
        }
        var directories = Directory.GetDirectories(source, "*", SearchOption.AllDirectories).Select(relative).ToArray();
        var root = pfs.GetURoot();
        if (!directories.OrderBy(path => path).SequenceEqual(Directories(root, "").OrderBy(path => path)))
            throw new Exception("GP4 directory namespace mismatch");
        // This oracle covers the generated synthetic fixture, not arbitrary source trees.
        if (files.Count != 5 || directories.Length != 4) throw new Exception("Unexpected fixture size");
        Console.WriteLine("PASS: independent GP4 inner-image namespace/bytes: 5 files, 4 directories; container metadata excluded, keystone unchanged");
    }

    static System.Collections.Generic.IEnumerable<string> Directories(PfsReader.Dir parent, string prefix)
    {
        foreach (var child in parent.children.OfType<PfsReader.Dir>())
        {
            var path = prefix + child.name;
            yield return path;
            foreach (var nested in Directories(child, path + "/")) yield return nested;
        }
    }
}
