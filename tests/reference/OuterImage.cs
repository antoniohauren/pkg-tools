using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using LibOrbisPkg.PFS;
using LibOrbisPkg.Util;

// Original public synthetic inputs. No reference key declarations are exercised.
class OuterImage
{
    static void Main(string[] args)
    {
        var passcode = new string(Enumerable.Range(0, 32).Select(i => (char)(0x21 + i)).ToArray());
        var derived = Enumerable.Range(0, 7).Select(i => Crypto.ComputeKeys("ZZ0000-CUSA00000_00-SYNTHETIC0000000", passcode, (uint)i)).ToArray();
        Action<byte[], string> check = (bytes, expected) => {
            if (BitConverter.ToString(Crypto.Sha256(bytes)).Replace("-", "").ToLowerInvariant() != expected)
                throw new Exception("Legacy known-answer mismatch");
        };
        check(derived.SelectMany(v => v).ToArray(), "5d9db1f987ef961cb0f904b8a7637a4be7e1bd3836f002dcb475eb0d2fce8473");
        for (int variant = 0; variant < 2; variant++)
        {
            var testSeed = Enumerable.Range(0, 16).Select(i => variant == 0 ? (byte)0 : (byte)i).ToArray();
            var enc = Crypto.PfsGenCryptoKey(derived[1], testSeed, 1);
            var signing = Crypto.PfsGenSignKey(derived[1], testSeed);
            check(enc.Concat(signing).ToArray(), variant == 0 ? "b02114543bfb205623678c02f21df7e9619816e0d22bdb6da979a20d68a38914" : "53c45751d99c9076986bf98b72e9e094cbac6e97faeee65bfc5ca85961ed97e1");
            var plain = Enumerable.Range(0, 4096).Select(i => (byte)(i % 251)).ToArray();
            var padded = new byte[65536]; Array.Copy(plain, padded, plain.Length);
            check(Crypto.HmacSha256(signing, padded), variant == 0 ? "188040fd26cada2fb26e36e22fcbfc8ee657f7e7ceb0da9b04263b51d417aae5" : "92b7aceb3bbfdc8f96852005816c4bbf6532fa042dc803d445342869dde6b78f");
            new XtsBlockTransform(enc.Skip(16).ToArray(), enc.Take(16).ToArray()).EncryptSector(plain, 19);
            check(plain, variant == 0 ? "828b51da8f9f02e413b94ae8040419b20f15de95229ca73d77a949b217f4e2c5" : "9cd2b41a557c5c3e1d50cb27453f8cb99ba7b083c0f8bb499608f41e7d56330a");
        }
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var seed = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        if (BitConverter.ToString(Crypto.PfsGenCryptoKey(key, seed, 1)).Replace("-", "").ToLowerInvariant() !=
            "76be34e86d4a3793c4f2af46f63879f41b876753b3609b58c497052fc4f416b6" ||
            BitConverter.ToString(Crypto.PfsGenSignKey(key, seed)).Replace("-", "").ToLowerInvariant() !=
            "e9d9d5c076c2b31e0a95557f14f36f20b99cfcc788f7c09e640ada5f49eeb7bd")
            throw new Exception("Independent PFS derivation mismatch");
        foreach (var path in args)
        {
            using var map = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using var view = map.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            var outer = new PfsReader(view, ekpfs: key);
            var image = outer.GetAllFiles().Single();
            if (image.name != "pfs_image.dat" || outer.Header.Mode != (PfsMode.Signed | PfsMode.Encrypted | PfsMode.UnknownFlagAlwaysSet))
                throw new Exception("Outer manifest mismatch");
            var inner = new PfsReader(new PFSCReader(image.GetView()));
            var file = inner.GetAllFiles().Single();
            if (file.name != "pattern.bin" || (file.size != 13L * 65536 + 1 && file.size != 1835L * 65536 + 1))
                throw new Exception("Inner manifest mismatch");
            var data = file.GetView();
            var buffer = new byte[65536];
            for (long offset = 0; offset < file.size; offset += buffer.Length)
            {
                int count = (int)Math.Min(buffer.Length, file.size - offset);
                data.Read(offset, buffer, 0, count);
                for (int i = 0; i < count; i++) if (buffer[i] != (offset + i) % 251) throw new Exception("Payload mismatch");
            }
            Console.WriteLine("PASS: independent LibOrbisPkg signed/encrypted outer -> PFSC -> inner bytes");
        }
        Console.WriteLine("PASS: pinned LibOrbisPkg PFS derivation known answers");
    }
}
