using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace GRF.Core
{
    internal static class GravityResourceDecryptor
    {
        private static readonly byte[] HeaderKey = Hex("56fd7e712f6d36f55ca599e67b18107a");
        private static readonly byte[] HeaderIv = Hex("4ce8a1ae45b321607e4f26a4bb140c96");
        private static readonly byte[][] RegisteredProfiles =
        {
            Hex("2c942196406735fed0c6fc9e15b9480617196b534eaf25ac035081f2b6d4a37151cdaf6847786dd3e404032f8603383ec74920038a9e630407577e0b"),
            Hex("2a08da55410a5dd34ab5c1a404b167d9cd6b60e349fa8a6025bd0d282c0550bd4c606759c3dc9eb256b1455b743e81f9bc8a066e76b6054f11c1a301"),
            Hex("1e5ab522d97334c99be5413336177abe59e6778ce6d54aa3df2b2656b180defae67c0a11f554ce7615bfe6c41302fe059ce0ec6f59ec7ed3493b3d93"),
            Hex("58153206749f6d2a33a20d4e51c7f565b3c804c8d761717664db6b81ddbf54e14b077c728bad590a69e76ea0d3805ccb172835d21aa6ec46fd95298c")
        };

        public static byte[] DecryptResource(byte[] encryptedData, byte[] filePathBytes, int expectedDecompressedSize)
        {
            if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
            if (filePathBytes == null) throw new ArgumentNullException(nameof(filePathBytes));
            if (expectedDecompressedSize < 0)
                throw new ArgumentOutOfRangeException(nameof(expectedDecompressedSize));
            byte[] header = DecodeHeader(encryptedData, filePathBytes);
            if (U32(header, 4) != (uint)(encryptedData.Length - 104))
                throw Bad("Stored body length does not match the header.");
            if (U32(header, 12) != (uint)expectedDecompressedSize)
                throw Bad("Expected decompressed size does not match the header.");
            uint compression = (U32(header, 0) >> 16) & 255;
            if (compression != 0 && compression != 2)
                throw Bad("Unsupported compression selector.");
            byte[] body = DecodeBody(Slice(encryptedData, 104, encryptedData.Length - 104), filePathBytes, header);
            if (U32(header, 8) != (uint)body.Length)
                throw Bad("Decoded body length does not match the header.");
            byte[] output = compression == 2 ? DecodeLz4(body, expectedDecompressedSize) : body;
            if (output.Length != expectedDecompressedSize || !HashMatches(output, header))
                throw Bad("Resource output size or final hash validation failed.");
            return output;
        }

        private static byte[] GetKeyContext(byte[] header)
        {
            uint id = U32(header, 32);
            if (id == 0) return Slice(header, 36, 60);
            if (id > RegisteredProfiles.Length) throw Bad("Unsupported registered key ID.");
            byte[] context = (byte[])RegisteredProfiles[(int)id - 1].Clone();
            if ((U32(header, 0) & 0x01000000) != 0)
                XorRepeat(context, 0, Slice(header, 16, 16));
            return context;
        }

        private static byte[] DecodeBody(byte[] body, byte[] path, byte[] header)
        {
            uint flags = U32(header, 0);
            if (body.Length <= 128 && (uint)body.Length == U32(header, 8)) return body;
            if (flags == 0x00020000) return body;
            if (body.Length < 128) throw Bad("Truncated encrypted body.");
            if (flags == 0x00020001) return DecodeBranch1(body, path, header);
            switch (flags)
            {
                case 0x00020005: case 0x00020007: case 0x00020080: case 0x01020085:
                case 0x00000005: case 0x00000007: case 0x00000080: case 0x01000085:
                    break;
                default: throw Bad("Unsupported body flags.");
            }
            byte[] context = GetKeyContext(header), pathHash = Hash128(path);
            byte[] digest = Slice(header, 16, 16), stream;
            int tail = body.Length - 128;
            uint selector = flags & 255;
            if (selector == 0x80)
            {
                int start = tail >= 3072 ? 2048 : 0;
                int count = tail >= 3072 ? 1024 : tail & ~15;
                stream = DeriveStream(pathHash, digest, Slice(context, 49, 8));
                if (count != 0)
                {
                    byte[] plain = AesCbc(body, 128 + start, count, Slice(context, 44, 16), Slice(context, 28, 16));
                    Buffer.BlockCopy(plain, 0, body, 128 + start, count);
                }
                XorRepeat(body, 128, stream);
            }
            else if (selector == 5 || selector == 7)
            {
                int segment = Math.Min(tail, 1040);
                if (segment == 0 || (segment & 15) != 0) throw Bad("Invalid AES segment length.");
                byte[] key, iv;
                if (selector == 5)
                {
                    key = Slice(context, 0, 16); iv = Slice(context, 16, 16);
                    stream = DeriveStream(digest, pathHash, Slice(context, 48, 8));
                }
                else
                {
                    key = Slice(context, 28, 16); iv = Slice(context, 44, 16);
                    stream = DeriveStream(pathHash, digest, Slice(context, 52, 8));
                }
                byte[] plain = AesCbc(body, 128, segment, key, iv);
                int padding = plain[segment - 1];
                if (padding < 1 || padding > 16 || (segment == 1040 && padding != 16))
                    throw Bad("Invalid AES padding length.");
                for (int i = 0; i < padding; i++)
                    if (plain[segment - 1 - i] != padding) throw Bad("Invalid AES padding bytes.");
                byte[] output = new byte[body.Length - padding];
                Buffer.BlockCopy(body, 0, output, 0, 128);
                Buffer.BlockCopy(plain, 0, output, 128, segment - padding);
                for (int i = segment; i < tail; i++)
                    output[128 + i - padding] = (byte)(body[128 + i] ^ stream[(i - segment) & 15]);
                return output;
            }
            else
            {
                int count = Math.Min(tail, 1024) & ~15;
                stream = DeriveStream(digest, pathHash, Slice(context, 49, 8));
                byte[] previous = Slice(context, 40, 16);
                uint[] schedule = Rc6Schedule(Slice(context, 24, 16));
                for (int pos = 128; pos < 128 + count; pos += 16)
                {
                    byte[] current = Slice(body, pos, 16), mask = Rc6Encrypt(previous, schedule);
                    for (int i = 0; i < 16; i++) body[pos + i] = (byte)(current[i] ^ mask[i]);
                    previous = current;
                }
                XorRepeat(body, 128, stream);
            }
            return body;
        }

        private static byte[] DecodeHeader(byte[] raw, byte[] path)
        {
            if (raw.Length < 104 || raw[0] != 1) throw Bad("Unsupported or truncated prefix.");
            byte[] h;
            switch (raw[1])
            {
                case 1: h = AesCbc(raw, 8, 96, HeaderKey, HeaderIv); break;
                case 2: h = AesCbc(raw, 8, 96, HeaderKey, Hash128(path)); break;
                case 15: h = AesCbc(raw, 8, 96, HeaderKey, Hash128(Slice(raw, 4, 4))); break;
                case 0x71: h = DecodeHeader71(raw); break;
                default: throw Bad("Unsupported header kind.");
            }
            if (XxHash32.HashToUInt32(h) != U32(raw, 4)) throw Bad("Header checksum mismatch.");
            return h;
        }

        private static byte[] DecodeHeader71(byte[] raw)
        {
            byte[] previous = Hex("a095dfcfd04b74db027ede09"), output = new byte[96];
            for (int pos = 0; pos < 96; pos += 12)
            {
                byte[] current = Slice(raw, 8 + pos, 12);
                byte[] stream = TransformHeaderBlock(previous);
                for (int j = 0; j < 12; j++) output[pos + j] = (byte)(current[j] ^ stream[j]);
                previous = current;
            }
            return output;
        }

        private static byte[] TransformHeaderBlock(byte[] block)
        {
            unchecked
            {
                uint a = Be32(block, 0), b = Be32(block, 4), c = Be32(block, 8), rc = 0x0b0b;
                for (int i = 0; i < 11; i++)
                {
                    a ^= 0xad61aeda ^ (rc << 16); b ^= 0xbf203e1d; c ^= 0xfe1db72b ^ rc;
                    Theta(ref a, ref b, ref c);
                    uint x = Rol(a, 22), y = b, z = Rol(c, 1);
                    a = Rol((~z | y) ^ x, 1);
                    b = y ^ (~x | z);
                    c = Rol((~y | x) ^ z, 22);
                    rc <<= 1;
                    if ((rc & 0x10000) != 0) rc ^= 0x11011;
                }
                a ^= 0xad61aeda ^ (rc << 16); b ^= 0xbf203e1d; c ^= 0xfe1db72b ^ rc;
                Theta(ref a, ref b, ref c);
                byte[] r = new byte[12]; PutBe(r, 0, a); PutBe(r, 4, b); PutBe(r, 8, c); return r;
            }
        }

        private static void Theta(ref uint a, ref uint b, ref uint c)
        {
            unchecked
            {
                uint d = Rol(a ^ b ^ c, 16) ^ Rol(a ^ b ^ c, 8);
                uint e = (((a >> 16) ^ c) >> 8) ^ (((a << 16) ^ b) << 8);
                uint f = (((b << 16) ^ c) << 8) ^ (((b >> 16) ^ a) >> 8);
                a ^= e ^ d; b ^= f ^ d; c ^= (f << 16) ^ (e >> 16) ^ d;
            }
        }

        private static byte[] DecodeBranch1(byte[] body, byte[] path, byte[] h)
        {
            byte[] h1 = Hash128(path, U32(h, 12));
            byte[] h2 = Hash128(Slice(h, 36, 60), U64(h1, 8));
            uint[] words = new uint[4], keys = new uint[8];
            int[] map = { 5, 4, 7, 6 };
            for (int i = 0; i < 4; i++)
            {
                uint w = words[i] = Be32(h2, i * 4);
                keys[i] = w ^ Rol(w, 1) ^ Rol(w, 8);
                keys[map[i]] = w ^ Rol(w, 1) ^ Rol(w, 11);
            }
            byte[] output = (byte[])body.Clone(), previous = Slice(h, 16, 16);
            int aligned = (body.Length - 128) / 16 * 16;
            for (int pos = 128; pos < 128 + Math.Min(aligned, 1024); pos += 16)
            {
                byte[] current = Slice(output, pos, 16), plain = DecodeBranch1Block(current, keys);
                for (int i = 0; i < 16; i++) output[pos + i] = (byte)(plain[i] ^ previous[i]);
                previous = current;
            }
            previous = Slice(h, 16, 16);
            for (int pos = 128; pos < 128 + aligned; pos += 16)
            {
                byte[] current = Slice(output, pos, 16);
                for (int i = 0; i < 16; i++)
                {
                    int j = (i + 12) & 15;
                    output[pos + i] = (byte)(previous[i] ^ current[j] ^ h1[j]);
                }
                previous = current;
            }
            for (int i = 0; i < body.Length - 128 - aligned; i++)
                output[128 + aligned + i] ^= (byte)(previous[i] ^ h1[i]);
            return output;
        }

        private static byte[] DecodeBranch1Block(byte[] block, uint[] keys)
        {
            unchecked
            {
                uint[] w = { Be32(block, 0), Be32(block, 4), Be32(block, 8), Be32(block, 12) };
                for (int r = 79; r >= 0; r--)
                {
                    uint part = Rol(w[(r + 1) & 3], (r & 1) != 0 ? 8 : 1) ^ keys[r & 7];
                    w[r & 3] = (Rol(w[r & 3], (r & 1) != 0 ? 31 : 24) - part) ^ (uint)r;
                }
                byte[] output = new byte[16];
                for (int i = 0; i < 4; i++) PutBe(output, i * 4, w[i]);
                return output;
            }
        }

        private static byte[] DeriveStream(byte[] first, byte[] key, byte[] seed8)
        {
            uint[] k = new uint[52];
            for (int i = 0; i < 8; i++) k[i] = BinaryPrimitives.ReadUInt16BigEndian(key.AsSpan(i * 2, 2));
            for (int i = 8; i < 52; i++)
            {
                int b = i & ~7;
                k[i] = ((k[b + ((i + 1) & 7) - 8] << 9) | (k[b + ((i + 2) & 7) - 8] >> 7)) & 65535;
            }
            byte[] block = new byte[8];
            for (int i = 0; i < 8; i++) block[i] = (byte)(first[i] ^ seed8[i]);
            byte[] left = IdeaEncrypt(block, k);
            for (int i = 0; i < 8; i++) block[i] = (byte)(first[i + 8] ^ left[i]);
            byte[] right = IdeaEncrypt(block, k), output = new byte[16];
            Buffer.BlockCopy(left, 0, output, 0, 8); Buffer.BlockCopy(right, 0, output, 8, 8);
            return output;
        }

        private static uint IdeaMul(uint a, uint b) => (uint)(((ulong)(a == 0 ? 65536 : a) * (b == 0 ? 65536u : b) % 65537) & 65535);

        private static byte[] IdeaEncrypt(byte[] block, uint[] k)
        {
            uint a = BinaryPrimitives.ReadUInt16BigEndian(block.AsSpan(0, 2));
            uint b = BinaryPrimitives.ReadUInt16BigEndian(block.AsSpan(2, 2));
            uint c = BinaryPrimitives.ReadUInt16BigEndian(block.AsSpan(4, 2));
            uint d = BinaryPrimitives.ReadUInt16BigEndian(block.AsSpan(6, 2));
            for (int r = 0; r < 8; r++)
            {
                int j = r * 6;
                a = IdeaMul(a, k[j]); b = (b + k[j + 1]) & 65535;
                c = (c + k[j + 2]) & 65535; d = IdeaMul(d, k[j + 3]);
                uint e = IdeaMul(a ^ c, k[j + 4]);
                uint f = IdeaMul(((b ^ d) + e) & 65535, k[j + 5]);
                e = (e + f) & 65535;
                (a, b, c, d) = (a ^ f, c ^ f, b ^ e, d ^ e);
            }
            byte[] output = new byte[8];
            uint[] result = { IdeaMul(a, k[48]), (c + k[49]) & 65535,
            (b + k[50]) & 65535, IdeaMul(d, k[51]) };
            for (int i = 0; i < 4; i++)
                BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(i * 2, 2), (ushort)result[i]);
            return output;
        }

        private static uint[] Rc6Schedule(byte[] key)
        {
            unchecked
            {
                uint[] words = { U32(key, 0), U32(key, 4), U32(key, 8), U32(key, 12) };
                uint[] s = new uint[44];
                for (int i = 0; i < 44; i++) s[i] = 0xb7e15163 + (uint)i * 0x9e3779b9;
                uint a = 0, b = 0; int x = 0, y = 0;
                for (int i = 0; i < 132; i++)
                {
                    a = s[x] = Rol(s[x] + a + b, 3);
                    b = words[y] = Rol(words[y] + a + b, (int)((a + b) & 31));
                    x = (x + 1) % 44; y = (y + 1) % 4;
                }
                return s;
            }
        }

        private static byte[] Rc6Encrypt(byte[] block, uint[] s)
        {
            unchecked
            {
                uint a = U32(block, 0), b = U32(block, 4) + s[0], c = U32(block, 8), d = U32(block, 12) + s[1];
                for (int i = 1; i <= 20; i++)
                {
                    uint t = Rol(b * (2 * b + 1), 5), u = Rol(d * (2 * d + 1), 5);
                    a = Rol(a ^ t, (int)(u & 31)) + s[2 * i];
                    c = Rol(c ^ u, (int)(t & 31)) + s[2 * i + 1];
                    (a, b, c, d) = (b, c, d, a);
                }
                byte[] r = new byte[16]; PutLe(r, 0, a + s[42]); PutLe(r, 4, b);
                PutLe(r, 8, c + s[43]); PutLe(r, 12, d); return r;
            }
        }

        private static byte[] DecodeLz4(byte[] data, int size)
        {
            byte[] output = new byte[size];
            int pos = 0, written = 0;
            while (pos < data.Length)
            {
                int token = data[pos++];
                int literal = ReadLength(data, ref pos, token >> 4);
                if (literal > data.Length - pos || literal > size - written)
                    throw Bad("Invalid LZ4 literal length.");
                Buffer.BlockCopy(data, pos, output, written, literal);
                pos += literal; written += literal;
                if (pos == data.Length) break;
                if (data.Length - pos < 2) throw Bad("Truncated LZ4 match.");
                int distance = data[pos] | (data[pos + 1] << 8); pos += 2;
                if (distance == 0 || distance > written) throw Bad("Invalid LZ4 match offset.");
                int encoded = ReadLength(data, ref pos, token & 15);
                if (encoded > int.MaxValue - 4) throw Bad("LZ4 length overflow.");
                int match = encoded + 4;
                if (match > size - written) throw Bad("LZ4 output exceeds expected size.");
                for (int i = 0; i < match; i++) output[written + i] = output[written + i - distance];
                written += match;
            }
            if (written != size) throw Bad("Wrong decompressed size.");
            return output;
        }

        private static int ReadLength(byte[] data, ref int pos, int length)
        {
            if (length != 15) return length;
            while (true)
            {
                if (pos >= data.Length) throw Bad("Truncated LZ4 length.");
                int b = data[pos++];
                if (length > int.MaxValue - b) throw Bad("LZ4 length overflow.");
                length += b; if (b != 255) return length;
            }
        }

        private static byte[] AesCbc(byte[] source, int offset, int count, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None; aes.Key = key; aes.IV = iv;
            using ICryptoTransform decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(source, offset, count);
        }

        private static byte[] Hash128(byte[] input, ulong seed = 0)
        {
            byte[] bytes = XxHash128.Hash(input, unchecked((long)seed));
            Array.Reverse(bytes); return bytes;
        }
        private static bool HashMatches(byte[] output, byte[] header) => Hash128(output).AsSpan().SequenceEqual(header.AsSpan(16, 16));
        private static void XorRepeat(byte[] data, int start, byte[] mask)
        {
            for (int i = start; i < data.Length; i++) data[i] ^= mask[(i - start) & 15];
        }
        private static uint Rol(uint x, int n) { n &= 31; return (x << n) | (x >> ((32 - n) & 31)); }
        private static uint U32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4));
        private static ulong U64(byte[] b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o, 8));
        private static uint Be32(byte[] b, int o) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o, 4));
        private static void PutBe(byte[] b, int o, uint v) => BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o, 4), v);
        private static void PutLe(byte[] b, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o, 4), v);
        private static byte[] Slice(byte[] source, int offset, int count) => source.AsSpan(offset, count).ToArray();
        private static byte[] Hex(string s)
        {
            byte[] bytes = new byte[s.Length / 2];
            for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return bytes;
        }
        private static InvalidDataException Bad(string message) => new(message);
    }
}
