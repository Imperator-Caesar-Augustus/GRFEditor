using System;
using System.IO;
using System.Linq;
using System.Text;
using GRF.ContainerFormat;
using Utilities.Services;

namespace GRF.Core {

	public static class DecryptedGpfExporter {




		public static void Export(GrfHolder source, string destination,
			Action<float> progress = null, Func<bool> isCancellationRequested = null) {
			if (source == null) throw new ArgumentNullException(nameof(source));
			if (!source.IsOpened) throw new InvalidOperationException("Open an archive first.");
			if (source.IsBusy || source.Commands.IsLocked) throw new InvalidOperationException("The source archive is busy.");
			if (String.IsNullOrWhiteSpace(destination)) throw new ArgumentException("Choose a destination.", nameof(destination));
			string target = Path.GetFullPath(destination);
			if (!String.Equals(Path.GetExtension(target), ".gpf", StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("The decrypted archive must use the .gpf extension.", nameof(destination));
			if (!String.IsNullOrEmpty(source.FileName) &&
			    String.Equals(target, Path.GetFullPath(source.FileName), StringComparison.OrdinalIgnoreCase))
				throw new InvalidOperationException("Choose a different file to preserve the source archive.");

			string directory = Path.GetDirectoryName(target);
			Directory.CreateDirectory(directory);
			string temporary = Path.Combine(directory, "." + Path.GetFileName(target) + "." + Guid.NewGuid().ToString("N") + ".tmp");
			source.IsBusy = true;
			try {
				var entries = source.FileTable.Entries.Where(e =>
					!e.Modification.HasFlag(Modification.Removed) && !e.Flags.HasFlag(EntryType.RemoveFile))
					.Select(e => (FileEntry)e.Copy()).ToList();
				if (entries.Count > Int32.MaxValue - 7) throw new InvalidDataException("Too many GPF entries.");
				CheckCancellation(source, isCancellationRequested);
				using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
				using (var writer = new BinaryWriter(output, Encoding.ASCII, true))
				using (var table = new MemoryStream())
				using (var metadata = new BinaryWriter(table, Encoding.ASCII, true)) {
					writer.Write(Encoding.ASCII.GetBytes(GrfStrings.MasterOfMagic));
					writer.Write(new byte[14]);
					writer.Write((uint)0);
					writer.Write(0);
					writer.Write(entries.Count + 7);
					writer.Write(0x200);
					for (int i = 0; i < entries.Count; i++) {
						CheckCancellation(source, isCancellationRequested);
						var entry = entries[i];

						entry.BypassSaveCheck = true;
						byte[] plain;
						try { plain = entry.GetDecompressedData(); }
						catch (Exception error) {
							throw new InvalidDataException("Could not decode entry: " + entry.RelativePath, error);
						}
						CheckCancellation(source, isCancellationRequested);
						byte[] compressed = Compression.ZlibDotNet.Compress(plain);
						long aligned = ((long)compressed.Length + 7) & ~7L;
						if (aligned > Int32.MaxValue || output.Position - GrfHeader.DataByteSize + aligned > UInt32.MaxValue)
							throw new InvalidDataException("The output exceeds the GRF 2.0/GPF size limit.");
						uint offset = checked((uint)(output.Position - GrfHeader.DataByteSize));
						writer.Write(compressed);
						writer.Write(new byte[(int)(aligned - compressed.Length)]);

						byte[] name = EncodingService.Ansi.GetBytes(EncodingService.GetAnsiString(entry.GetFixedFileName()));
						if (name.Length == 0 || Array.IndexOf(name, (byte)0) >= 0)
							throw new InvalidDataException("Invalid GPF filename: " + entry.RelativePath);
						metadata.Write(name);
						metadata.Write((byte)0);
						metadata.Write(compressed.Length);
						metadata.Write((int)aligned);
						metadata.Write(plain.Length);
						metadata.Write((byte)EntryType.File);
						metadata.Write(offset);
						source.Progress = 95f * (i + 1) / Math.Max(1, entries.Count);
						progress?.Invoke(source.Progress);
					}
					CheckCancellation(source, isCancellationRequested);
					uint tableOffset = checked((uint)(output.Position - GrfHeader.DataByteSize));
					byte[] uncompressedTable = table.ToArray();
					byte[] compressedTable = Compression.ZlibDotNet.Compress(uncompressedTable);
					writer.Write(compressedTable.Length);
					writer.Write(uncompressedTable.Length);
					writer.Write(compressedTable);
					output.Position = 30;
					writer.Write(tableOffset);
					writer.Flush();
					output.Flush(true);
				}
				CheckCancellation(source, isCancellationRequested);
				if (File.Exists(target))
					File.Replace(temporary, target, null);
				else
					File.Move(temporary, target);
				source.Progress = 100;
			}
			finally {
				source.IsBusy = false;
				if (File.Exists(temporary)) File.Delete(temporary);
			}
		}

		private static void CheckCancellation(GrfHolder source, Func<bool> cancellation) {
			if (source.IsCancelling || (cancellation != null && cancellation()))
				throw new OperationCanceledException("Decrypted GPF export was cancelled.");
		}
	}
}
