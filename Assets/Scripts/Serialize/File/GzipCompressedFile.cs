﻿using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Cysharp.Threading.Tasks;

namespace R1Engine.Serialize {
	public class GzipCompressedFile : LinearSerializedFile {
		public GzipCompressedFile(Context context) : base(context) {
		}

		public override Pointer StartPointer => new Pointer((uint)baseAddress, this);

		public override Reader CreateReader() {
			Stream s = FileSystem.GetFileReadStream(AbsolutePath);
			// Create a memory stream to write to so we can get the position
			var memStream = new MemoryStream();

			// Decompress to the memory stream
			using (var gZipStream = new GZipStream(s, CompressionMode.Decompress))
				gZipStream.CopyTo(memStream);

			// Set the position to the beginning
			memStream.Position = 0;
			s.Close();

			length = (uint)memStream.Length;
			Reader reader = new Reader(memStream, isLittleEndian: Endianness == Endian.Little);
			return reader;
		}

		public override Writer CreateWriter() {
			Stream memStream = new MemoryStream();
			memStream.SetLength(length);
			Writer writer = new Writer(memStream, isLittleEndian: Endianness == Endian.Little);
			return writer;
		}

		public override void EndWrite(Writer writer) {
			if (writer != null) {
				CreateBackupFile();
				using (Stream s = FileSystem.GetFileWriteStream(AbsolutePath, RecreateOnWrite)) {
					using (GZipStream compressionStream = new GZipStream(s, CompressionMode.Compress)) {
						writer.BaseStream.CopyTo(compressionStream);
					}
				}
			}
			base.EndWrite(writer);
		}

		public override Pointer GetPointer(uint serializedValue, Pointer anchor = null) {
			if (length == 0) {
				Stream s = FileSystem.GetFileReadStream(AbsolutePath);
				// Create a memory stream to write to so we can get the position
				var memStream = new MemoryStream();

				// Decompress to the memory stream
				using (var gZipStream = new GZipStream(s, CompressionMode.Decompress))
					gZipStream.CopyTo(memStream);

				// Set the position to the beginning
				memStream.Position = 0;
				length = (uint)memStream.Length;
				s.Close();
				memStream.Close();
			}
			uint anchorOffset = anchor?.AbsoluteOffset ?? 0;
			if (serializedValue + anchorOffset >= baseAddress && serializedValue + anchorOffset <= baseAddress + length) {
				return new Pointer(serializedValue, this, anchor: anchor);
			}
			return null;
		}
	}
}
