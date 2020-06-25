﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace R1Engine.Serialize {
	public abstract class BinaryFile : IDisposable {
		public Context Context { get; }
		public long baseAddress;
		private Dictionary<uint, Pointer> predefinedPointers = new Dictionary<uint, Pointer>();
		public abstract Pointer StartPointer { get; }

		/// <summary>
		/// The file path relative to the main directory in the context
		/// </summary>
		public string filePath;

		/// <summary>
		/// Files can also be identified with an alias.
		/// </summary>
		public string alias;
		public string AbsolutePath => Context.BasePath + filePath;

		public abstract Reader CreateReader();
		public abstract Writer CreateWriter();

		public virtual Pointer GetPointer(uint serializedValue, Pointer anchor = null) {
			Pointer ptr = new Pointer(serializedValue, this, anchor: anchor);
			return ptr;
		}
		public virtual bool AllowInvalidPointer(uint serializedValue, Pointer anchor = null) {
			return false;
		}
		public virtual Pointer GetPreDefinedPointer(uint offset) {
			if (predefinedPointers.ContainsKey(offset)) {
				return predefinedPointers[offset];
			}
			return null;
		}

		public virtual void EndRead(Reader reader) {
			((IDisposable)reader).Dispose();
		}
		public virtual void EndWrite(Writer writer) {
			((IDisposable)writer).Dispose();
		}

		public BinaryFile(Context context) {
			this.Context = context;
		}

		protected void CreateBackupFile() {
			if (Settings.BackupFiles) {
				if (!FileSystem.FileExists(AbsolutePath + ".BAK")) {
					if (FileSystem.FileExists(AbsolutePath)) {
						using (Stream s = FileSystem.GetFileReadStream(AbsolutePath)) {
							using (Stream sb = FileSystem.GetFileWriteStream(AbsolutePath + ".BAK")) {
								s.CopyTo(sb);
							}
						}
					}
				}
			}
		}

		public virtual void Dispose() { }

		public Endian Endianness { get; set; } = Endian.Little;
		public enum Endian {
			Little,
			Big
		}
	}
}
