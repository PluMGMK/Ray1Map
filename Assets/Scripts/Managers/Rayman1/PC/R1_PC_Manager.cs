﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Cysharp.Threading.Tasks;
using R1Engine.Serialize;
using UnityEngine;

namespace R1Engine
{
    /// <summary>
    /// The game manager for Rayman 1 (PC)
    /// </summary>
    public class R1_PC_Manager : R1_PCBaseManager
    {
        #region Values and paths

        /// <summary>
        /// Gets the levels for each world
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The levels</returns>
        public override GameInfo_Volume[] GetLevels(GameSettings settings) => GameInfo_Volume.SingleVolume(WorldHelpers.GetR1Worlds().Select(w => new GameInfo_World((int)w, Directory.EnumerateFiles(settings.GameDirectory + GetWorldFolderPath(w), $"RAY??.LEV", SearchOption.TopDirectoryOnly)
            .Select(FileSystem.GetFileNameWithoutExtensions)
            .Select(x => Int32.Parse(x.Substring(3)))
            .ToArray())).ToArray());

        /// <summary>
        /// Gets the folder path for the specified world
        /// </summary>
        /// <param name="world">The world</param>
        /// <returns>The world folder path</returns>
        public string GetWorldFolderPath(R1_World world) => GetDataPath() + GetWorldName(world) + "/";

        /// <summary>
        /// Gets the file path for the big ray file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The big ray file path</returns>
        public override string GetBigRayFilePath(GameSettings settings) => GetDataPath() + $"BRAY.DAT";

        /// <summary>
        /// Gets the file path for the vignette file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The vignette file path</returns>
        public override string GetVignetteFilePath(GameSettings settings) => $"VIGNET.DAT";

        /// <summary>
        /// Gets the file path for the specified level
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The level file path</returns>
        public override string GetLevelFilePath(GameSettings settings) => GetWorldFolderPath(settings.R1_World) + $"RAY{settings.Level}.LEV";

        /// <summary>
        /// Gets the file path for the specified world file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The world file path</returns>
        public override string GetWorldFilePath(GameSettings settings) => GetDataPath() + $"RAY{settings.World}.WLD";

        public virtual string GetLanguageFilePath() => "RAY.LNG";

        /// <summary>
        /// Gets the archive files which can be extracted
        /// </summary>
        public override ArchiveFile[] GetArchiveFiles(GameSettings settings) => new ArchiveFile[0];

        /// <summary>
        /// Gets additional sound archives
        /// </summary>
        /// <param name="settings">The game settings</param>
        public override AdditionalSoundArchive[] GetAdditionalSoundArchives(GameSettings settings) => new AdditionalSoundArchive[]
        {
            new AdditionalSoundArchive("VIG", new ArchiveFile("SNDVIG.DAT"), 16),
        };

        public override bool IsDESMultiColored(Context context, int desIndex, GeneralEventInfoData[] generalEvents) => generalEvents.Any(x => x.DesR1[context.Settings.R1_World] == desIndex && ((R1_EventType)x.Type).IsMultiColored());

        /// <summary>
        /// Gets the available game actions
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The game actions</returns>
        public override GameAction[] GetGameActions(GameSettings settings)
        {
            return base.GetGameActions(settings).Concat(new GameAction[]
            {
                new GameAction("Decrypt Save Files", false, false, (input, output) => DecryptSaveFiles(settings)),
                new GameAction("Read Save Files", false, false, (input, output) => ReadSaveFiles(settings))
            }).ToArray();
        }

        #endregion

        #region Manager Methods

        public void DecryptSaveFiles(GameSettings settings)
        {
            using (var context = new Context(settings))
            {
                foreach (var save in Directory.GetFiles(settings.GameDirectory, "*.sav", SearchOption.TopDirectoryOnly).Select(Path.GetFileName))
                {
                    LinearSerializedFile f = new LinearSerializedFile(context)
                    {
                        filePath = save
                    };
                    context.AddFile(f);
                    SerializerObject s = context.Deserializer;
                    byte[] saveData = null;
                    s.DoAt(f.StartPointer, () => {
                        s.DoEncoded(new PC_R1_SaveEncoder(), () => {
                            saveData = s.SerializeArray<byte>(saveData, s.CurrentLength, name: "SaveData");
                            Util.ByteArrayToFile(context.BasePath + save + ".dec", saveData);
                        });
                    });
                    /*LinearSerializedFile f2 = new LinearSerializedFile(context) {
                        filePath = save + ".recompressed"
                    };
                    context.AddFile(f2);
                    s = context.Serializer;
                    s.DoAt(f2.StartPointer, () => {
                        s.DoEncoded(new R1PCSaveEncoder(), () => {
                            saveData = s.SerializeArray<byte>(saveData, saveData.Length, name: "SaveData");
                        });
                    });*/
                }
            }
        }

        public void ReadSaveFiles(GameSettings settings)
        {
            using (var context = new Context(settings))
            {
                foreach (var save in Directory.GetFiles(settings.GameDirectory, "*.sav", SearchOption.TopDirectoryOnly).Select(Path.GetFileName))
                {
                    LinearSerializedFile f = new LinearSerializedFile(context)
                    {
                        filePath = save
                    };
                    context.AddFile(f);
                    SerializerObject s = context.Deserializer;
                    s.DoAt(f.StartPointer, () => {
                        s.DoEncoded(new PC_R1_SaveEncoder(), () => s.SerializeObject<R1_PC_SaveFile>(default, name: "SaveFile"));
                    });
                }
            }
        }

        /// <summary>
        /// Extracts the data from an archive file
        /// </summary>
        /// <param name="context">The context</param>
        /// <param name="file">The archive file</param>
        /// <returns>The archive data</returns>
        public override IEnumerable<ArchiveData> ExtractArchive(Context context, ArchiveFile file)
        {
            // Get the sound file table
            var soundFileTable =
                // Sound file
                file.FilePath == GetSoundFilePath() ? new[]
            {
                new
                {
                    FileOffset = 0x0,
                    FileSize = 0x1D140,
                    XORKey = 0xC0,
                    Checksum = 0x3C
                },
                new
                {
                    FileOffset = 0x1D140,
                    FileSize = 0x2224C,
                    XORKey = 0x94,
                    Checksum = 0x68
                },
                new
                {
                    FileOffset = 0x3F38C,
                    FileSize = 0x46DE8,
                    XORKey = 0x29,
                    Checksum = 0x95
                },
                new
                {
                    FileOffset = 0x86174,
                    FileSize = 0x3181C,
                    XORKey = 0x0ED,
                    Checksum = 0x17
                },
                new
                {
                    FileOffset = 0x0B7990,
                    FileSize = 0x30E98,
                    XORKey = 0x24,
                    Checksum = 0xB4
                },
                new
                {
                    FileOffset = 0x0E8828,
                    FileSize = 0x2F2F0,
                    XORKey = 0xF3,
                    Checksum = 0x3B
                },
                new
                {
                    FileOffset = 0x117B18,
                    FileSize = 0x2D588,
                    XORKey = 0xF8,
                    Checksum = 0x33
                },
            } :
                // Sound manifest
                file.FilePath == GetSoundManifestFilePath() ?
                new[]
            {
                new
                {
                    FileOffset = 0x0,
                    FileSize = 0x800,
                    XORKey = 0x4D,
                    Checksum = 0xC3
                },
                new
                {
                    FileOffset = 0x800,
                    FileSize = 0x800,
                    XORKey = 0xD9,
                    Checksum = 0xC1
                },
                new
                {
                    FileOffset = 0x1000,
                    FileSize = 0x800,
                    XORKey = 0x24,
                    Checksum = 0x8E
                },
                new
                {
                    FileOffset = 0x1800,
                    FileSize = 0x800,
                    XORKey = 0xFA,
                    Checksum = 0x16
                },
                new
                {
                    FileOffset = 0x2000,
                    FileSize = 0x800,
                    XORKey = 0x67,
                    Checksum = 0x49
                },
                new
                {
                    FileOffset = 0x2800,
                    FileSize = 0x800,
                    XORKey = 0xAB,
                    Checksum = 0xB7
                },
                new
                {
                    FileOffset = 0x3000,
                    FileSize = 0x800,
                    XORKey = 0x63,
                    Checksum = 0xDE
                },
            } :
                // Sound vignette
                new[]
            {
                new
                {
                    FileOffset = 0x0,
                    FileSize = 0x146F4,
                    XORKey = 0x4D,
                    Checksum = 0x60
                },
                new
                {
                    FileOffset = 0x146F4,
                    FileSize = 0x20DB0,
                    XORKey = 0xD9,
                    Checksum = 0x26
                },
                new
                {
                    FileOffset = 0x354A4,
                    FileSize = 0x1CE12,
                    XORKey = 0x24,
                    Checksum = 0x43
                },
                new
                {
                    FileOffset = 0x522B6,
                    FileSize = 0x144A0,
                    XORKey = 0xFA,
                    Checksum = 0x7A
                },
                new
                {
                    FileOffset = 0x66756,
                    FileSize = 0x8A40,
                    XORKey = 0x67,
                    Checksum = 0xB1
                },
                new
                {
                    FileOffset = 0x6F196,
                    FileSize = 0x1EAD0,
                    XORKey = 0xAB,
                    Checksum = 0xA4
                },
                new
                {
                    FileOffset = 0x8DC66,
                    FileSize = 0x1804A,
                    XORKey = 0x63,
                    Checksum = 0xDB
                },
                new
                {
                    FileOffset = 0x0A5CB0,
                    FileSize = 0x6380,
                    XORKey = 0x47,
                    Checksum = 0x54
                },
                new
                {
                    FileOffset = 0x0AC030,
                    FileSize = 0x10AFE,
                    XORKey = 0x87,
                    Checksum = 0x4F
                },
            };

            // Read the file bytes
            var fileData = File.ReadAllBytes(context.BasePath + file.FilePath);

            // Return every archive file
            for (var i = 0; i < soundFileTable.Length; i++)
            {
                // Get the entry
                var entry = soundFileTable[i];

                // Return the data
                yield return new ArchiveData(i.ToString(), fileData.Skip(entry.FileOffset).Take(entry.FileSize).Select(x => (byte)(x ^ entry.XORKey)).ToArray());
            }
        }

        public override Texture2D LoadBackgroundVignette(Context context, R1_PC_WorldFile world, R1_PC_LevFile level, bool parallax) => null;

        protected override async UniTask<IReadOnlyDictionary<string, string[]>> LoadLocalizationAsync(Context context)
        {
            var lngPath = GetLanguageFilePath();

            await FileSystem.PrepareFile(context.BasePath + lngPath);

            // Read the language file
            var lng = FileFactory.ReadText<R1_PC_LNGFile>(lngPath, context);

            // Set the common localization
            var loc = new Dictionary<string, string[]>()
            {
                ["English"] = lng.Strings[0],
                ["French"] = lng.Strings[1],
                ["German"] = lng.Strings[2],
            };

            // Set extended localization if available
            if (lng.Strings.Length > 3)
                loc.Add("Japanese", lng.Strings[3]);
            if (lng.Strings.Length > 4)
                loc.Add("Chinese", lng.Strings[4]);

            return loc;
        }

        #endregion
    }
}