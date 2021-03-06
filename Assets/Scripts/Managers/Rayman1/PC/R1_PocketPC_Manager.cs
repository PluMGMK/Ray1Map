﻿using R1Engine.Serialize;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Cysharp.Threading.Tasks;
using UnityEngine;

namespace R1Engine
{
    /// <summary>
    /// The game manager for Rayman Ultimate (Pocket PC)
    /// </summary>
    public class R1_PocketPC_Manager : R1_PC_Manager
    {
        #region Values and paths

        /// <summary>
        /// Gets the levels for each world
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The levels</returns>
        public override GameInfo_Volume[] GetLevels(GameSettings settings) => GameInfo_Volume.SingleVolume(WorldHelpers.GetR1Worlds().Select(w => new GameInfo_World((int)w, Directory.EnumerateFiles(settings.GameDirectory + GetWorldFolderPath(w), $"{GetShortWorldName(w)}??.lev.gz", SearchOption.TopDirectoryOnly)
            .Select(FileSystem.GetFileNameWithoutExtensions)
            .Select(x => Int32.Parse(x.Substring(3)))
            .ToArray())).ToArray());

        /// <summary>
        /// Gets the file path for the big ray file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The big ray file path</returns>
        public override string GetBigRayFilePath(GameSettings settings) => GetDataPath() + $"bray.dat.gz";

        /// <summary>
        /// Gets the file path for the vignette file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The vignette file path</returns>
        public override string GetVignetteFilePath(GameSettings settings) => String.Empty;

        /// <summary>
        /// Gets the file path for the allfix file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The allfix file path</returns>
        public override string GetAllfixFilePath(GameSettings settings) => GetDataPath() + $"allfix.dat.gz";

        /// <summary>
        /// Gets the file path for the specified level
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The level file path</returns>
        public override string GetLevelFilePath(GameSettings settings) => GetWorldFolderPath(settings.R1_World) + $"{GetShortWorldName(settings.R1_World)}{settings.Level}.lev.gz";

        /// <summary>
        /// Gets the file path for the specified world file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The world file path</returns>
        public override string GetWorldFilePath(GameSettings settings) => GetDataPath() + $"ray{settings.World}.wld.gz";

        /// <summary>
        /// Gets the short name for the world
        /// </summary>
        /// <returns>The short world name</returns>
        public override string GetShortWorldName(R1_World world)
        {
            switch (world)
            {
                case R1_World.Jungle:
                    return "JUN";
                case R1_World.Music:
                    return "MUS";
                case R1_World.Mountain:
                    return "MON";
                case R1_World.Image:
                    return "IMG";
                case R1_World.Cave:
                    return "CAV";
                case R1_World.Cake:
                    return "CAK";
                default:
                    throw new ArgumentOutOfRangeException(nameof(world), world, null);
            }
        }

        public string GetVignetteFilePath(int index) => GetDataPath() + $"dat/{index:00}.dat.gz";

        #endregion

        #region Manager Methods

        /// <summary>
        /// Gets a binary file to add to the context
        /// </summary>
        /// <param name="context">The context</param>
        /// <param name="filePath">The file path</param>
        /// <returns>The binary file</returns>
        protected override BinaryFile GetFile(Context context, string filePath) => new GzipCompressedFile(context)
        {
            filePath = filePath
        };

        protected override async UniTask<IReadOnlyDictionary<string, string[]>> LoadLocalizationAsync(Context context)
        {
            var lngPath = GetLanguageFilePath();

            await AddFile(context, lngPath);

            // Read the language file
            var lng = FileFactory.ReadText<R1_PC_LNGFile>(lngPath, context);

            // Set the common localization
            return new Dictionary<string, string[]>()
            {
                ["English1"] = lng.Strings[0],
                ["English2"] = lng.Strings[1],
                ["English3"] = lng.Strings[2],
                ["French"] = lng.Strings[3],
                ["German"] = lng.Strings[4],
            };
        }

        public override async UniTask<Texture2D> LoadBackgroundVignetteAsync(Context context, R1_PC_WorldFile world, R1_PC_LevFile level, bool parallax)
        {
            return (await LoadPCXAsync(context, world.Plan0NumPcx[parallax ? level.ParallaxBackgroundIndex : level.BackgroundIndex])).ToTexture(true);
        }

        public override async UniTask<PCX> GetWorldMapVigAsync(Context context)
        {
            return await LoadPCXAsync(context, 46);
        }

        protected async UniTask<PCX> LoadPCXAsync(Context context, int index)
        {
            var xor = LoadVignetteHeader(context)[index].XORKey;

            var path = GetVignetteFilePath(index);

            await AddFile(context, path);

            var s = context.Deserializer;
            PCX pcx = null;

            s.DoAt(context.GetFile(path).StartPointer, () =>
            {
                s.DoXOR(xor, () =>
                {
                    // Read the data
                    pcx = s.SerializeObject<PCX>(default, name: $"VIGNET");
                });
            });

            return pcx;
        }

        protected R1_PC_EncryptedFileArchiveEntry[] LoadVignetteHeader(Context context)
        {
            var s = context.Deserializer;

            var headerBytes = R1_PC_ArchiveHeaders.GetHeader(context.Settings, "VIGNET.DAT");
            var headerLength = headerBytes.Length / 12;

            var headerStream = new MemoryStream(headerBytes);
            var file = s.Context.AddStreamFile($"VIGNET_Header", headerStream);

            return s.DoAt(file.StartPointer, () => s.SerializeObjectArray<R1_PC_EncryptedFileArchiveEntry>(default, headerLength, name: "Entries"));
        }

        public override void ExtractVignette(GameSettings settings, string vigPath, string outputDir)
        {
            // Create a new context
            using (var context = new Context(settings))
            {
                R1_PC_EncryptedFileArchiveEntry[] entries = LoadVignetteHeader(context);
                var s = context.Deserializer;

                // Extract every .pcx file
                for (int i = 0; i < entries.Length; i++)
                {
                    var path = GetVignetteFilePath(i);
                    var file = new GzipCompressedFile(context)
                    {
                        filePath = path
                    };

                    context.AddFile(file);

                    s.DoAt(file.StartPointer, () =>
                    {
                        s.DoXOR(entries[i].XORKey, () =>
                        {
                            // Read the data
                            var pcx = s.SerializeObject<PCX>(default, name: $"PCX[{i}]");

                            // Convert to a texture
                            var tex = pcx.ToTexture(true);

                            // Write the bytes
                            Util.ByteArrayToFile(Path.Combine(outputDir, $"{i}.png"), tex.EncodeToPNG());
                        });
                    });
                }
            }
        }

        #endregion
    }
}