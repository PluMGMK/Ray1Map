﻿using System;
using System.Linq;
using System.Text;

namespace R1Engine
{
    /// <summary>
    /// Data for Rayman 1 (DSi)
    /// </summary>
    public class R1_DSi_DataFile : R1Serializable, IR1_GBAData
    {
        /// <summary>
        /// The map data for the current level
        /// </summary>
        public R1_GBA_LevelMapData LevelMapData { get; set; }

        /// <summary>
        /// The event data for the current level
        /// </summary>
        public R1_GBA_LevelEventData LevelEventData { get; set; }

        public R1_DSi_PaletteReference[] Palettes { get; set; }

        /// <summary>
        /// The sprite palette for the current level
        /// </summary>
        /// <param name="settings">The game settings</param>
        public ARGB1555Color[] GetSpritePalettes(GameSettings settings)
        {
            R1_DSi_PaletteReference palRef = null;
            switch (settings.R1_World)
            {
                case R1_World.Jungle:
                    palRef = Palettes.FirstOrDefault(p => p.Name == "PALETTE_ray");
                    break;
                case R1_World.Music:
                    palRef = Palettes.FirstOrDefault(p => p.Name == "PALETTE_mus");
                    break;
                case R1_World.Mountain:
                    palRef = Palettes.FirstOrDefault(p => p.Name == "PALETTE_mnt");
                    // NOTE: There's a mnt2. It appears to be unused?
                    break;
                case R1_World.Image:
                    palRef = Palettes.FirstOrDefault(p => p.Name == "PALETTE_img");
                    break;
                case R1_World.Cave:
                    palRef = Palettes.FirstOrDefault(p => p.Name == "PALETTE_cav");
                    break;
                case R1_World.Cake:
                    palRef = Palettes.FirstOrDefault(p => p.Name == "PALETTE_ray");
                    break;
            }
            return palRef?.Palette;
        }

        /// <summary>
        /// The background vignette data
        /// </summary>
        public R1_GBA_BackgroundVignette[] BackgroundVignettes { get; set; }

        // TODO: Parse these from data
        public R1_GBA_IntroVignette[] IntroVignettes => null;
        public R1_GBA_WorldMapVignette WorldMapVignette { get; set; }

        public byte[] WorldLevelOffsetTable { get; set; }

        public Pointer[] StringPointerTable { get; set; }
        public string[][] Strings { get; set; }

        /// <summary>
        /// Handles the data serialization
        /// </summary>
        /// <param name="s">The serializer object</param>
        public override void SerializeImpl(SerializerObject s)
        {
            // Get the pointer table
            var pointerTable = PointerTables.R1_DSi_PointerTable(s.GameSettings.GameModeSelection, this.Offset.file);

            s.DoAt(pointerTable[R1_DSi_Pointer.WorldLevelOffsetTable],
                () => WorldLevelOffsetTable = s.SerializeArray<byte>(WorldLevelOffsetTable, 8, name: nameof(WorldLevelOffsetTable)));

            // Get the global level index
            var levelIndex = WorldLevelOffsetTable[s.GameSettings.World] + (s.GameSettings.Level - 1);

            // Serialize data from the ROM
            s.DoAt((s.GameSettings.R1_World == R1_World.Jungle ? pointerTable[R1_DSi_Pointer.JungleMaps] : pointerTable[R1_DSi_Pointer.LevelMaps]) + (levelIndex * 32), 
                () => LevelMapData = s.SerializeObject<R1_GBA_LevelMapData>(LevelMapData, name: nameof(LevelMapData)));
            s.DoAt(pointerTable[R1_DSi_Pointer.BackgroundVignette],
                () => BackgroundVignettes = s.SerializeObjectArray<R1_GBA_BackgroundVignette>(BackgroundVignettes, 48, name: nameof(BackgroundVignettes)));
            WorldMapVignette = s.SerializeObject<R1_GBA_WorldMapVignette>(WorldMapVignette, name: nameof(WorldMapVignette));

            // Serialize the level event data
            LevelEventData = new R1_GBA_LevelEventData();
            LevelEventData.SerializeData(s, pointerTable[R1_DSi_Pointer.EventGraphicsPointers], pointerTable[R1_DSi_Pointer.EventDataPointers], pointerTable[R1_DSi_Pointer.EventGraphicsGroupCountTablePointers], pointerTable[R1_DSi_Pointer.LevelEventGraphicsGroupCounts]);

            s.DoAt(pointerTable[R1_DSi_Pointer.SpecialPalettes], () => Palettes = s.SerializeObjectArray<R1_DSi_PaletteReference>(Palettes, 10, name: nameof(Palettes)));

            // Serialize strings
            s.DoAt(pointerTable[R1_DSi_Pointer.StringPointers], () =>
            {
                StringPointerTable = s.SerializePointerArray(StringPointerTable, 5 * 394, name: nameof(StringPointerTable));
                
                if (Strings == null)
                    Strings = new string[5][];

                var enc = new Encoding[]
                {
                    // Spanish
                    Encoding.GetEncoding(1252),
                    // English
                    Encoding.GetEncoding(437),
                    // French
                    Encoding.GetEncoding(1252),
                    // Italian
                    Encoding.GetEncoding(1252),
                    // German
                    Encoding.GetEncoding(437),
                };

                for (int i = 0; i < Strings.Length; i++)
                {
                    if (Strings[i] == null)
                        Strings[i] = new string[394];

                    for (int j = 0; j < Strings[i].Length; j++)
                    {
                        s.DoAt(StringPointerTable[i * 394 + j], () => Strings[i][j] = s.SerializeString(Strings[i][j], encoding: enc[i], name: $"{nameof(Strings)}[{i}][{j}]"));
                    }
                }
            });
        }

        /// <summary>
        /// Creates a relocated 0.bin file, that is searchable with file offsets in big endian, prefixed with "DD".
        /// e.g.: the bytes 010F1E02 (a pointer to 0x01) become DD000001.
        /// </summary>
        /// <param name="s"></param>
        public void CreateRelocatedFile(SerializerObject s) {
            byte[] data = s.SerializeArray<byte>(null, s.CurrentLength, name: "fullfile");
            uint addr = 0x021E0F00;
            for (int j = 0; j < data.Length; j++) {
                if (data[j] == 0x02) {
                    int off = j - 3;
                    uint ptr = BitConverter.ToUInt32(data, off);
                    if (ptr >= addr && ptr < addr + data.Length) {
                        ptr = (ptr - addr) + 0xDD000000;
                        byte[] newData = BitConverter.GetBytes(ptr);
                        for (int y = 0; y < 4; y++) {
                            data[off + 3 - y] = newData[y];
                        }
                        j += 3;
                    }
                }
            }
            Util.ByteArrayToFile(s.Context.BasePath + "relocated.bin", data);
        }
    }

    /*

        SPLASH SCREENS:

        ???


        LOADING + CREDITS SCREENS:

        ???


        INTRO SCREENS:

        ???
 */
}