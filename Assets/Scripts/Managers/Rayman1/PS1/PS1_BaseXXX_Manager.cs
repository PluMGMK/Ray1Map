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
    /// Base .xxx game manager for PS1
    /// </summary>
    public abstract class PS1_BaseXXX_Manager : PS1_Manager
    {
        /// <summary>
        /// Gets the file path for the specified level
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The level file path</returns>
        public virtual string GetLevelFilePath(GameSettings settings) => GetWorldFolderPath(settings.World) + $"{GetWorldName(settings.World)}{settings.Level:00}.XXX";

        /// <summary>
        /// Gets the file path for the allfix file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The allfix file path</returns>
        public virtual string GetAllfixFilePath(GameSettings settings) => GetDataPath() + $"RAY.XXX";

        /// <summary>
        /// Gets the file path for the big ray file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The big ray file path</returns>
        public virtual string GetBigRayFilePath(GameSettings settings) => GetDataPath() + $"INI.XXX";

        /// <summary>
        /// Gets the file path for the font file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The font file path</returns>
        public virtual string GetFontFilePath(GameSettings settings) => GetDataPath() + $"LET2.IMG";

        /// <summary>
        /// Gets the file path for the specified world file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The world file path</returns>
        public virtual string GetWorldFilePath(GameSettings settings) => GetWorldFolderPath(settings.World) + $"{GetWorldName(settings.World)}.XXX";

        /// <summary>
        /// Gets the folder path for the specified world
        /// </summary>
        /// <param name="world">The world</param>
        /// <returns>The world folder path</returns>
        public virtual string GetWorldFolderPath(World world) => GetDataPath() + GetWorldName(world) + "/";

        /// <summary>
        /// Gets the base path for the game data
        /// </summary>
        /// <returns>The data path</returns>
        public virtual string GetDataPath() => "RAY/";

        /// <summary>
        /// Gets the levels for each world
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The levels</returns>
        public override KeyValuePair<World, int[]>[] GetLevels(GameSettings settings) => EnumHelpers.GetValues<World>().Select(w => new KeyValuePair<World, int[]>(w, Directory.EnumerateFiles(settings.GameDirectory + GetWorldFolderPath(w), $"{GetWorldName(w)}**.XXX", SearchOption.TopDirectoryOnly)
            .Select(FileSystem.GetFileNameWithoutExtensions)
            .Where(x => x.Length == 5)
            .Select(x => Int32.Parse(x.Substring(3)))
            .ToArray())).Where(x => x.Value.Any()).ToArray();

        /// <summary>
        /// Gets the available game actions
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The game actions</returns>
        public override GameAction[] GetGameActions(GameSettings settings)
        {
            return base.GetGameActions(settings).Concat(new GameAction[]
            {
                new GameAction("Export Palettes", false, true, (input, output) => ExportPaletteImageAsync(settings, output)),
            }).ToArray();
        }

        /// <summary>
        /// Gets the vignette file info
        /// </summary>
        /// <returns>The vignette file info</returns>
        protected override PS1VignetteFileInfo[] GetVignetteInfo() => new PS1VignetteFileInfo[]
        {
            new PS1VignetteFileInfo("RAY/IMA/CRD/END_01.R16", 320),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC.XXX", 206, 199, 182, 195, 214, 187),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC_CLOR.R16", 206),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC_MAR.R16 ", 195),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC_MOSR.R16", 182),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC_RAYR.R16", 187),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC_SKOR.R16", 199),
            new PS1VignetteFileInfo("RAY/IMA/CRD/VAC_TOOR.R16", 214),

            // EU only
            new PS1VignetteFileInfo("RAY/IMA/CRD/LANGUE.R16", 320),
            new PS1VignetteFileInfo("RAY/IMA/CRD/PIRACY.R16", 320),

            new PS1VignetteFileInfo("RAY/IMA/FND/NWORLD.R16"),
            new PS1VignetteFileInfo("RAY/IMA/FND/IMGF2.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/IMGF3.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/IMGF4.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/IMGF5.XXX"),
            // Ignore US exclusive duplicate
            //new PS1VignetteFileInfo("RAY/IMA/FND/IMGF21.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/JUNF1.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/JUNF2.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/JUNF3.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/JUNF4.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/JUNF5.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/JUNF6.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MONF1.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MONF2.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MONF3.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MONF4.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MONF5.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MUSF1.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MUSF2.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MUSF3.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MUSF4.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/MUSF5.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/CAVF1.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/CAVF2.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/CAVF3.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/CAVF4.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/CAVF5.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/CAVF6.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/GATF1.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/GATF2.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/GATF3.XXX"),
            new PS1VignetteFileInfo("RAY/IMA/FND/IMGF1.XXX"),

            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_JOE.R16", 162),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_MUS.R16", 159),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_PR1.R16", 254),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_PR2.R16", 208),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_PR3.R16", 200),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_PR4.R16", 200),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_PR5.R16", 146),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_RAP.R16", 171),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_TRZ.R16", 178),
            new PS1VignetteFileInfo("RAY/IMA/VIG/CONTINUE.R16", 320),
            new PS1VignetteFileInfo("RAY/IMA/VIG/FND01.R16", 320),
            new PS1VignetteFileInfo("RAY/IMA/VIG/FND02.R16", 320),
            new PS1VignetteFileInfo("RAY/IMA/VIG/LOGO_UBI.R16", 640),
            new PS1VignetteFileInfo("RAY/IMA/VIG/PRE.XXX", 254, 208, 200, 200, 146),
            new PS1VignetteFileInfo("RAY/IMA/VIG/PRESENT.R16", 279),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_01R.R16", 219),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_02R.R16", 231),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_03R.R16", 257),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_04R.R16", 200),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_05R.R16", 146),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_06R.R16", 203),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_DRK.R16", 168),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_END.R16", 306),

            // JP only
            new PS1VignetteFileInfo("RAY/IMA/VIG/PRES01A.R16", 640),
            new PS1VignetteFileInfo("RAY/IMA/VIG/PRES01B.R16", 640),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_CAK.R16", 203),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_CAV.R16", 146),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_HLO.R16", 320),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_IMG.R16", 200),
            new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_JUN.R16", 219),
            // This one seems broken or using some weird encoding
            //new PS1VignetteFileInfo("RAY/IMA/VIG/VIG_MON.R16", ???),
        };

        /// <summary>
        /// Gets the base directory name for exporting a common design
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <param name="des">The design to export</param>
        /// <returns>The base directory name</returns>
        protected override string GetExportDirName(GameSettings settings, Common_Design des)
        {
            // Get the file path
            var path = des.FilePath;

            if (path == null)
                throw new Exception("Path can not be null");

            if (path == GetAllfixFilePath(settings))
                return $"Allfix/";
            else if (path == GetWorldFilePath(settings))
                return $"{settings.World}/{settings.World} - ";
            else if (path == GetLevelFilePath(settings))
                return $"{settings.World}/{settings.World}{settings.Level} - ";

            return $"Unknown/";
        }

        public async UniTask ExportPaletteImageAsync(GameSettings settings, string outputPath)
        {
            var spritePals = new List<ARGB1555Color[]>();
            var tilePals = new List<ARGB1555Color[]>();

            void Add(ICollection<ARGB1555Color[]> pals, ARGB1555Color[] pal)
            {
                if (pal != null && !pals.Any(x => x.SequenceEqual(pal)))
                    pals.Add(pal);
            }

            // Enumerate every world
            foreach (var world in GetLevels(settings))
            {
                settings.World = world.Key;
                settings.Level = 1;

                using (var context = new Context(settings))
                {
                    // Read the allfix file
                    await LoadExtraFile(context, GetAllfixFilePath(context.Settings));
                    var allfix = FileFactory.Read<PS1_R1_AllfixFile>(GetAllfixFilePath(context.Settings), context);

                    // Read the BigRay file
                    await LoadExtraFile(context, GetBigRayFilePath(context.Settings));
                    var br = FileFactory.Read<PS1_R1_BigRayFile>(GetBigRayFilePath(context.Settings), context);

                    Add(spritePals, allfix.Palette1);
                    Add(spritePals, allfix.Palette2);
                    Add(spritePals, allfix.Palette3);
                    Add(spritePals, allfix.Palette4);
                    Add(spritePals, allfix.Palette5);
                    Add(spritePals, allfix.Palette6);
                    Add(spritePals, br.Palette1);
                    Add(spritePals, br.Palette2);

                    // Read the world file
                    await LoadExtraFile(context, GetWorldFilePath(context.Settings));
                    var wld = FileFactory.Read<PS1_R1_WorldFile>(GetWorldFilePath(context.Settings), context);

                    Add(spritePals, wld.EventPalette1);
                    Add(spritePals, wld.EventPalette2);

                    foreach (var tilePal in wld.TilePalettes ?? new ARGB1555Color[0][])
                        Add(tilePals, tilePal);
                }
            }

            // Export
            PaletteHelpers.ExportPalette(Path.Combine(outputPath, $"{settings.GameModeSelection}.png"), spritePals.Concat(tilePals).SelectMany(x => x).ToArray(), optionalWrap: 256);
        }

        public override async UniTask ExportMenuSpritesAsync(GameSettings settings, string outputPath, bool exportAnimFrames)
        {
            using (var menuContext = new Context(settings)) 
            {
                using (var bigRayContext = new Context(settings))
                {
                    // Read the allfix & font files for the menu
                    await LoadExtraFile(menuContext, GetAllfixFilePath(menuContext.Settings));
                    var fix = FileFactory.Read<PS1_R1_AllfixFile>(GetAllfixFilePath(menuContext.Settings), menuContext);
                    await LoadExtraFile(menuContext, GetFontFilePath(menuContext.Settings));

                    // Read the BigRay file
                    await LoadExtraFile(bigRayContext, GetBigRayFilePath(bigRayContext.Settings));
                    var br = FileFactory.Read<PS1_R1_BigRayFile>(GetBigRayFilePath(bigRayContext.Settings), bigRayContext);

                    // Correct font palette
                    if (settings.EngineVersion == EngineVersion.RayPS1JP)
                    {
                        foreach (PS1_FontData font in fix.AllfixData.FontData)
                        {
                            foreach (Common_ImageDescriptor imgDescr in font.ImageDescriptors)
                            {
                                var paletteInfo = imgDescr.PaletteInfo;
                                paletteInfo = (ushort)BitHelpers.SetBits(paletteInfo, 509, 10, 6);
                                imgDescr.PaletteInfo = paletteInfo;
                            }
                        }
                    }
                    else
                    {
                        foreach (PS1_FontData font in fix.AllfixData.FontData)
                        {
                            foreach (Common_ImageDescriptor imgDescr in font.ImageDescriptors)
                            {
                                var paletteInfo = imgDescr.PaletteInfo;
                                paletteInfo = (ushort)BitHelpers.SetBits(paletteInfo, 492, 10, 6);
                                imgDescr.PaletteInfo = paletteInfo;
                            }
                        }
                    }

                    // Export
                    await ExportMenuSpritesAsync(menuContext, bigRayContext, outputPath, exportAnimFrames, fix.AllfixData.FontData, fix.AllfixData.MenuEvents, br.BigRayData);
                }
            }
        }
    }
}