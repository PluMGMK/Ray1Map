﻿using System;
using System.IO;
using System.Linq;
using R1Engine.Serialize;
using System.Threading.Tasks;
using System.Collections.Generic;
using UnityEngine;

namespace R1Engine
{
    /// <summary>
    /// The game manager for Rayman 1 (PS1 - Japan Demo Vol6)
    /// </summary>
    public class PS1_R1JPDemoVol6_Manager : PS1_Manager
    {
        /// <summary>
        /// The width of the tile set in tiles
        /// </summary>
        public override int TileSetWidth => 40;

        /// <summary>
        /// The file info to use
        /// </summary>
        protected override Dictionary<string, PS1FileInfo> FileInfo => PS1FileInfo.fileInfoDemoVol6;

        protected override PS1MemoryMappedFile.InvalidPointerMode InvalidPointerMode => PS1MemoryMappedFile.InvalidPointerMode.Allow;

        /// <summary>
        /// Gets the file path for the allfix file
        /// </summary>
        /// <returns>The allfix file path</returns>
        public virtual string GetAllfixFilePath() => $"RAY.DTA";

        /// <summary>
        /// Gets the file path for the world file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The world file path</returns>
        public virtual string GetWorldFilePath(GameSettings settings) => $"{GetWorldName(settings.World)}.DTA";

        /// <summary>
        /// Gets the file path for the level tile set file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The level tile set file path</returns>
        public string GetTileSetFilePath(GameSettings settings) => $"{GetWorldName(settings.World)}_OPT.R16";

        /// <summary>
        /// Gets the file path for the level file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The level file path</returns>
        public string GetLevelFilePath(GameSettings settings) => $"{GetWorldName(settings.World)}{settings.Level:00}.DTA";

        /// <summary>
        /// Gets the file path for the level map file
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The level map file path</returns>
        public string GetMapFilePath(GameSettings settings) => $"{GetWorldName(settings.World)}{settings.Level:00}.MAP";

        /// <summary>
        /// Gets the levels for each world
        /// </summary>
        /// <param name="settings">The game settings</param>
        /// <returns>The levels</returns>
        public override KeyValuePair<World, int[]>[] GetLevels(GameSettings settings) => EnumHelpers.GetValues<World>().Select(w => new KeyValuePair<World, int[]>(w, Directory.EnumerateFiles(settings.GameDirectory, $"{GetWorldName(w)}*.MAP", SearchOption.TopDirectoryOnly)
            .Select(FileSystem.GetFileNameWithoutExtensions)
            .Select(x => Int32.Parse(x.Substring(3)))
            .ToArray())).ToArray();

        /// <summary>
        /// Gets the tile set to use
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>The tile set to use</returns>
        public override Common_Tileset GetTileSet(Context context)
        {
            // Get the file name
            var filename = GetTileSetFilePath(context.Settings);

            // Read the file
            var tileSet = FileFactory.Read<ObjectArray<ARGB1555Color>>(filename, context, (s, x) => x.Length = s.CurrentLength / 2);

            // Return the tile set
            return new Common_Tileset(tileSet.Value, TileSetWidth, CellSize);
        }

        /// <summary>
        /// Fills the PS1 v-ram and returns it
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>The filled v-ram</returns>
        public override void FillVRAM(Context context)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets the sprite texture for an event
        /// </summary>
        /// <param name="context">The context</param>
        /// <param name="e">The event</param>
        /// <param name="s">The image descriptor to use</param>
        /// <returns>The texture</returns>
        public override Texture2D GetSpriteTexture(Context context, PS1_R1_Event e, Common_ImageDescriptor s)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Loads the specified level for the editor
        /// </summary>
        /// <param name="context">The serialization context</param>
        /// <param name="loadTextures">Indicates if textures should be loaded</param>
        /// <returns>The editor manager</returns>
        public override async Task<BaseEditorManager> LoadAsync(Context context, bool loadTextures)
        {
            // Get the file paths
            var allfixPath = GetAllfixFilePath();
            var worldPath = GetWorldFilePath(context.Settings);
            var levelPath = GetLevelFilePath(context.Settings);
            var mapPath = GetMapFilePath(context.Settings);
            var tileSetPath = GetTileSetFilePath(context.Settings);

            // Load the files
            await LoadExtraFile(context, allfixPath);
            await LoadExtraFile(context, worldPath);
            await LoadExtraFile(context, levelPath);
            await LoadExtraFile(context, mapPath);
            await LoadExtraFile(context, tileSetPath);

            // Read the files
            var map = FileFactory.Read<PS1_R1_MapBlock>(mapPath, context);
            var level = FileFactory.Read<PS1_R1JPDemo_LevFile>(levelPath, context);

            // Load the level
            return await LoadAsync(context, map, level.Events, level.EventLinkTable.Select(x => (ushort)x).ToArray(), 
                // TODO: Change this to "loadTextures"!
                false);
        }

        /// <summary>
        /// Gets the vignette file info
        /// </summary>
        /// <returns>The vignette file info</returns>
        protected override PS1VignetteFileInfo[] GetVignetteInfo() => new PS1VignetteFileInfo[]
        {
            new PS1VignetteFileInfo("JUN_F01.R16"),
            new PS1VignetteFileInfo("LOGO_UBI.R16", 640),
            new PS1VignetteFileInfo("PRES01A.R16", 640),
            new PS1VignetteFileInfo("PRES01B.R16", 640),
        };
    }
}