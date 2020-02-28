﻿using System;
using System.IO;
using System.Linq;

namespace R1Engine
{
    /// <summary>
    /// The game manager for Rayman 1 (PC)
    /// </summary>
    public class PC_R1_Manager : IGameManager
    {
        /// <summary>
        /// The currently loaded level data
        /// </summary>
        public PC_R1_LevFile LevelData { get; set; }

        /// <summary>
        /// Gets the folder name for the specified world
        /// </summary>
        /// <param name="world">The world</param>
        /// <returns>The folder name</returns>
        public string GetWorldFolderName(World world)
        {
            switch (world)
            {
                case World.Jungle:
                    return "JUNGLE";
                case World.Music:
                    return "MUSIC";
                case World.Mountain:
                    return "MOUNTAIN";
                case World.Image:
                    return "IMAGE";
                case World.Cave:
                    return "CAVE";
                case World.Cake:
                    return "CAKE";
                default:
                    throw new ArgumentOutOfRangeException(nameof(world), world, null);
            }
        }

        /// <summary>
        /// Gets the file path for the specified level
        /// </summary>
        /// <param name="basePath">The base game path</param>
        /// <param name="world">The world</param>
        /// <param name="level">The level</param>
        /// <returns>The level file path</returns>
        public string GetLevelFilePath(string basePath, World world, int level)
        {
            return Path.Combine(basePath, GetWorldFolderName(world), $"RAY{level}.LEV");
        }

        /// <summary>
        /// Loads the specified level
        /// </summary>
        /// <param name="basePath">The base game path</param>
        /// <param name="world">The world</param>
        /// <param name="level">The level</param>
        /// <returns>The level</returns>
        public Common_Lev LoadLevel(string basePath, World world, int level)
        {
            // Open the level
            using (var lvlFile = File.OpenRead(GetLevelFilePath(basePath, world, level)))
                // Read the level
                LevelData = lvlFile.Read<PC_R1_LevFile>();

            var commonLvl = new Common_Lev()
            {
                Width = LevelData.MapWidth,
                Height = LevelData.MapHeight,

                // TODO: Clean up by making a common event class
                Events = LevelData.Events.Select(x => new Event()
                {
                    pos = new PxlVec((ushort)x.XPosition, (ushort)x.YPosition)
                }).ToArray(),
                
                // TODO: Clean up by making a common event class
                Tiles = new Type[LevelData.Tiles.Length],
                
                // TODO: Need to set this or else it crashes
                TileSet = null
            };

            // Set the tiles
            for (int y = 0; y < LevelData.MapHeight; y++)
            {
                for (int x = 0; x < LevelData.MapWidth; x++)
                {
                    var index = y * LevelData.MapWidth + x;

                    commonLvl.Tiles[index] = new Type()
                    {
                        col = LevelData.Tiles[index].CollisionType,
                        gX = x,
                        gY = y
                    };
                }
            }

            return commonLvl;
        }
    }
}