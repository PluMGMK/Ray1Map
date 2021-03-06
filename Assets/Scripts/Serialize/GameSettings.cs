﻿using System;

namespace R1Engine
{
    /// <summary>
    /// Common game settings
    /// </summary>
    public class GameSettings
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="gameModeSelection">The game mode selection</param>
        /// <param name="gameDirectory">The game directory</param>
        /// <param name="world">The game world</param>
        /// <param name="level">The game level, starting at 1</param>
        public GameSettings(GameModeSelection gameModeSelection, string gameDirectory, int world, int level)
        {
            // Get the attribute data
            var atr = gameModeSelection.GetAttribute<GameModeAttribute>();

            GameModeSelection = gameModeSelection;
            Game = atr.Game;
            EngineVersion = atr.EngineVersion;
            MajorEngineVersion = atr.MajorEngineVersion;
            GameDirectory = Util.NormalizePath(gameDirectory, isFolder: true);
            World = world;
            Level = level;
        }

        /// <summary>
        /// The game mode selection
        /// </summary>
        public GameModeSelection GameModeSelection { get; }

        /// <summary>
        /// The major engine version
        /// </summary>
        public MajorEngineVersion MajorEngineVersion { get; }

        /// <summary>
        /// The engine version
        /// </summary>
        public EngineVersion EngineVersion { get; }

        /// <summary>
        /// The game
        /// </summary>
        public Game Game { get; }

        /// <summary>
        /// The game directory
        /// </summary>
        public string GameDirectory { get; set; }

        /// <summary>
        /// The game world
        /// </summary>
        public int World { get; set; }

        public R1_World R1_World
        {
            get => (R1_World) World;
            set => World = (int)value;
        }

        /// <summary>
        /// The game level, starting at 1
        /// </summary>
        public int Level { get; set; }

        /// <summary>
        /// The educational game volume name
        /// </summary>
        public string EduVolume { get; set; }

        public IGameManager GetGameManager => (IGameManager)Activator.CreateInstance(GameModeSelection.GetAttribute<GameModeAttribute>().ManagerType);
    }
}