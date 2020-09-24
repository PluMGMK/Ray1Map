﻿using System;
using System.Collections.Generic;
using Cysharp.Threading.Tasks;
using R1Engine.Serialize;

namespace R1Engine
{
    /// <summary>
    /// The game manager for Rayman 1 (PS1 - EU Demo)
    /// </summary>
    public class R1_PS1EUDemo_Manager : R1_PS1_Manager
    {
        /// <summary>
        /// Gets the folder path for the specified world
        /// </summary>
        /// <param name="world">The world</param>
        /// <returns>The world folder path</returns>
        public override string GetWorldFolderPath(R1_World world) => String.Empty;

        public string GetLanguageFilePath(string langCode) => $"IMA/RAY{langCode}.TXT";

        /// <summary>
        /// Gets the base path for the game data
        /// </summary>
        /// <returns>The data path</returns>
        public override string GetDataPath() => String.Empty;

        /// <summary>
        /// Gets the file info to use
        /// </summary>
        /// <param name="settings">The game settings</param>
        protected override Dictionary<string, PS1FileInfo> GetFileInfo(GameSettings settings) => PS1FileInfo.fileInfoPALDemo;

        public override string GetExeFilePath => "RAY.EXE";

        protected override async UniTask<IReadOnlyDictionary<string, string[]>> LoadLocalizationAsync(Context context)
        {
            var filePath = GetLanguageFilePath("US");

            await FileSystem.PrepareFile(context.BasePath + filePath);

            // Create the dictionary
            return new Dictionary<string, string[]>()
            {
                ["English"] = FileFactory.ReadText<R1_TextLocFile>(filePath, context).Strings
            };
        }

        public override uint? TypeZDCOffset => 0x93998;
        public override uint? ZDCDataOffset => 0x92998;
        public override uint? EventFlagsOffset => 0x92198;
    }
}