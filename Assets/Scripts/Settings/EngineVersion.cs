﻿using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace R1Engine
{
    /// <summary>
    /// The available game modes
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum EngineVersion
    {
        /// <summary>
        /// Rayman 1 (PS1)
        /// </summary>
        RayPS1,

        /// <summary>
        /// Rayman 1 (PS1 - JP)
        /// </summary>
        RayPS1JP,

        /// <summary>
        /// Rayman 1 (PS1 - JP Demos)
        /// </summary>
        RayPS1JPDemo,

        /// <summary>
        /// Rayman 1 (Saturn)
        /// </summary>
        RaySaturn,

        /// <summary>
        /// Rayman 1 (PC)
        /// </summary>
        RayPC,

        /// <summary>
        /// Rayman Designer + spin-offs (PC)
        /// </summary>
        RayKit,

        /// <summary>
        /// Educational Rayman games (PC)
        /// </summary>
        RayEduPC,

        /// <summary>
        /// Rayman Ultimate (Pocket PC)
        /// </summary>
        RayPocketPC,
    }
}