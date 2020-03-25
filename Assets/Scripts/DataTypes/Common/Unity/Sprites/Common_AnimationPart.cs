﻿using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace R1Engine {
    public class Common_AnimationPart {
        /// <summary>
        /// The sprite
        /// </summary>
        public int SpriteIndex { get; set; }

        /// <summary>
        /// The x position
        /// </summary>
        public int X { get; set; }

        /// <summary>
        /// The y position
        /// </summary>
        public int Y { get; set; }

        /// <summary>
        /// Flipped or not?
        /// </summary>
        public bool Flipped { get; set; }
    }
}