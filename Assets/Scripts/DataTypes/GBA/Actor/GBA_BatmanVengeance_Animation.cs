﻿using System.Collections.Generic;

namespace R1Engine
{
    public class GBA_BatmanVengeance_Animation : R1Serializable {
        #region Data

        public uint FrameCount { get; set; }

        public uint[] FrameOffsets { get; set; }

        #endregion

        #region Parsed

        public GBA_BatmanVengeance_AnimationFrame[] Frames { get; set; }

        #endregion

        #region Public Methods

        public override void SerializeImpl(SerializerObject s)
        {
            FrameCount = s.Serialize<uint>(FrameCount, name: nameof(FrameCount));

            FrameOffsets = s.SerializeArray<uint>(FrameOffsets, FrameCount, name: nameof(FrameOffsets));
            if (Frames == null) Frames = new GBA_BatmanVengeance_AnimationFrame[FrameCount];
            for (int i = 0; i < FrameOffsets.Length; i++) {
                s.DoAt(Offset + 4 + FrameOffsets[i], () => {
                    Frames[i] = s.SerializeObject<GBA_BatmanVengeance_AnimationFrame>(Frames[i], name: $"{nameof(Frames)}[{i}]");
                });
            }
        }

        #endregion
    }
}