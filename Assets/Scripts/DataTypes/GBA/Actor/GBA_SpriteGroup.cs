﻿using System.Collections.Generic;

namespace R1Engine
{
    public class GBA_SpriteGroup : GBA_BaseBlock {
        #region Data

        public byte Byte_00 { get; set; }
        public byte Byte_01 { get; set; }
        public byte TileMapOffsetIndex { get; set; }
        public byte PaletteOffsetIndex { get; set; }
        public byte UnkOffsetIndex3 { get; set; }
        public byte Byte_04 { get; set; }
        public byte AnimationsCount { get; set; }
        public byte Byte_06 { get; set; }

        public byte[] AnimationIndexTable { get; set; }

        #endregion

        #region Parsed

        public GBA_SpritePalette Palette { get; set; }
        public GBA_SpriteTileMap TileMap { get; set; }
        public GBA_Animation[] Animations { get; set; }
        public Dictionary<int, GBA_AffineMatrixList> Matrices { get; set; } = new Dictionary<int, GBA_AffineMatrixList>();

        #endregion

        #region Public Methods

        public override void SerializeBlock(SerializerObject s)
        {
            if (s.GameSettings.EngineVersion != EngineVersion.GBA_Sabrina)
            {
                Byte_00 = s.Serialize<byte>(Byte_00, name: nameof(Byte_00));
                Byte_01 = s.Serialize<byte>(Byte_01, name: nameof(Byte_01));
            }

            TileMapOffsetIndex = s.Serialize<byte>(TileMapOffsetIndex, name: nameof(TileMapOffsetIndex));
            PaletteOffsetIndex = s.Serialize<byte>(PaletteOffsetIndex, name: nameof(PaletteOffsetIndex));

            if (s.GameSettings.EngineVersion >= EngineVersion.GBA_PrinceOfPersia)
                UnkOffsetIndex3 = s.Serialize<byte>(UnkOffsetIndex3, name: nameof(UnkOffsetIndex3));

            Byte_04 = s.Serialize<byte>(Byte_04, name: nameof(Byte_04));
            AnimationsCount = s.Serialize<byte>(AnimationsCount, name: nameof(AnimationsCount));
            Byte_06 = s.Serialize<byte>(Byte_06, name: nameof(Byte_06));

            AnimationIndexTable = s.SerializeArray<byte>(AnimationIndexTable, AnimationsCount, name: nameof(AnimationIndexTable));
        }

        public override void SerializeOffsetData(SerializerObject s)
        {
            Palette = s.DoAt(OffsetTable.GetPointer(PaletteOffsetIndex), () => s.SerializeObject<GBA_SpritePalette>(Palette, name: nameof(Palette)));
            TileMap = s.DoAt(OffsetTable.GetPointer(TileMapOffsetIndex), () => s.SerializeObject<GBA_SpriteTileMap>(TileMap, onPreSerialize: x =>
            {
                if (s.GameSettings.EngineVersion == EngineVersion.GBA_Sabrina)
                    x.IsDataCompressed = BitHelpers.ExtractBits(Byte_04, 1, 5) == 0;
            }, name: nameof(TileMap)));

            if (Animations == null)
                Animations = new GBA_Animation[AnimationsCount];

            for (int i = 0; i < Animations.Length; i++)
                Animations[i] = s.DoAt(OffsetTable.GetPointer(AnimationIndexTable[i]), () => s.SerializeObject<GBA_Animation>(Animations[i], name: $"{nameof(Animations)}[{i}]"));

            for (int i = 0; i < Animations.Length; i++) {
                if (Animations[i] == null) continue;
                int matrixIndex = Animations[i].AffineMatricesIndex;
                if (matrixIndex != 0) {

                    Matrices[matrixIndex] = s.DoAt(OffsetTable.GetPointer(matrixIndex),
                        () => s.SerializeObject<GBA_AffineMatrixList>(
                            Matrices.ContainsKey(matrixIndex) ? Matrices[matrixIndex] : null,
                            onPreSerialize: ml => ml.FrameCount = Animations[i].FrameCount,
                            name: $"{nameof(Matrices)}[{matrixIndex}]"));
                }
            }
        }

        #endregion
    }
}