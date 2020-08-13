﻿namespace R1Engine
{
    public class GBA_LevelBlock : GBA_BaseBlock
    {
        #region Level Data

        public ushort PlayFieldIndex { get; set; }
        public byte Unk_02 { get; set; }
        public byte Unk_03 { get; set; }

        public byte ObjectsCountTotal { get; set; }
        public byte ObjectsCount1 { get; set; }
        public byte ObjectsCount2 { get; set; }
        public byte Unk_07 { get; set; }
        public byte Unk_08 { get; set; }
        public byte Unk_09 { get; set; }
        public byte Unk_0A { get; set; }
        public byte Unk_0B { get; set; }

        public GBA_Actor[] Actors { get; set; }

        public byte[] UnkData { get; set; }

        #endregion

        #region Parsed

        public GBA_PlayField PlayField { get; set; }

        #endregion

        #region Public Methods

        public override void SerializeImpl(SerializerObject s)
        {
            PlayFieldIndex = s.Serialize<ushort>(PlayFieldIndex, name: nameof(PlayFieldIndex));
            Unk_02 = s.Serialize<byte>(Unk_02, name: nameof(Unk_02));
            Unk_03 = s.Serialize<byte>(Unk_03, name: nameof(Unk_03));

            ObjectsCountTotal = s.Serialize<byte>(ObjectsCountTotal, name: nameof(ObjectsCountTotal));
            ObjectsCount1 = s.Serialize<byte>(ObjectsCount1, name: nameof(ObjectsCount1));
            ObjectsCount2 = s.Serialize<byte>(ObjectsCount2, name: nameof(ObjectsCount2));
            Unk_07 = s.Serialize<byte>(Unk_07, name: nameof(Unk_07));

            Unk_08 = s.Serialize<byte>(Unk_08, name: nameof(Unk_08));
            Unk_09 = s.Serialize<byte>(Unk_09, name: nameof(Unk_09));
            Unk_0A = s.Serialize<byte>(Unk_0A, name: nameof(Unk_0A));
            Unk_0B = s.Serialize<byte>(Unk_0B, name: nameof(Unk_0B));

            if (s.GameSettings.EngineVersion == EngineVersion.PrinceOfPersiaGBA || s.GameSettings.EngineVersion == EngineVersion.Ray3GBA) {
                Actors = s.SerializeObjectArray<GBA_Actor>(Actors, ObjectsCount1 + ObjectsCount2, name: nameof(Actors));
            } else {
                Actors = s.SerializeObjectArray<GBA_Actor>(Actors, ObjectsCountTotal, name: nameof(Actors));
            }

            // TODO: What is this data?
            //Controller.print(Actors.Sum(a => a.Unk_0B));
            Controller.print("Length of unknown data: " + (BlockSize - (s.CurrentPointer - Offset)));
            UnkData = s.SerializeArray<byte>(UnkData, BlockSize - (s.CurrentPointer - Offset), name: nameof(UnkData));
        }

        public override void SerializeOffsetData(SerializerObject s)
        {
            // Parse level block data
            PlayField = s.DoAt(OffsetTable.GetPointer(PlayFieldIndex), () => s.SerializeObject<GBA_PlayField>(PlayField, name: nameof(PlayField)));

            if (s.GameSettings.EngineVersion == EngineVersion.StarWarsGBA || s.GameSettings.EngineVersion == EngineVersion.BatmanVengeanceGBA) return;
            // Parse actor data
            for (var i = 0; i < Actors.Length; i++)
            {
                if (Actors[i].GraphicsDataIndex < OffsetTable.OffsetsCount)
                    Actors[i].GraphicData = s.DoAt(OffsetTable.GetPointer(Actors[i].GraphicsDataIndex),
                        () => s.SerializeObject<GBA_ActorGraphicData>(Actors[i].GraphicData,
                            name: $"{nameof(GBA_Actor.GraphicData)}[{i}]"));
            }
        }

        #endregion
    }
}