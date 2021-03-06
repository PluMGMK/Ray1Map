﻿namespace R1Engine
{
    public class GBA_ActorGraphicData : GBA_BaseBlock
    {
        public byte[] UnkData { get; set; }

        public byte SpriteGroupOffsetIndex { get; set; }
        public byte Byte_09 { get; set; }
        public byte Byte_0A { get; set; }
        public byte Byte_0B { get; set; }

        public GBA_ActorState[] States { get; set; }

        public GBA_SpriteGroup SpriteGroup { get; set; }
        public GBA_BatmanVengeance_SpriteGroup SpriteGroup_BatmanVengeance { get; set; }

        public override void SerializeBlock(SerializerObject s)
        {
            if (s.GameSettings.EngineVersion > EngineVersion.GBA_BatmanVengeance) {
                UnkData = s.SerializeArray<byte>(UnkData, 8, name: nameof(UnkData));
            }

            SpriteGroupOffsetIndex = s.Serialize<byte>(SpriteGroupOffsetIndex, name: nameof(SpriteGroupOffsetIndex));
            Byte_09 = s.Serialize<byte>(Byte_09, name: nameof(Byte_09));
            Byte_0A = s.Serialize<byte>(Byte_0A, name: nameof(Byte_0A));
            Byte_0B = s.Serialize<byte>(Byte_0B, name: nameof(Byte_0B));

            // TODO: Get number of entries
            if (s.GameSettings.EngineVersion <= EngineVersion.GBA_BatmanVengeance) {
                States = s.SerializeObjectArray<GBA_ActorState>(States, (BlockSize - 4) / 12, name: nameof(States));
            } else {
                States = s.SerializeObjectArray<GBA_ActorState>(States, (BlockSize - 12) / 8, name: nameof(States));
            }
        }

        public override void SerializeOffsetData(SerializerObject s)
        {
            if (s.GameSettings.EngineVersion == EngineVersion.GBA_BatmanVengeance) {
                SpriteGroup_BatmanVengeance = s.DoAt(OffsetTable.GetPointer(SpriteGroupOffsetIndex), () => s.SerializeObject<GBA_BatmanVengeance_SpriteGroup>(SpriteGroup_BatmanVengeance, name: nameof(SpriteGroup_BatmanVengeance)));
            } else {
                SpriteGroup = s.DoAt(OffsetTable.GetPointer(SpriteGroupOffsetIndex), () => s.SerializeObject<GBA_SpriteGroup>(SpriteGroup, name: nameof(SpriteGroup)));
            }

            // Parse state data
            for (var i = 0; i < States.Length; i++)
            {
                if (States[i].StateDataType != -1)
                    States[i].StateData = s.DoAt(OffsetTable.GetPointer(States[i].StateDataOffsetIndex), () => s.SerializeObject<GBA_ActorStateData>(States[i].StateData, name: $"{nameof(GBA_ActorState.StateData)}[{i}]"));
            }
        }
    }
}