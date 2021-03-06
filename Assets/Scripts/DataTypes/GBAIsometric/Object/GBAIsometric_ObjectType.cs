﻿namespace R1Engine
{
    public class GBAIsometric_ObjectType : R1Serializable
    {
        public uint Uint_00 { get; set; }
        public Pointer<GBAIsometric_ObjectTypeData> DataPointer { get; set; }

        public override void SerializeImpl(SerializerObject s)
        {
            Uint_00 = s.Serialize<uint>(Uint_00, name: nameof(Uint_00));
            DataPointer = s.SerializePointer<GBAIsometric_ObjectTypeData>(DataPointer, resolve: true, name: nameof(DataPointer));
        }
    }
}