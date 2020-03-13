﻿using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace R1Engine
{
    /// <summary>
    /// Event localization data for Rayman Mapper (PC)
    /// </summary>
    [Description("Rayman Mapper (PC) Event Localization File")]
    public class PC_Mapper_EventLocFile : PC_BaseFile
    {
        /// <summary>
        /// The amount of localization items
        /// </summary>
        public uint LocCount { get; set; }

        /// <summary>
        /// Unknown header values
        /// </summary>
        public ushort[] Unknown2 { get; set; }

        /// <summary>
        /// The localization items
        /// </summary>
        public PC_Mapper_EventLocItem[] LocItems { get; set; }

        /// <summary>
        /// Deserializes the file contents
        /// </summary>
        /// <param name="deserializer">The deserializer</param>
        public override void Deserialize(BinaryDeserializer deserializer)
        {
            base.Deserialize(deserializer);

            LocCount = deserializer.Read<uint>();

            // TODO: Find way to avoid this
            // Since we don't know the length we go on until we hit the bytes for the localization items (they always start with MS)
            byte[] values;
            List<ushort> tempList = new List<ushort>();

            while (Settings.StringEncoding.GetString(values = deserializer.ReadArray<byte>(2)) != "MS")
                tempList.Add(BitConverter.ToUInt16(values, 0));

            Unknown2 = tempList.ToArray();

            // Go back two steps...
            deserializer.BaseStream.Position -= 2;

            LocItems = deserializer.ReadArray<PC_Mapper_EventLocItem>(LocCount);
        }

        /// <summary>
        /// Serializes the file contents
        /// </summary>
        /// <param name="serializer">The serializer</param>
        public override void Serialize(BinarySerializer serializer)
        {
            base.Serialize(serializer);

            serializer.Write(LocCount);
            serializer.Write(Unknown2);
            serializer.Write(LocItems);
        }
    }
}