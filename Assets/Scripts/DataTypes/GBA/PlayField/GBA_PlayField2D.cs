﻿namespace R1Engine
{
    // 0x03000e20 has pointer to this struct for the current level during runtime

    public class GBA_PlayField2D : GBA_BaseBlock
    {
        #region PlayField Data

        public bool IsMode7 { get; set; }

        public byte TileMapIndex { get; set; }

        // Seems to determine the tilemap for BG_0
        public byte Unk_02 { get; set; }
        
        public byte Unk_03 { get; set; }

        // For BG_0 parallax scrolling?
        // 0-4 (isn't it 0-3?)
        public byte ClusterCount { get; set; }

        // 0-5
        public byte LayerCount { get; set; }
        
        public byte[] ClusterTable { get; set; }
        public byte[] LayerTable { get; set; }

        // Prince of Persia
        public byte[] UnkBytes1 { get; set; }
        public byte[] UnkBytes2 { get; set; }

        // Batman: Vengeance
        public byte TilePaletteIndex { get; set; }
        #endregion

        #region Parsed

        public GBA_Cluster[] Clusters { get; set; }
        public GBA_TileLayer[] Layers { get; set; }
        public GBA_TileMap Tilemap { get; set; }

        public byte[] ClusterData { get; set; }
        public GBA_Batman_TileLayer[] BatmanLayers { get; set; }

        // Batman: Vengeance
        public GBA_Palette TilePalette { get; set; }
        #endregion

        #region Public Methods

        public override void SerializeImpl(SerializerObject s)
        {
            if (s.GameSettings.EngineVersion == EngineVersion.PrinceOfPersiaGBA ||
                s.GameSettings.EngineVersion == EngineVersion.StarWarsGBA) {
                UnkBytes1 = s.SerializeArray<byte>(UnkBytes1, 3, name: nameof(UnkBytes1));
                TileMapIndex = s.Serialize<byte>(TileMapIndex, name: nameof(TileMapIndex));
                Unk_02 = s.Serialize<byte>(Unk_02, name: nameof(Unk_02));
                Unk_03 = s.Serialize<byte>(Unk_03, name: nameof(Unk_03));
                UnkBytes2 = s.SerializeArray<byte>(UnkBytes2, 2, name: nameof(UnkBytes2));
            } else if(s.GameSettings.EngineVersion == EngineVersion.BatmanVengeanceGBA) {
                TilePaletteIndex = s.Serialize<byte>(TilePaletteIndex, name: nameof(TilePaletteIndex));
            } else {
                IsMode7 = s.Serialize<bool>(IsMode7, name: nameof(IsMode7));

                // Mode7 maps have a different structure
                if (IsMode7)
                    return;

                TileMapIndex = s.Serialize<byte>(TileMapIndex, name: nameof(TileMapIndex));
                Unk_02 = s.Serialize<byte>(Unk_02, name: nameof(Unk_02));
                Unk_03 = s.Serialize<byte>(Unk_03, name: nameof(Unk_03));
            }

            ClusterCount = s.Serialize<byte>(ClusterCount, name: nameof(ClusterCount));
            LayerCount = s.Serialize<byte>(LayerCount, name: nameof(LayerCount));

            if (s.GameSettings.EngineVersion != EngineVersion.BatmanVengeanceGBA) {
                ClusterTable = s.SerializeArray<byte>(ClusterTable, 4, name: nameof(ClusterTable));
                LayerTable = s.SerializeArray<byte>(LayerTable, 6, name: nameof(LayerTable));
            } else {
                UnkBytes1 = s.SerializeArray<byte>(UnkBytes1, 1, name: nameof(UnkBytes1));
                ClusterData = s.SerializeArray<byte>(ClusterData, 0x10 * ClusterCount, name: nameof(ClusterData));
                ClusterData = s.SerializeArray<byte>(ClusterData, 0x10 * ClusterCount, name: nameof(ClusterData));
                BatmanLayers = s.SerializeObjectArray<GBA_Batman_TileLayer>(BatmanLayers, LayerCount, name: nameof(BatmanLayers));
            }
        }

        public override void SerializeOffsetData(SerializerObject s)
        {
            if (s.GameSettings.EngineVersion != EngineVersion.BatmanVengeanceGBA) {
                if (Clusters == null)
                    Clusters = new GBA_Cluster[ClusterCount];

                // Serialize layers
                for (int i = 0; i < ClusterCount; i++)
                    Clusters[i] = s.DoAt(OffsetTable.GetPointer(ClusterTable[i]), () => s.SerializeObject<GBA_Cluster>(Clusters[i], name: $"{nameof(Clusters)}[{i}]"));

                if (Layers == null)
                    Layers = new GBA_TileLayer[LayerCount];

                // Serialize layers
                for (int i = 0; i < LayerCount; i++)
                    Layers[i] = s.DoAt(OffsetTable.GetPointer(LayerTable[i]), () => s.SerializeObject<GBA_TileLayer>(Layers[i], name: $"{nameof(Layers)}[{i}]"));


                // Serialize tilemap
                Tilemap = s.DoAt(OffsetTable.GetPointer(TileMapIndex), () => s.SerializeObject<GBA_TileMap>(Tilemap, name: nameof(Tilemap)));
            } else {
                // Serialize tile palette
                TilePalette = s.DoAt(OffsetTable.GetPointer(TilePaletteIndex), () => s.SerializeObject<GBA_Palette>(TilePalette, name: nameof(TilePalette)));

                if (Layers == null)
                    Layers = new GBA_TileLayer[LayerCount];

                // Serialize layers
                for (int i = 0; i < LayerCount; i++)
                    s.DoAt(OffsetTable.GetPointer(BatmanLayers[i].LayerID), () => {
                        Layers[i] = s.SerializeObject<GBA_TileLayer>(Layers[i], onPreSerialize: l => {
                            l.IsCompressed = BatmanLayers[i].IsCompressed;
                            l.IsCollisionBlock = BatmanLayers[i].IsCollisionBlock;
                            l.Width = BatmanLayers[i].Width;
                            l.Height = BatmanLayers[i].Height;
                        }, name: $"{nameof(Layers)}[{i}]");
                    });

            }
        }

		#endregion

		public class GBA_Batman_TileLayer : R1Serializable {
            public byte LayerID { get; set; }
            public bool IsCollisionBlock { get; set; }
            public bool IsCompressed { get; set; }
            public byte Unk_03 { get; set; }

            public ushort Width { get; set; }
            public ushort Height { get; set; }
            public override void SerializeImpl(SerializerObject s) {
                LayerID = s.Serialize<byte>(LayerID, name: nameof(LayerID));
                IsCollisionBlock = s.Serialize<bool>(IsCollisionBlock, name: nameof(IsCollisionBlock));

                IsCompressed = s.Serialize<bool>(IsCompressed, name: nameof(IsCompressed));
                Unk_03 = s.Serialize<byte>(Unk_03, name: nameof(Unk_03));

                Width = s.Serialize<ushort>(Width, name: nameof(Width));
                Height = s.Serialize<ushort>(Height, name: nameof(Height));
            }
		}
	}
}