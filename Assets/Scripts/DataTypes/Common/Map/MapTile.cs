﻿using System;

namespace R1Engine
{
    /// <summary>
    /// Common map tile data
    /// </summary>
    public class MapTile : R1Serializable, ICloneable
    {
        /// <summary>
        /// The tile map x position
        /// </summary>
        public ushort TileMapX { get; set; }

        /// <summary>
        /// The tile map y position
        /// </summary>
        public ushort TileMapY { get; set; }

        /// <summary>
        /// The tile collision type
        /// </summary>
        public byte CollisionType { get; set; }

        public byte PC_Unk1 { get; set; }

        /// <summary>
        /// The transparency mode for this cell
        /// </summary>
        public R1_PC_MapTileTransparencyMode PC_TransparencyMode { get; set; }

        public byte PC_Unk2 { get; set; }

        public bool HorizontalFlip { get; set; }
        public bool VerticalFlip { get; set; }

        public byte PaletteIndex { get; set; }

        public GBA_TileType GBATileType { get; set; } = GBA_TileType.Normal;
        public bool Is8Bpp { get; set; }
        public bool IsFirstBlock { get; set; }

        public GBARRR_MapBlock.MapType GBARRRType { get; set; }
        public byte GBARRR_MenuUnk { get; set; }

        public enum GBA_TileType {
            BGTile,
            Normal,
            FGTile,
            Mode7Tile
        }

        /// <summary>
        /// Handles the data serialization
        /// </summary>
        /// <param name="s">The serializer object</param>
        public override void SerializeImpl(SerializerObject s) 
        {
            if (s.GameSettings.GameModeSelection == GameModeSelection.MapperPC || s.GameSettings.EngineVersion == EngineVersion.R1_GBA|| s.GameSettings.EngineVersion == EngineVersion.R1_DSi)
            {
                TileMapY = s.Serialize<ushort>(TileMapY, name: nameof(TileMapY));
                TileMapX = 0;
                CollisionType = (byte)s.Serialize<ushort>((ushort)CollisionType, name: nameof(CollisionType));
            }
            else if (s.GameSettings.EngineVersion == EngineVersion.R1_PC || s.GameSettings.EngineVersion == EngineVersion.R1_PC_Kit || s.GameSettings.EngineVersion == EngineVersion.R1_PC_Edu || s.GameSettings.EngineVersion == EngineVersion.R1_PS1_Edu || s.GameSettings.EngineVersion == EngineVersion.R1_PocketPC)
            {
                TileMapY = s.Serialize<ushort>(TileMapY, name: nameof(TileMapY));
                TileMapX = 0;
                CollisionType = s.Serialize<byte>(CollisionType, name: nameof(CollisionType));
                PC_Unk1 = s.Serialize<byte>(PC_Unk1, name: nameof(PC_Unk1));
                PC_TransparencyMode = s.Serialize<R1_PC_MapTileTransparencyMode>(PC_TransparencyMode, name: nameof(PC_TransparencyMode));
                PC_Unk2 = s.Serialize<byte>(PC_Unk2, name: nameof(PC_Unk2));
            }
            else if (s.GameSettings.EngineVersion == EngineVersion.R1_PS1_JPDemoVol3 || s.GameSettings.EngineVersion == EngineVersion.R1_PS1_JPDemoVol6)
            {
                s.SerializeBitValues<int>(bitFunc =>
                {
                    TileMapX = (ushort)bitFunc(TileMapX, 10, name: nameof(TileMapX));
                    TileMapY = (ushort)bitFunc(TileMapY, 6, name: nameof(TileMapY));
                    CollisionType = (byte)bitFunc(CollisionType, 8, name: nameof(CollisionType));
                });
            }
            else if (s.GameSettings.EngineVersion == EngineVersion.R1_Saturn)
            {
                s.SerializeBitValues<ushort>(bitFunc =>
                {
                    TileMapX = (ushort)bitFunc(TileMapX, 4, name: nameof(TileMapX));
                    TileMapY = (ushort)bitFunc(TileMapY, 12, name: nameof(TileMapY));
                });

                CollisionType = s.Serialize<byte>(CollisionType, name: nameof(CollisionType));
                s.Serialize<byte>(0, name: "Padding");
            }
            else if (s.GameSettings.MajorEngineVersion == MajorEngineVersion.Rayman1_Jaguar)
            {
                s.SerializeBitValues<ushort>(bitFunc =>
                {
                    TileMapY = (ushort)bitFunc(TileMapY, 12, name: nameof(TileMapY));
                    CollisionType = (byte)bitFunc(CollisionType, 4, name: nameof(CollisionType));
                });

                TileMapX = 0;
            }
            else if (s.GameSettings.MajorEngineVersion == MajorEngineVersion.SNES)
            {
                s.SerializeBitValues<ushort>(bitFunc =>
                {
                    TileMapY = (ushort)bitFunc(TileMapY, 10, name: nameof(TileMapY));
                    HorizontalFlip = bitFunc(HorizontalFlip ? 1 : 0, 1, name: nameof(HorizontalFlip)) == 1;
                    VerticalFlip = bitFunc(VerticalFlip ? 1 : 0, 1, name: nameof(VerticalFlip)) == 1;
                    CollisionType = (byte)bitFunc(CollisionType, 4, name: nameof(CollisionType));
                });

                TileMapX = 0;
            }
            else if (s.GameSettings.MajorEngineVersion == MajorEngineVersion.GBA)
            {
                // TODO: Use SerializeBitValues

                if ((GBATileType == GBA_TileType.BGTile || GBATileType == GBA_TileType.FGTile)
                    && s.GameSettings.EngineVersion != EngineVersion.GBA_SplinterCell_NGage
                    && s.GameSettings.EngineVersion != EngineVersion.GBA_BatmanVengeance) {
                    int numBits = Is8Bpp ? 9 : 10;

                    if (s.GameSettings.EngineVersion <= EngineVersion.GBA_BatmanVengeance) {
                        numBits = 8;
                    }/*else if(s.GameSettings.EngineVersion >= EngineVersion.GBA_StarWarsTrilogy) {
                        numBits = Is8Bpp ? 9 : 10;
                    } else if (s.GameSettings.EngineVersion >= EngineVersion.GBA_SplinterCell) {
                        numBits = 9;
                        if (GBATileType == GBA_TileType.FGTile) numBits = 10;
                    }*/

                    ushort value = 0;

                    value = (ushort)BitHelpers.SetBits(value, TileMapY, numBits, 0);
                    //value = (ushort)BitHelpers.SetBits(value, VerticalFlip ? 1 : 0, 1, numBits);
                    value = (ushort)BitHelpers.SetBits(value, HorizontalFlip ? 1 : 0, 1, numBits);
                    value = (ushort)BitHelpers.SetBits(value, PaletteIndex, 4, 12);

                    value = s.Serialize<ushort>(value, name: nameof(value));

                    TileMapY = (ushort)BitHelpers.ExtractBits(value, numBits, 0);
                    TileMapX = 0;
                    if (Is8Bpp) {
                        IsFirstBlock = BitHelpers.ExtractBits(value, 1, 9) == 1;
                    }
                    HorizontalFlip = BitHelpers.ExtractBits(value, 1, 10) == 1;
                    VerticalFlip = BitHelpers.ExtractBits(value, 1, 11) == 1;
                    PaletteIndex = (byte)BitHelpers.ExtractBits(value, 4, 12);

                    s.Log($"{nameof(TileMapY)}: {TileMapY}");
                    s.Log($"{nameof(HorizontalFlip)}: {HorizontalFlip}");
                    s.Log($"{nameof(IsFirstBlock)}: {IsFirstBlock}");
                    s.Log($"{nameof(PaletteIndex)}: {PaletteIndex}");
                } else if(GBATileType == GBA_TileType.Mode7Tile) {

                    ushort value = 0;

                    value = (ushort)BitHelpers.SetBits(value, TileMapY, 9, 0);
                    //value = (ushort)BitHelpers.SetBits(value, VerticalFlip ? 1 : 0, 1, numBits);
                    value = (ushort)BitHelpers.SetBits(value, HorizontalFlip ? 1 : 0, 1, 9);

                    value = s.Serialize<ushort>(value, name: nameof(value));

                    TileMapY = (ushort)BitHelpers.ExtractBits(value, 9, 0);
                    TileMapX = 0;
                    IsFirstBlock = BitHelpers.ExtractBits(value, 1, 9) == 1;
                    HorizontalFlip = BitHelpers.ExtractBits(value, 1, 10) == 1;
                    VerticalFlip = BitHelpers.ExtractBits(value, 1, 11) == 1;

                    s.Log($"{nameof(TileMapY)}: {TileMapY}");
                    s.Log($"{nameof(HorizontalFlip)}: {HorizontalFlip}");
                    s.Log($"{nameof(IsFirstBlock)}: {IsFirstBlock}");
                } else {
                    int numBits = Is8Bpp ? 14 : 11;

                    if (s.GameSettings.EngineVersion <= EngineVersion.GBA_BatmanVengeance) {
                        numBits = 10;
                    } else if (s.GameSettings.EngineVersion == EngineVersion.GBA_SplinterCell_NGage) {
                        numBits = Is8Bpp ? 14 : 12;
                    } else if (s.GameSettings.EngineVersion >= EngineVersion.GBA_SplinterCell) {
                        numBits = Is8Bpp ? 14 : 12;
                    }

                    ushort value = 0;

                    value = (ushort)BitHelpers.SetBits(value, TileMapY, numBits, 0);
                    value = (ushort)BitHelpers.SetBits(value, HorizontalFlip ? 1 : 0, 1, numBits);
                    value = (ushort)BitHelpers.SetBits(value, PaletteIndex, 4, 12);

                    value = s.Serialize<ushort>(value, name: nameof(value));

                    TileMapY = (ushort)BitHelpers.ExtractBits(value, numBits, 0);
                    if (s.GameSettings.EngineVersion == EngineVersion.GBA_SplinterCell_NGage && Is8Bpp) {
                        TileMapY = (ushort)BitHelpers.ExtractBits(value, numBits-1, 0);
                    }
                    TileMapX = 0;
                    HorizontalFlip = BitHelpers.ExtractBits(value, 1, numBits) == 1;
                    if (s.GameSettings.EngineVersion == EngineVersion.GBA_BatmanVengeance) {
                        VerticalFlip = BitHelpers.ExtractBits(value, 1, numBits + 1) == 1;
                    }
                    if (!Is8Bpp) {
                        if (s.GameSettings.EngineVersion >= EngineVersion.GBA_SplinterCell) {
                            PaletteIndex = (byte)BitHelpers.ExtractBits(value, 3, 13);
                        } else {
                            PaletteIndex = (byte)BitHelpers.ExtractBits(value, 4, 12);
                        }

                        if (s.GameSettings.EngineVersion == EngineVersion.GBA_SplinterCell) {
                            PaletteIndex += 8;
                        }
                    } else if(s.GameSettings.EngineVersion != EngineVersion.GBA_BatmanVengeance) {
                        VerticalFlip = BitHelpers.ExtractBits(value, 1, numBits + 1) == 1;
                    }

                    s.Log($"{nameof(TileMapY)}: {TileMapY}");
                    s.Log($"{nameof(HorizontalFlip)}: {HorizontalFlip}");
                    s.Log($"{nameof(PaletteIndex)}: {PaletteIndex}");
                }
            }
            else if (s.GameSettings.EngineVersion == EngineVersion.R1_PS1 || s.GameSettings.EngineVersion == EngineVersion.R2_PS1)
            {
                s.SerializeBitValues<ushort>(bitFunc =>
                {
                    TileMapX = (ushort)bitFunc(TileMapX, 4, name: nameof(TileMapX));
                    TileMapY = (ushort)bitFunc(TileMapY, 6, name: nameof(TileMapY));
                    CollisionType = (byte)bitFunc(CollisionType, 6, name: nameof(CollisionType));
                });
            }
            else if (s.GameSettings.EngineVersion == EngineVersion.R1_PS1_JP)
            {
                s.SerializeBitValues<ushort>(bitFunc =>
                {
                    TileMapX = (ushort)bitFunc(TileMapX, 9, name: nameof(TileMapX));
                    CollisionType = (byte)bitFunc(CollisionType, 7, name: nameof(CollisionType));
                });
            }
            else if (s.GameSettings.MajorEngineVersion == MajorEngineVersion.GBARRR)
            {
                if (GBARRRType == GBARRR_MapBlock.MapType.Collision)
                {
                    CollisionType = s.Serialize<byte>(CollisionType, name: nameof(CollisionType));
                }
                else if (GBARRRType == GBARRR_MapBlock.MapType.Tiles)
                {
                    TileMapY = s.Serialize<ushort>(TileMapY, name: nameof(TileMapY));
                }
                else if (GBARRRType == GBARRR_MapBlock.MapType.Foreground) {
                    s.SerializeBitValues<ushort>(bitFunc =>
                    {
                        TileMapY = (ushort)bitFunc(TileMapY, 10, name: nameof(TileMapY));
                        HorizontalFlip = bitFunc(HorizontalFlip ? 1 : 0, 1, name: nameof(HorizontalFlip)) == 1;
                        VerticalFlip = bitFunc(VerticalFlip ? 1 : 0, 1, name: nameof(VerticalFlip)) == 1;
                        PaletteIndex = (byte)bitFunc(PaletteIndex, 4, name: nameof(PaletteIndex));
                        //Unk = (byte)bitFunc(Unk, 4, name: nameof(Unk));
                    });
                }
                else if (GBARRRType == GBARRR_MapBlock.MapType.Menu) {
                    s.SerializeBitValues<ushort>(bitFunc =>
                    {
                        TileMapY = (ushort)bitFunc(TileMapY, 8, name: nameof(TileMapY));
                        GBARRR_MenuUnk = (byte)bitFunc(GBARRR_MenuUnk, 2, name: nameof(GBARRR_MenuUnk));
                        HorizontalFlip = bitFunc(HorizontalFlip ? 1 : 0, 1, name: nameof(HorizontalFlip)) == 1;
                        VerticalFlip = bitFunc(VerticalFlip ? 1 : 0, 1, name: nameof(VerticalFlip)) == 1;
                        PaletteIndex = (byte)bitFunc(PaletteIndex, 4, name: nameof(PaletteIndex));
                        //Unk = (byte)bitFunc(Unk, 4, name: nameof(Unk));
                    });
                }
                else if (GBARRRType == GBARRR_MapBlock.MapType.Mode7Tiles) {
                    TileMapY = s.Serialize<byte>((byte)TileMapY, name: nameof(TileMapY));
                }
            }
        }

        public MapTile CloneObj() => (MapTile)Clone();
        public object Clone() => MemberwiseClone();
    }
}