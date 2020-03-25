﻿namespace R1Engine
{
    /// <summary>
    /// Allfix data for Rayman 1 (PS1)
    /// </summary>
    public class PS1_R1_AllfixFile : PS1_R1_BaseFile
    {
        #region File Pointers

        public Pointer DataBlockPointer => BlockPointers[0];

        public Pointer TextureBlockPointer => BlockPointers[1];

        public Pointer Palette1Pointer => BlockPointers[2];

        public Pointer Palette2Pointer => BlockPointers[3];

        public Pointer Palette3Pointer => BlockPointers[4];

        public Pointer Palette4Pointer => BlockPointers[5];

        public Pointer Palette5Pointer => BlockPointers[6];

        public Pointer Palette6Pointer => BlockPointers[7];

        #endregion

        #region Block Data

        /// <summary>
        /// The data block
        /// </summary>
        public byte[] DataBlock { get; set; }

        /// <summary>
        /// The texture block
        /// </summary>
        public byte[] TextureBlock { get; set; }

        public ARGB1555Color[] Palette1 { get; set; }

        public ARGB1555Color[] Palette2 { get; set; }

        public ARGB1555Color[] Palette3 { get; set; }

        public ARGB1555Color[] Palette4 { get; set; }

        public ARGB1555Color[] Palette5 { get; set; }

        public ARGB1555Color[] Palette6 { get; set; }

        #endregion

        #region Public Methods

        /// <summary>
        /// Serializes the data
        /// </summary>
        /// <param name="s">The serializer object</param>
        public override void SerializeImpl(SerializerObject s)
        {
            // HEADER
            base.SerializeImpl(s);

            // DATA BLOCK
            s.DoAt(DataBlockPointer, () => {
                DataBlock = s.SerializeArray<byte>(DataBlock, TextureBlockPointer - s.CurrentPointer, name: "DataBlock");
            });

            // TEXTURE BLOCK
            s.DoAt(TextureBlockPointer, () => {
                TextureBlock = s.SerializeArray<byte>(TextureBlock, Palette1Pointer - s.CurrentPointer, name: "TextureBlock");
            });

            // PALETTE 1
            s.DoAt(Palette1Pointer, () => {
                Palette1 = s.SerializeObjectArray<ARGB1555Color>(Palette1, 256, name: "Palette1");
            });

            // PALETTE 2
            s.DoAt(Palette2Pointer, () => {
                Palette2 = s.SerializeObjectArray<ARGB1555Color>(Palette2, 256, name: "Palette2");
            });

            // PALETTE 3
            s.DoAt(Palette3Pointer, () => {
                Palette3 = s.SerializeObjectArray<ARGB1555Color>(Palette3, 256, name: "Palette3");
            });

            // PALETTE 4
            s.DoAt(Palette4Pointer, () => {
                Palette4 = s.SerializeObjectArray<ARGB1555Color>(Palette4, 256, name: "Palette4");
            });

            // PALETTE 5
            s.DoAt(Palette5Pointer, () => {
                Palette5 = s.SerializeObjectArray<ARGB1555Color>(Palette5, 256, name: "Palette5");
            });

            // PALETTE 6
            s.DoAt(Palette6Pointer, () => {
                Palette6 = s.SerializeObjectArray<ARGB1555Color>(Palette6, 256, name: "Palette6");
            });
        }

        #endregion
    }
}