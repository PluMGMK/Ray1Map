﻿namespace R1Engine
{
    public class R1_SaturnUS_Manager : R1_Saturn_Manager
    {
        public override uint GetPalOffset => 0x79224;
        public override uint GetFndFileTableOffset => 0x81948;
        public override uint GetFndSPFileTableOffset => 0x81D3F;
        public override uint GetFndIndexTableOffset => 0x81C77;

        public override uint? TypeZDCOffset => 0x7F032;
        public override uint? ZDCDataOffset => 0x7e032;
        public override uint? EventFlagsOffset => 0x7D830;
        public override uint? WorldInfoOffset => 0x7F900;
    }
}