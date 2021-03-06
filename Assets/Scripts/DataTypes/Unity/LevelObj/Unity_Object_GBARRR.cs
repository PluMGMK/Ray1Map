﻿using System;
using System.Collections.Generic;
using System.Linq;
using UnityEngine;

namespace R1Engine
{
    public class Unity_Object_GBARRR : Unity_Object
    {
        public Unity_Object_GBARRR(GBARRR_Actor actor, Unity_ObjectManager_GBARRR objManager)
        {
            Actor = actor;
            ObjManager = objManager;
        }

        public GBARRR_Actor Actor { get; }
        public Unity_ObjectManager_GBARRR ObjManager { get; }

        public override short XPosition
        {
            get => Actor.XPosition;
            set => Actor.XPosition = value;
        }
        public override short YPosition
        {
            get => Actor.YPosition;
            set => Actor.YPosition = value;
        }

        public override string DebugText =>
              $"UShort_0C: {Actor.Ushort_0C}{Environment.NewLine}" +
              $"P_GraphicsIndex: {Actor.P_GraphicsIndex}{Environment.NewLine}" +
              $"P_GraphicsOffset: {Actor.P_GraphicsOffset:X8}{Environment.NewLine}" +
              $"P_SpriteSize: {Actor.P_SpriteSize}{Environment.NewLine}" +
              $"P_FrameCount: {Actor.P_FrameCount}{Environment.NewLine}";

        public override R1Serializable SerializableData => Actor;
        public override ILegacyEditorWrapper LegacyWrapper { get; }

        public override bool IsEditor => CurrentAnimation == null;

        public override bool FlipHorizontally => BitHelpers.ExtractBits(Actor.Data1[3], 1, 4) == 1;
        public override Vector2 Pivot
        {
            get
            {
                var sprite = Sprites?.ElementAtOrDefault(CurrentAnimation?.Frames.ElementAtOrDefault(AnimationFrame)?.SpriteLayers.FirstOrDefault()?.ImageIndex ?? 0);

                // Set the pivot to the center of the sprite
                return new Vector2((sprite?.rect.width ?? 0) / 2, (sprite?.rect.height ?? 0) / 2);
            }
        }

        public override bool CanBeLinkedToGroup => true;

        public override string PrimaryName => $"Type_{(byte)Actor.ObjectType}";
        public override string SecondaryName => $"{Actor.ObjectType}";

        public Unity_ObjectManager_GBARRR.GraphicsData GraphicsData => ObjManager.GraphicsDatas.ElementAtOrDefault(GraphicsDataIndex);
        public int GraphicsDataIndex
        {
            get => ObjManager.GraphicsDataLookup.TryGetItem(Actor.P_GraphicsOffset, -1);
            set
            {
                if (value != GraphicsDataIndex)
                {
                    OverrideAnimIndex = null;
                    Actor.P_GraphicsOffset = (byte)ObjManager.GraphicsDatas[value].GraphicsOffset;
                }
            }
        }

        public override Unity_ObjAnimation CurrentAnimation => GraphicsData?.Animation;
        public override int AnimSpeed => 5; // TODO: Fix
        public override int? GetAnimIndex => 0;
        protected override int GetSpriteID => GraphicsDataIndex;
        public override IList<Sprite> Sprites => GraphicsData?.AnimFrames;
        protected override bool IsUIStateArrayUpToDate => false;
        protected override void RecalculateUIStates() => UIStates = new UIState[0];
    }
}