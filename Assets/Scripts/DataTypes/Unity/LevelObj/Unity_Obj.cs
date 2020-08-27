﻿using System;
using System.Linq;

namespace R1Engine
{
    public class Unity_Obj : Unity_BaseEditorElement<R1_EventData>
    {
        #region Constructor

        public Unity_Obj(R1_EventData eventData) : base(eventData) { }

        #endregion

        #region Private Fields

        private Enum _type;

        #endregion

        #region Public Properties

        /// <summary>
        /// The event type
        /// </summary>
        public Enum Type
        {
            get => _type;
            set
            {
                _type = value;

                // Update type values
                TypeValue = (ushort)Convert.ChangeType(Type, typeof(ushort));
                TypeInfo = Type.GetAttribute<ObjTypeInfoAttribute>();
            }
        }

        /// <summary>
        /// The event type as a ushort
        /// </summary>
        public ushort TypeValue { get; private set; }

        protected ObjTypeInfoAttribute TypeInfo { get; private set; }

        public string DESKey { get; set; }
        public string ETAKey { get; set; }

        // Rayman 2 only
        public int? MapLayer { get; set; }
        public bool FlipHorizontally { get; set; }

        public ushort[] LabelOffsets { get; set; }
        public R1_EventCommandCollection CommandCollection { get; set; }

        /// <summary>
        /// The link table index
        /// </summary>
        public int LinkIndex { get; set; }

        public int[] GBALinks { get; set; }

        /// <summary>
        /// True if the event is forced to be handled as an always event
        /// </summary>
        public bool ForceAlways { get; set; }

        /// <summary>
        /// True if the event is forced to have its animation speed to 0
        /// </summary>
        public bool ForceNoAnimation { get; set; }
        
        /// <summary>
        /// Optional frame to freeze at if <see cref="ForceNoAnimation"/> is true
        /// </summary>
        public byte? ForceFrame { get; set; }

        #endregion

        #region Methods

        // TODO: Check PS1 flags
        // Unk_28 is also some active flag, but it's 0 for Rayman
        protected bool IsActive() => Data.PC_Flags.HasFlag(R1_EventData.PC_EventFlags.SwitchedOn) && Data.Unk_36 == 1;

        public bool GetIsFlippedHorizontally(R1_EventState state)
        {
            // If loading from memory, check runtime flags
            if (Settings.LoadFromMemory)
            {
                if (Data.PC_Flags.HasFlag(R1_EventData.PC_EventFlags.DetectZone))
                    return true;

                // TODO: Check PS1 flags

                return false;
            }

            // Check if we force the event to flip...
            if (FlipHorizontally)
                return true;

            // Check if it's the pin event and if the hp flag is set
            if (Type is R1_EventType et && et == R1_EventType.TYPE_PUNAISE3 && Data.HitPoints == 1)
                return true;

            // If the first command changes its direction to right, flip the event (a bit hacky, but works for trumpets etc.)
            if (CommandCollection?.Commands?.FirstOrDefault()?.Command == R1_EventCommandType.GO_RIGHT)
                return true;

            // If we're on GBA, check the state
            if (LevelEditorData.CurrentSettings.MajorEngineVersion == MajorEngineVersion.GBA)
                return state?.IsFlippedHorizontally ?? false;

            return false;
        }


        public bool GetIsFlippedVertically(R1_EventState state) {
            // If we're on GBA, check the state
            if (LevelEditorData.CurrentSettings.MajorEngineVersion == MajorEngineVersion.GBA)
                return state?.IsFlippedVertically ?? false;

            return false;
        }

        public bool GetIsVisible()
        {
            if (GetIsEditor())
                return Settings.ShowEditorEvents;

            if (GetIsAlways())
                return Settings.ShowAlwaysEvents || (Settings.LoadFromMemory && IsActive());

            // Default to visible
            return true;
        }

        public bool GetIsFaded() => Settings.LoadFromMemory && !IsActive();

        public bool GetIsAlways()
        {
            // Check if it's forced to be handled as an always event
            if (ForceAlways)
                return true;

            // The "DEMO" text uses type "TYPE_DARK2_PINK_FLY", which is normally an always event
            if (Type is R1_EventType e && e == R1_EventType.TYPE_DARK2_PINK_FLY)
                return false;

            // Check the flag
            return TypeInfo?.Flag == ObjTypeFlag.Always;
        }

        public bool GetIsEditor() => TypeInfo?.Flag == ObjTypeFlag.Editor;

        #endregion
    }
}