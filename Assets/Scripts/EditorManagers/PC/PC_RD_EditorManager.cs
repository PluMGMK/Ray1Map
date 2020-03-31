﻿using System.Linq;
using R1Engine.Serialize;

namespace R1Engine
{
    /// <summary>
    /// The editor manager for Rayman Designer (PC)
    /// </summary>
    public class PC_RD_EditorManager : PC_EditorManager
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="level">The common level</param>
        /// <param name="context">The context</param>
        /// <param name="manager">The manager</param>
        /// <param name="designs">The common design</param>
        public PC_RD_EditorManager(Common_Lev level, Context context, PC_Manager manager, Common_Design[] designs) : base(level, context, manager, designs)
        {
            DESFileIndex = manager.GetDESNames(context).Select(x => x.Remove(x.Length - 4)).ToArray();
            ETAFileIndex = manager.GetETANames(context).Select(x => x.Remove(x.Length - 4)).ToArray();
        }

        /// <summary>
        /// Indicates if the local commands should be used
        /// </summary>
        protected override bool UsesLocalCommands => false;

        /// <summary>
        /// The DES file index
        /// </summary>
        public string[] DESFileIndex { get; }
        
        /// <summary>
        /// The ETA file index
        /// </summary>
        public string[] ETAFileIndex { get; }

        /// <summary>
        /// Gets the DES index for the specified event data item
        /// </summary>
        /// <param name="eventInfoData">The event info data item</param>
        /// <returns>The DES index</returns>
        public override int? GetDesIndex(GeneralEventInfoData eventInfoData)
        {
            return DESFileIndex.FindItemIndex(x => x == eventInfoData.DesKit[Settings.World]) + 1;
        }

        /// <summary>
        /// Gets the ETA index for the specified event data item
        /// </summary>
        /// <param name="eventInfoData">The event info data item</param>
        /// <returns>The ETA index</returns>
        public override int? GetEtaIndex(GeneralEventInfoData eventInfoData)
        {
            return ETAFileIndex.FindItemIndex(x => x == eventInfoData.EtaKit[Settings.World]);
        }

        /// <summary>
        /// Checks if the event is available in the current world
        /// </summary>
        /// <param name="eventInfoData">The event info data item</param>
        /// <returns>True if it's available, otherwise false</returns>
        public override bool IsAvailableInWorld(GeneralEventInfoData eventInfoData)
        {
            return eventInfoData.DesKit.ContainsKey(Settings.World) && eventInfoData.DesKit[Settings.World] != null;
        }
    }
}