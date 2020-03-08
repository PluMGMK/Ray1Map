﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using UnityEngine;

namespace R1Engine
{
    /// <summary>
    /// Event info manager class
    /// </summary>
    public static class EventInfoManager
    {
        /// <summary>
        /// Generated a JSON file with the common event information based on the current settings
        /// </summary>
        /// <param name="customInfoPath">The custom info file path</param>
        /// <param name="outputFilePath">The output file path</param>
        public static void GenerateEventInfo(string customInfoPath, string outputFilePath)
        {
            var eventInfo = new List<EventInfoData>();

            // Read the custom info
            using (var file = File.OpenRead(customInfoPath))
            {
                using (var reader = new StreamReader(file))
                {
                    // Ignore header line
                    reader.ReadLine();

                    // Enumerate each line
                    while (!reader.EndOfStream)
                    {
                        var line = reader.ReadLine()?.Split(',');

                        if (line == null)
                            break;

                        var type = Int32.Parse(line[0]);
                        var etat = Int32.Parse(line[1]);
                        var subEtat = Int32.Parse(line[2]);

                        var names = new Dictionary<World, string>();
                        var index = 3;

                        foreach (World world in EnumHelpers.GetValues<World>())
                        {
                            var name = line[index].Trim('"');

                            if (!String.IsNullOrWhiteSpace(name))
                                names.Add(world, name);

                            index++;
                        }

                        bool? isAlways = line[index] == "TRUE" ? true : line[index] == "FALSE" ? (bool?)false : null;

                        index++;

                        bool? editorOnly = line[index] == "TRUE" ? true : line[index] == "FALSE" ? (bool?)false : null; 

                        // Get the ID
                        var id = new EventID(type, etat, subEtat);

                        // Create the item
                        eventInfo.Add(new EventInfoData(new GeneralEventInfoData()
                        {
                            ID = id,
                            Names = names,
                            IsAlways = isAlways,
                            EditorOnly = editorOnly
                        }));
                    }
                }
            }
            
            // Create a Designer manager
            var rdManager = new PC_RD_Manager();

            // Enumerate each Designer world
            foreach (World world in EnumHelpers.GetValues<World>())
            {
                // Get the event manifest file path
                var eventFilePath = Path.Combine(Settings.GameDirectories[GameModeSelection.RaymanDesignerPC], rdManager.GetWorldName(world), "EVE.MLT");

                // Read the manifest
                var eventFile = FileFactory.Read<PC_RD_EventManifestFile>(eventFilePath, new GameSettings(GameMode.RayKit, Settings.GameDirectories[GameModeSelection.RaymanDesignerPC]));

                // Add each entry
                foreach (PC_RD_EventManifestFile.PC_RD_EventManifestItem e in eventFile.Items)
                {
                    // Get the ID values
                    var type = Int32.TryParse(e.Obj_type, out var v) ? v : -1;
                    var etat = (int)e.Etat;
                    var subEtat = Int32.TryParse(e.SubEtat, out var v2) ? v2 : -1;

                    // Get the ID
                    var id = new EventID(type, etat, subEtat);

                    // Find the event info
                    var data = eventInfo.Find(x => x.ID == id);

                    // Ignore if not found
                    if (data == null)
                    {
                        Debug.LogWarning("No matching event found for Designer");
                        continue;
                    }

                    // Add the data
                    if (data.PCDesignerManifest == null)
                        data.PCDesignerManifest = new EventInfoData.PC_DesignerEventManifestData(e);
                }
            }
            // Enumerate the PC versions
            foreach (GameModeSelection mode in new GameModeSelection[]
            {
                GameModeSelection.RaymanPC,
                GameModeSelection.RaymanDesignerPC,
                GameModeSelection.RaymanByHisFansPC,
                GameModeSelection.Rayman60LevelsPC,
                GameModeSelection.RaymanEducationalPC,
            })
            {
                // Get the attribute data
                var attr = mode.GetAttribute<GameModeAttribute>();

                // Get the manager
                var manager = (PC_Manager)Activator.CreateInstance(attr.ManagerType);

                // Enumerate each PC world
                foreach (World world in EnumHelpers.GetValues<World>())
                {
                    // Get the settings
                    var s = new GameSettings(attr.GameMode, Settings.GameDirectories[mode], world)
                    {
                        EduVolume = Settings.EduVolume
                    };

                    // Enumerate each level
                    foreach (var i in manager.GetLevels(s))
                    {
                        // Set the level
                        s.Level = i;

                        // Get the level file path
                        var lvlFilePath = manager.GetLevelFilePath(s);

                        // Read the level
                        var lvl = FileFactory.Read<PC_LevFile>(lvlFilePath, s);

                        var index = 0;

                        // Handle every event
                        foreach (var e in lvl.Events)
                        {
                            // Get the ID
                            var id = new EventID((int)e.Type, e.Etat, e.SubEtat);

                            // Find the event info
                            var data = eventInfo.FindItem(x => x.ID == id);

                            // Ignore if not found
                            if (data == null)
                            {
                                Debug.LogWarning("No matching event found");
                                continue;
                            }

                            // Add the data
                            if (!data.PCInfo.ContainsKey(attr.GameMode))
                                data.PCInfo.Add(attr.GameMode, new EventInfoData.PC_EventInfo(e, lvl.EventCommands[index], world));

                            if (!data.PCInfo[attr.GameMode].ETA.ContainsKey(world))
                                data.PCInfo[attr.GameMode].ETA.Add(world, e.ETA);

                            if (!data.PCInfo[attr.GameMode].DES.ContainsKey(world))
                                data.PCInfo[attr.GameMode].DES.Add(world, e.DES);

                            index++;
                        }
                    }
                }
            }

            // Serialize to the file
            JsonHelpers.SerializeToFile(eventInfo, outputFilePath);
        }

        /// <summary>
        /// Generates a .csv file with custom event info to be filled out
        /// </summary>
        /// <param name="oldCsvFilePath">The old .csv file path</param>
        /// <param name="outputFilePath">The new .csv output file path</param>
        public static void GenerateCustomEventInfo(string oldCsvFilePath, string outputFilePath)
        {
            // Create the output
            var output = new List<GeneralEventInfoData>();

            var rdManager = new PC_RD_Manager();

            // Read the event localization files
            var loc = rdManager.GetEventLocFiles(Settings.GameDirectories[GameModeSelection.RaymanDesignerPC])["USA"].SelectMany(x => x.LocItems).ToArray();

            // Enumerate each Designer world
            foreach (World world in EnumHelpers.GetValues<World>())
            {
                // Get the event manifest file path
                var eventFilePath = Path.Combine(Settings.GameDirectories[GameModeSelection.RaymanDesignerPC], rdManager.GetWorldName(world), "EVE.MLT");

                // Read the manifest
                var eventFile = FileFactory.Read<PC_RD_EventManifestFile>(eventFilePath, new GameSettings(GameMode.RayKit, Settings.GameDirectories[GameModeSelection.RaymanDesignerPC]));

                // Add each entry
                foreach (PC_RD_EventManifestFile.PC_RD_EventManifestItem e in eventFile.Items)
                {
                    // Attempt to find the matching localization entry
                    PC_RD_EventLocItem locItem = loc.FindItem(x => x.LocKey == e.Name);

                    var type = Int32.TryParse(e.Obj_type, out int res) ? res : -1;

                    if (type == -1)
                        continue;

                    var subEtat = Int32.TryParse(e.SubEtat, out int res2) ? res2 : -1;

                    if (subEtat == -1)
                        continue;

                    // Create the ID
                    var id = new EventID(type, (int)e.Etat, subEtat);

                    // Try and get the item
                    var data = output.Find(x => x.ID == id);

                    // If not found, create it
                    if (data == null)
                    {
                        data = new GeneralEventInfoData()
                        {
                            ID = id
                        };

                        output.Add(data);
                    }

                    // Update always flag
                    if (data.IsAlways == null)
                        data.IsAlways = e.DesignerGroup == -1;

                    // Add the name
                    if (!data.Names.ContainsKey(world))
                        // Add the world
                        data.Names.Add(world, "?");
                }
            }

            // Enumerate the PC versions
            foreach (GameModeSelection mode in new GameModeSelection[]
            {
                GameModeSelection.RaymanPC,
                GameModeSelection.RaymanDesignerPC,
                GameModeSelection.RaymanByHisFansPC,
                GameModeSelection.Rayman60LevelsPC,
                GameModeSelection.RaymanEducationalPC,
            })
            {
                // Get the attribute data
                var attr = mode.GetAttribute<GameModeAttribute>();

                // Get the manager
                var manager = (PC_Manager)Activator.CreateInstance(attr.ManagerType);

                // Enumerate each PC world
                foreach (World world in EnumHelpers.GetValues<World>())
                {
                    // Get the settings
                    var s = new GameSettings(attr.GameMode, Settings.GameDirectories[mode], world)
                    {
                        EduVolume = Settings.EduVolume
                    };

                    // Enumerate each Rayman 1 level
                    foreach (var i in manager.GetLevels(s))
                    {
                        // Set the level
                        s.Level = i;

                        // Get the level file path
                        var lvlFilePath = manager.GetLevelFilePath(s);

                        // Read the level
                        var lvl = FileFactory.Read<PC_LevFile>(lvlFilePath, s);

                        // Add every event
                        foreach (var e in lvl.Events)
                        {
                            // Get the ID
                            var id = e.GetEventID();

                            // Check if the data has already been added
                            var data = output.Find(x => x.ID == id);

                            // If not found, create it
                            if (data == null)
                            {
                                data = new GeneralEventInfoData()
                                {
                                    ID = id
                                };

                                output.Add(data);
                            }

                            if (!data.Names.ContainsKey(world))
                                // Add the world
                                data.Names.Add(world, "?");
                        }
                    }
                }
            }

            // Order the data
            output = output.OrderBy(x => x.ID.Type).ToList();

            // Add names from .csv file
            using (var csvFile = File.OpenRead(oldCsvFilePath))
            {
                using (var reader = new StreamReader(csvFile))
                {
                    // Ignore header line
                    reader.ReadLine();

                    // Enumerate each line
                    while (!reader.EndOfStream)
                    {
                        var line = reader.ReadLine()?.Split(',');

                        if (line == null)
                            break;

                        var name = line[1].Trim('"');
                        var type = Int32.Parse(line[6]);
                        var subEtat = Int32.Parse(line[9]);
                        var etat = Int32.Parse(line[10]);

                        // Get the ID
                        var id = new EventID(type, etat, subEtat);

                        // Find matching item
                        var item = output.Find(x => x.ID == id);

                        if (item == null)
                        {
                            Debug.LogWarning($"No matching even for {name} of type {type}");
                            continue;
                        }

                        // Get the world
                        var world = Path.GetFileName(Path.GetDirectoryName(line[17].Trim('"')));

                        // Set the name
                        item.Names[(World)Enum.Parse(typeof(World), world, true)] = name;
                    }
                }
            }

            // Write to file
            using (var file = File.Create(outputFilePath))
            {
                using (var writer = new StreamWriter(file))
                {
                    // Write header
                    writer.Write("\"Type\",");
                    writer.Write("\"Etat\",");
                    writer.Write("\"SubEtat\",");

                    foreach (World world in EnumHelpers.GetValues<World>())
                        writer.Write($"\"Name ({world})\",");

                    writer.Write("\"IsAlways\",");
                    writer.Write("\"EditorOnly\"");

                    // Write values
                    foreach (var item in output)
                    {
                        writer.WriteLine();

                        writer.Write(item.ID.Type + ",");
                        writer.Write(item.ID.Etat + ",");
                        writer.Write(item.ID.SubEtat + ",");

                        foreach (World world in EnumHelpers.GetValues<World>())
                            writer.Write($"\"{(item.Names.TryGetValue(world, out string value) ? value : String.Empty)}\",");

                        writer.Write($"\"{(item.IsAlways?.ToString() ?? String.Empty)}\",");
                        writer.Write($"\"{(item.EditorOnly?.ToString() ?? String.Empty)}\"");
                    }
                }
            }
        }

        /// <summary>
        /// Loads the event info from a file
        /// </summary>
        /// <param name="filePath">The file path to load from</param>
        /// <returns>The loaded event info</returns>
        public static EventInfoData[] LoadEventInfo(string filePath = null)
        {
            // Default the path
            if (filePath == null)
                filePath = "CommonEvents.json";

            return Cache ?? (Cache = JsonHelpers.DeserializeFromFile<EventInfoData[]>(filePath));
        }

        /// <summary>
        /// The loaded event info cache
        /// </summary>
        private static EventInfoData[] Cache { get; set; }
    }

    /// <summary>
    /// General event info data
    /// </summary>
    public class GeneralEventInfoData
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public GeneralEventInfoData()
        {
            Names = new Dictionary<World, string>();
        }

        /// <summary>
        /// The event ID
        /// </summary>
        public EventID ID { get; set; }

        /// <summary>
        /// The event names
        /// </summary>
        public Dictionary<World, string> Names { get; set; }

        /// <summary>
        /// Indicates if the event is an always event
        /// </summary>
        public bool? IsAlways { get; set; }

        /// <summary>
        /// Indicates if the event should only be displayed in the editor
        /// </summary>
        public bool? EditorOnly { get; set; }
    }
}