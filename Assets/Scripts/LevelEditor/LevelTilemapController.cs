﻿using UnityEngine;
using UnityEngine.Tilemaps;
using UnityEngine.UI;

namespace R1Engine
{
    public class LevelTilemapController : MonoBehaviour 
    {
        /// <summary>
        /// References to specific tilemap gameObjects in inspector
        /// </summary>
        public Tilemap[] Tilemaps;

        public Tilemap tilemapFull;
        public bool focusedOnTemplate=false;
        public Editor editor;

        /// <summary>
        /// The events
        /// </summary>
        public GameObject Events;

        /// <summary>
        /// Palette buttons
        /// </summary>
        public Button[] paletteButtons;
        //The ui text
        public GameObject paletteText;
        //0 is auto
        private int currentPalette = 1;

        // Reference to the background ting
        public SpriteRenderer backgroundTint;

        /// <summary>
        /// The type collision tiles
        /// </summary>
        public Tile[] TypeCollisionTiles;
        public Tile[] TypeCollisionTilesHD;

        // Infro tracked for when switching between template and normal level
        private Vector3 previousCameraPosNormal;
        private Vector3 previousCameraPosTemplate = new Vector3(0,0,-10f);
        private int templateMaxY=0;

        public int camMaxX=1;
        public int camMaxY=1;


        public void InitializeTilemaps() {
            // Disable palette buttons based on if there are 3 palettes or not
            if (!Controller.obj.levelController.EditorManager.Has3Palettes)
            {
                paletteText.SetActive(false);
                paletteButtons[0].gameObject.SetActive(false);
                paletteButtons[1].gameObject.SetActive(false);
                paletteButtons[2].gameObject.SetActive(false);
                paletteButtons[3].gameObject.SetActive(false);
            }

            // Fill out types first
            foreach (Common_Tile t in Controller.obj.levelController.currentLevel.Maps[editor.currentMap].Tiles) 
            {
                var collisionTypeIndex = (int)t.CollisionType;

                // Fill out types first
                if (Settings.UseHDCollisionSheet) 
                {
                    if (collisionTypeIndex >= TypeCollisionTilesHD.Length)
                    {
                        Debug.LogWarning($"Collision type {t.CollisionType} is not supported");
                        collisionTypeIndex = 0;
                    }

                    Tilemaps[0].SetTile(new Vector3Int(t.XPosition, t.YPosition, 0), TypeCollisionTilesHD[collisionTypeIndex]);
                }
                else 
                {
                    if (collisionTypeIndex >= TypeCollisionTiles.Length)
                    {
                        Debug.LogWarning($"Collision type {t.CollisionType} is not supported");
                        collisionTypeIndex = 0;
                    }

                    Tilemaps[0].SetTile(new Vector3Int(t.XPosition, t.YPosition, 0), TypeCollisionTiles[collisionTypeIndex]);
                }
            }
            // Fill out tiles
            RefreshTiles(Controller.obj.levelController.EditorManager.Has3Palettes ? 0 : 1);

            //Set max cam sizes
            camMaxX = Controller.obj.levelController.currentLevel.Maps[editor.currentMap].Width;
            camMaxY = Controller.obj.levelController.currentLevel.Maps[editor.currentMap].Height;
        }

        // Used to redraw all tiles with different palette (0 = auto, 1-3 = palette)
        public void RefreshTiles(int palette) {
            //Change button visibility
            currentPalette = palette;
            for (int i = 0; i < paletteButtons.Length; i++) {
                ColorBlock b = paletteButtons[i].colors;
                if (currentPalette == i) {
                    b.normalColor = new Color(1, 1, 1);
                }
                else {
                    b.normalColor = new Color(0.5f, 0.5f, 0.5f);
                }
                paletteButtons[i].colors = b;
            }

            // Get the current level
            var lvl = Controller.obj.levelController.currentLevel;

            // If auto, refresh indexes
            if (palette == 0)
                lvl.AutoApplyPalette();

            //Refresh tiles
            foreach (Common_Tile t in lvl.Maps[editor.currentMap].Tiles)
            {
                int p = (palette == 0 ? t.PaletteIndex : palette) - 1;
                Tilemaps[1].SetTile(new Vector3Int(t.XPosition, t.YPosition, 0), lvl.Maps[editor.currentMap].TileSet[p].Tiles[t.TileSetGraphicIndex]);
            }
            //Refresh the full tilemap
            int xx = 0;
            int yy = 0;
            foreach(Tile t in lvl.Maps[editor.currentMap].TileSet[0].Tiles) {
                tilemapFull.SetTile(new Vector3Int(xx, yy, 0), t);
                xx++;
                if (xx == 16) {
                    xx = 0;
                    yy++;
                }
            }
            //Debug.Log(lvl.Maps[editor.currentMap].TileSet[0].Tiles.Length);
            templateMaxY = yy+1;
        }

        // Resize the background tint
        public void ResizeBackgroundTint(int x, int y) {
            backgroundTint.transform.localScale = new Vector2(x, y);
        }

        // Used for switching the view between template and normal tiles
        public void ShowHideTemplate() {
            focusedOnTemplate = !focusedOnTemplate;

            Tilemaps[1].gameObject.SetActive(!focusedOnTemplate);
            tilemapFull.gameObject.SetActive(focusedOnTemplate);

            //Clear the selection square so it doesn't remain and look bad
            editor.tileSelectSquare.Clear();

            if (focusedOnTemplate) {
                editor.ClearSelection();
                //Save camera and set new
                previousCameraPosNormal = Camera.main.transform.position;
                Camera.main.GetComponent<EditorCam>().pos = previousCameraPosTemplate;
                //Resize the background tint for a better effect
                ResizeBackgroundTint(16, templateMaxY);
                //Set max cam sizes
                camMaxX = 16;
                camMaxY = templateMaxY;
            }
            else {
                //Set camera back
                previousCameraPosTemplate = Camera.main.transform.position;
                Camera.main.GetComponent<EditorCam>().pos = previousCameraPosNormal;
                //Resize background tint
                var lvl = Controller.obj.levelController.currentLevel.Maps[editor.currentMap];
                ResizeBackgroundTint(lvl.Width, lvl.Height);
                //Set max cam sizes
                camMaxX = lvl.Width;
                camMaxY = lvl.Height;
            }
        }

        // Converts mouse position to worldspace and then tile positions (1 = 16)
        public Vector3 MouseToTileCoords(Vector3 mousePos) {
            var worldMouse = Camera.main.ScreenToWorldPoint(new Vector3(mousePos.x, mousePos.y, 10));
            return new Vector3(Mathf.Floor(worldMouse.x), Mathf.Floor(worldMouse.y + 1), 10);
        }

        // Get one common tile at given position
        public Common_Tile GetTileAtPos(int x, int y) {
            if (Controller.obj.levelController.currentLevel == null) {
                return null;
            }
            else {
                if (focusedOnTemplate) {
                    Common_Tile t = new Common_Tile();
                    t.CollisionType = 0;
                    t.PaletteIndex = 0;
                    t.TileSetGraphicIndex = (y * 16) + x;

                    if (t.TileSetGraphicIndex > Controller.obj.levelController.currentLevel.Maps[editor.currentMap].TileSet[0].Tiles.Length-1) {
                        t.TileSetGraphicIndex = 0;
                    }

                    return t;
                }
                else {
                    foreach (var t in Controller.obj.levelController.currentLevel.Maps[editor.currentMap].Tiles) {
                        if (t.XPosition == x && t.YPosition == y) {
                            return t;
                        }
                    }
                }
                return null;
            }
        }

        public Common_Tile SetTileAtPos(int x, int y, Common_Tile newTileInfo, Common_Tile tile = null) {
            Tilemaps[0].SetTile(new Vector3Int(x, y, 0), null);
            Tilemaps[1].SetTile(new Vector3Int(x, y, 0), null);
            Tilemaps[0].SetTile(new Vector3Int(x, y, 0), TypeCollisionTiles[(int)newTileInfo.CollisionType]);
            Tilemaps[1].SetTile(new Vector3Int(x, y, 0), Controller.obj.levelController.currentLevel.Maps[editor.currentMap].TileSet[0].Tiles[newTileInfo.TileSetGraphicIndex]);

            // Get the tile if null
            if (tile == null)
                tile = Controller.obj.levelController.currentLevel.Maps[editor.currentMap].Tiles.FindItem(item => item.XPosition == x && item.YPosition == y);

            tile.CollisionType = newTileInfo.CollisionType;
            tile.PaletteIndex = newTileInfo.PaletteIndex;
            tile.TileSetGraphicIndex = newTileInfo.TileSetGraphicIndex;

            return tile;
        }

        public Common_Tile SetTypeAtPos(int x, int y, TileCollisionType typeIndex, Common_Tile tile = null) {
            Tilemaps[0].SetTile(new Vector3Int(x, y, 0), null);
            Tilemaps[0].SetTile(new Vector3Int(x, y, 0), TypeCollisionTiles[(int)typeIndex]);

            // Get the tile if null
            if (tile == null)
                tile = Controller.obj.levelController.currentLevel.Maps[editor.currentMap].Tiles.FindItem(item => item.XPosition == x && item.YPosition == y);
            tile.CollisionType = typeIndex;

            return tile;
        }
    }
}
