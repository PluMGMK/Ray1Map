﻿using UnityEngine;

namespace R1Engine {
    public class EventBehaviour : MonoBehaviour {
        public static GameObject resource { get {
                if (_resource == null) _resource = Resources.Load<GameObject>("Event");
                return _resource;
            } }
    static GameObject _resource;


        static Transform root;
        public Common_Event ev;
        public Transform icon;

        void Start() {
            if (ev == null)
                ev = new Common_Event();
            if (root == null) root = GameObject.Find("Events").transform;
            name = $"{root.childCount} | {ev.Data.Type}";
            transform.parent = root;
            transform.position = new Vector3(ev.Data.EventData.XPosition, ev.Data.EventData.YPosition) + Vector3.forward * 5;
        }
    }
}