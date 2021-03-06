﻿namespace R1Engine
{
    /// <summary>
    /// Event state for Rayman 1 (Jaguar)
    /// </summary>
    public class R1Jaguar_EventComplexDataState : R1Serializable
    {
        public Pointer AnimationPointer { get; set; }
        public byte Byte04 { get; set; }
        public byte Byte05 { get; set; }
        public byte Byte06 { get; set; }
        public byte LinkedStateIndex { get; set; }
        public byte FrameCount { get; set; }
        public byte[] UnkBytes { get; set; }

        // Passed from other structs
        public ushort LayersPerFrame { get; set; }

        // Parsed
        //public Jaguar_R1_AnimationDescriptor Animation { get; set; }
        public R1_AnimationLayer[] Layers { get; set; }

        /// <summary>
        /// Handles the data serialization
        /// </summary>
        /// <param name="s">The serializer object</param>
        public override void SerializeImpl(SerializerObject s)
        {
            AnimationPointer = s.SerializePointer(AnimationPointer, name: nameof(AnimationPointer));
            Byte04 = s.Serialize<byte>(Byte04, name: nameof(Byte04));
            Byte05 = s.Serialize<byte>(Byte05, name: nameof(Byte05));
            Byte06 = s.Serialize<byte>(Byte06, name: nameof(Byte06));
            LinkedStateIndex = s.Serialize<byte>(LinkedStateIndex, name: nameof(LinkedStateIndex));
            FrameCount = s.Serialize<byte>(FrameCount, name: nameof(FrameCount));
            UnkBytes = s.SerializeArray<byte>(UnkBytes, 7, name: nameof(UnkBytes));

            if (AnimationPointer != null) {
                // AnimationPointer points to first layer. So, go back 4 bytes to get header
                /*s.DoAt(AnimationPointer - 0x4, () => {
                    Animation = s.SerializeObject<Jaguar_R1_AnimationDescriptor>(Animation, name: nameof(Animation));
                });*/
                s.DoAt(AnimationPointer, () => {
                    Layers = s.SerializeObjectArray<R1_AnimationLayer>(Layers, LayersPerFrame * FrameCount, name: nameof(Layers));
                });
            }
        }



        /// <summary>
        /// Gets a common animation from the animation descriptor
        /// </summary>
        /// <param name="animationDescriptor">The animation descriptor</param>
        /// <returns>The common animation</returns>
        public Unity_ObjAnimation ToCommonAnimation(R1Jaguar_EventDefinition eventDefinition) {
            // Create the animation
            var animation = new Unity_ObjAnimation {
                Frames = new Unity_ObjAnimationFrame[FrameCount],
            };

            // The layer index
            var layer = 0;

            var ignoreYBit = Context.Settings.EngineVersion == EngineVersion.R1Jaguar_Proto && AnimationPointer.AbsoluteOffset == 0x00811DDC;

            // Create each frame
            for (int i = 0; i < FrameCount; i++) {
                // Create the frame
                var frame = new Unity_ObjAnimationFrame(new Unity_ObjAnimationPart[LayersPerFrame]);

                if (Layers != null) {

                    // Create each layer
                    for (var layerIndex = 0; layerIndex < LayersPerFrame; layerIndex++) {
                        var animationLayer = Layers[layer];
                        layer++;

                        // Create the animation part
                        Unity_ObjAnimationPart part;
                        if (eventDefinition.UShort_12 == 5 || eventDefinition.StructType == 31) {
                            part = new Unity_ObjAnimationPart {
                                ImageIndex = BitHelpers.ExtractBits(animationLayer.ImageIndex, 7, 0),
                                XPosition = animationLayer.XPosition,
                                YPosition = ignoreYBit ? BitHelpers.ExtractBits(animationLayer.YPosition, 7, 0) : animationLayer.YPosition,
                                IsFlippedHorizontally = BitHelpers.ExtractBits(animationLayer.ImageIndex, 1, 7) != 0
                            };
                        } else {
                            part = new Unity_ObjAnimationPart {
                                ImageIndex = animationLayer.ImageIndex,
                                XPosition = BitHelpers.ExtractBits(animationLayer.XPosition, 7, 0),
                                YPosition = ignoreYBit ? BitHelpers.ExtractBits(animationLayer.YPosition, 7, 0) : animationLayer.YPosition,
                                IsFlippedHorizontally = BitHelpers.ExtractBits(animationLayer.XPosition, 1, 7) != 0
                            };
                        }

                        // Add the part
                        frame.SpriteLayers[layerIndex] = part;
                    }
                }
                // Set the frame
                animation.Frames[i] = frame;
            }

            return animation;
        }
    }
}