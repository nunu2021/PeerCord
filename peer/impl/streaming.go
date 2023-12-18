package impl

import (
	"errors"
	"github.com/gordonklaus/portaudio"
	"github.com/vee2xx/camtron"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

type Streaming struct {
	audioStream  *portaudio.Stream
	videoChannel chan []byte
}

const (
	PortaudioInputChannelCount  = 1
	PortaudioOutputChannelCount = 0
	PortaudioSampleRate         = 44100
)

func NewStreaming() Streaming {
	return Streaming{
		audioStream:  nil,
		videoChannel: make(chan []byte, 50),
	}
}

func (n *node) InitializeStreaming() error {
	err := portaudio.Initialize()
	if err != nil {
		return xerrors.Errorf("failed to initialize PortAudio: %s", err)
	}

	stream, err := portaudio.OpenDefaultStream(
		PortaudioInputChannelCount,
		PortaudioOutputChannelCount,
		PortaudioSampleRate,
		portaudio.FramesPerBufferUnspecified,
		n.inputAudioCallback,
	)

	if err != nil {
		return xerrors.Errorf("failed to open PortAudio stream: %s", err)
	}

	n.streaming.audioStream = stream
	err = stream.Start()
	if err != nil {
		return xerrors.Errorf("failed to start PortAudio stream: %s", err)
	}

	camtron.RegisterStream(n.streaming.videoChannel)
	go n.inputVideoStreamHandler()
	camtron.StartCam()

	return nil
}

func (n *node) StopStreaming() error {
	audioStreamError := n.streaming.audioStream.Stop()
	audioTerminateError := portaudio.Terminate()

	close(n.streaming.videoChannel)
	camtron.StopWebcamUI()

	return errors.Join(audioStreamError, audioTerminateError)
}

func (n *node) receiveJoinCallRequest(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) receiveJoinCallReply(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) receiveLeaveCall(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) receiveCallData(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) inputAudioCallback(
	data []int32,
	timeInfo portaudio.StreamCallbackTimeInfo,
	flags portaudio.StreamCallbackFlags,
) {
}

func (n *node) inputVideoStreamHandler() {}
