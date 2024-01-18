package impl

import (
	"errors"
	"github.com/gordonklaus/portaudio"
	"github.com/vee2xx/camtron"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"os"
	"time"
)

type Streaming struct {
	portainerAudioStream   *portaudio.Stream
	camtronReceiverChannel chan []byte
	stop                   chan bool

	videoChannel chan []byte
	audioChannel chan []byte
}

const (
	PortaudioInputChannelCount  = 1
	PortaudioOutputChannelCount = 0
	PortaudioSampleRate         = 44100
	PacketWaitTimeout           = 30 * time.Millisecond
)

func NewStreaming() Streaming {
	return Streaming{
		portainerAudioStream:   nil,
		camtronReceiverChannel: make(chan []byte, 1),
		stop:                   make(chan bool),
		videoChannel:           make(chan []byte, 1),
		audioChannel:           make(chan []byte, 1),
	}
}

func (n *node) initializeStreaming() error {
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

	n.streaming.portainerAudioStream = stream
	err = stream.Start()
	if err != nil {
		return xerrors.Errorf("failed to start PortAudio stream: %s", err)
	}

	camtron.RegisterStream(n.streaming.camtronReceiverChannel)
	go n.inputVideoStreamHandler()
	// Camtron likes to override global log output to a file, set this
	// to stdout here again
	n.logger.Output(os.Stdout)
	camtron.StartCam()

	return nil
}

func (n *node) destroyStreaming() error {
	audioStreamError := n.streaming.portainerAudioStream.Stop()
	audioTerminateError := portaudio.Terminate()

	n.streaming.stop <- true
	camtron.StopWebcamUI()
	camtron.ShutdownStream()

	return errors.Join(audioStreamError, audioTerminateError)
}

func (n *node) inputAudioCallback(
	data []byte,
	timeInfo portaudio.StreamCallbackTimeInfo,
	flags portaudio.StreamCallbackFlags,
) {
	select {
	case n.streaming.videoChannel <- data:
	default:

	}
}

func (n *node) inputVideoStreamHandler() {
	for {
		select {
		case _, _ = <-n.streaming.stop:
			return
		case packet, ok := <-n.streaming.camtronReceiverChannel:
			if !ok {
				continue
			}
			select {
			case n.streaming.videoChannel <- packet:
			default:

			}
		case val, _ := <-camtron.Context: //check the Camtron's global context channel for the signal to shut down
			if val == "stop" {
				return
			}
		}
	}
}

func (n *node) receiveCallDataMsg(msg types.Message, pkt transport.Packet) error {
	data, ok := msg.(*types.CallDataMessage)
	if !ok {
		panic("not a CallDataMessage")
	}
	n.logger.Printf("received %d video bytes and %d audio bytes", len(data.VideoBytes), len(data.AudioBytes))
	return nil
}

func (n *node) GetNextVideoBytes() []byte {
	select {
	case bytes, ok := <-n.streaming.videoChannel:
		if !ok {
			return []byte{}
		}
		return bytes
	case <-time.After(PacketWaitTimeout):
		return []byte{}
	}
}

func (n *node) GetNextAudioBytes() []byte {
	select {
	case bytes, ok := <-n.streaming.audioChannel:
		if !ok {
			return []byte{}
		}
		return bytes
	case <-time.After(PacketWaitTimeout):
		return []byte{}
	}
}

func (n *node) GetNextCallDataMessage() types.CallDataMessage {
	return types.CallDataMessage{
		VideoBytes: n.GetNextVideoBytes(),
		AudioBytes: n.GetNextAudioBytes(),
	}
}