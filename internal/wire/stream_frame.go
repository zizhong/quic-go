package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A StreamFrame of QUIC
type StreamFrame struct {
	StreamID       protocol.StreamID
	FinBit         bool
	DataLenPresent bool
	Offset         protocol.ByteCount
	Data           []byte
}

var errInvalidStreamIDLen = errors.New("StreamFrame: Invalid StreamID length")

// ParseStreamFrame reads a stream frame. The type byte must not have been read yet.
func ParseStreamFrame(r *bytes.Reader, version protocol.VersionNumber) (*StreamFrame, error) {
	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	var offsetLen uint8
	var streamIDLen uint8
	if version <= protocol.Version39 {
		frame.FinBit = typeByte&0x40 > 0
		frame.DataLenPresent = typeByte&0x20 > 0
		offsetLen = typeByte & 0x1c >> 2
		if offsetLen != 0 {
			offsetLen++
		}
		streamIDLen = typeByte&0x3 + 1
	} else {
		fmt.Printf("typeByte: 0x%x\n", typeByte)
		frame.FinBit = typeByte&0x20 > 0
		frame.DataLenPresent = typeByte&0x1 > 0
		offsetLen = typeByte & 0x6 >> 1
		if offsetLen != 0 {
			offsetLen = 1 << offsetLen
		}
		streamIDLen = typeByte&0x18 + 1
	}

	fmt.Println("streamID len: ", streamIDLen)
	sid, err := utils.GetByteOrder(version).ReadUintN(r, streamIDLen)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)
	fmt.Println("streamID: ", frame.StreamID)

	fmt.Println("offsetLen: ", offsetLen)
	offset, err := utils.GetByteOrder(version).ReadUintN(r, offsetLen)
	if err != nil {
		return nil, err
	}
	frame.Offset = protocol.ByteCount(offset)
	fmt.Println("offset: ", frame.Offset)

	var dataLen uint16
	if frame.DataLenPresent {
		dataLen, err = utils.GetByteOrder(version).ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}
	fmt.Printf("dataLen: 0x%x\n", dataLen)

	if dataLen > uint16(protocol.MaxPacketSize) {
		return nil, qerr.Error(qerr.InvalidStreamData, "data len too large")
	}

	if !frame.DataLenPresent {
		// The rest of the packet is data
		dataLen = uint16(r.Len())
	}
	if dataLen != 0 {
		frame.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			return nil, err
		}
	}

	if frame.Offset+frame.DataLen() < frame.Offset {
		return nil, qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")
	}
	if !frame.FinBit && frame.DataLen() == 0 {
		return nil, qerr.EmptyStreamFrameNoFin
	}
	return frame, nil
}

// WriteStreamFrame writes a stream frame.
func (f *StreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if len(f.Data) == 0 && !f.FinBit {
		return errors.New("StreamFrame: attempting to write empty frame without FIN")
	}

	offsetLength := f.getOffsetLength(version)
	streamIDLen := f.calculateStreamIDLength()

	var typeByte byte
	if version <= protocol.Version39 {
		typeByte = uint8(0x80) // sets the leftmost bit to 1
		if f.FinBit {
			typeByte ^= 0x40
		}
		if f.DataLenPresent {
			typeByte ^= 0x20
		}
		if offsetLength > 0 {
			typeByte ^= (uint8(offsetLength) - 1) << 2
		}
		typeByte ^= streamIDLen - 1
	} else {
		typeByte = uint8(0xc0) // sets the two leftmost bits to 1
		if f.FinBit {
			typeByte ^= 0x20
		}
		if f.DataLenPresent {
			typeByte ^= 0x1
		}
		if offsetLength > 0 {
			typeByte ^= (uint8(offsetLength/2) - 1) << 1
		}
		typeByte ^= (streamIDLen - 1) << 3
	}

	b.WriteByte(typeByte)

	switch streamIDLen {
	case 1:
		b.WriteByte(uint8(f.StreamID))
	case 2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(f.StreamID))
	case 3:
		utils.GetByteOrder(version).WriteUint24(b, uint32(f.StreamID))
	case 4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(f.StreamID))
	default:
		return errInvalidStreamIDLen
	}

	switch offsetLength {
	case 0:
	case 2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(f.Offset))
	case 3:
		utils.GetByteOrder(version).WriteUint24(b, uint32(f.Offset))
	case 4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(f.Offset))
	case 5:
		utils.GetByteOrder(version).WriteUint40(b, uint64(f.Offset))
	case 6:
		utils.GetByteOrder(version).WriteUint48(b, uint64(f.Offset))
	case 7:
		utils.GetByteOrder(version).WriteUint56(b, uint64(f.Offset))
	case 8:
		utils.GetByteOrder(version).WriteUint64(b, uint64(f.Offset))
	}

	if f.DataLenPresent {
		utils.GetByteOrder(version).WriteUint16(b, uint16(len(f.Data)))
	}

	b.Write(f.Data)
	return nil
}

func (f *StreamFrame) calculateStreamIDLength() uint8 {
	if f.StreamID < (1 << 8) {
		return 1
	} else if f.StreamID < (1 << 16) {
		return 2
	} else if f.StreamID < (1 << 24) {
		return 3
	}
	return 4
}

func (f *StreamFrame) getOffsetLength(version protocol.VersionNumber) protocol.ByteCount {
	if f.Offset == 0 {
		return 0
	}
	if f.Offset < (1 << 16) {
		return 2
	}
	if version < protocol.Version39 && f.Offset < (1<<24) {
		return 3
	}
	if f.Offset < (1 << 32) {
		return 4
	}
	if version > protocol.Version39 {
		if f.Offset < (1 << 40) {
			return 5
		}
		if f.Offset < (1 << 48) {
			return 6
		}
		if f.Offset < (1 << 56) {
			return 7
		}
	}
	return 8
}

// MinLength returns the length of the header of a StreamFrame
// the total length of the StreamFrame is frame.MinLength() + frame.DataLen()
func (f *StreamFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	length := protocol.ByteCount(1) + protocol.ByteCount(f.calculateStreamIDLength()) + f.getOffsetLength(version)
	if f.DataLenPresent {
		length += 2
	}
	return length, nil
}

// DataLen gives the length of data in bytes
func (f *StreamFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}
