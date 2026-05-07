// Package frame defines the wire format for relay-tunnel: the plaintext Frame
// struct and helpers to marshal/unmarshal it. See crypto.go for the AES-GCM
// envelope and batch packer that wrap encoded frames before they hit the wire.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FlagSYN = 1 << 0 // first frame for a session, carries Target
	FlagFIN = 1 << 1 // sender is closing its write side
	FlagACK = 1 << 2 // ACK-only / keepalive (no payload, no SYN, no FIN)
	FlagRST = 1 << 3 // session reset: sender has no state for this session (e.g. server restart)
)

const (
	SessionIDLen   = 16
	maxTargetLen   = 255
	maxPayloadSize = 10 * 1024 * 1024 // 10MB sanity cap
)

// Frame is the plaintext message exchanged between client and VPS server,
// before AES-GCM sealing.
type Frame struct {
	SessionID [SessionIDLen]byte
	Seq       uint64
	Flags     uint8
	Target    string // populated only when FlagSYN is set
	Payload   []byte
}

func (f *Frame) HasFlag(flag uint8) bool { return f.Flags&flag != 0 }

// Marshal serializes the frame to a byte slice using the schema:
//
//	session_id  : 16 bytes
//	seq         : uint64 BE
//	flags       : uint8
//	target_len  : uint8
//	target      : N bytes
//	payload_len : uint32 BE
//	payload     : N bytes
func (f *Frame) Marshal() ([]byte, error) {
	if len(f.Target) > maxTargetLen {
		return nil, fmt.Errorf("target too long: %d > %d", len(f.Target), maxTargetLen)
	}
	if len(f.Payload) > maxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d", len(f.Payload))
	}
	size := SessionIDLen + 8 + 1 + 1 + len(f.Target) + 4 + len(f.Payload)
	out := make([]byte, size)
	off := 0
	copy(out[off:], f.SessionID[:])
	off += SessionIDLen
	binary.BigEndian.PutUint64(out[off:], f.Seq)
	off += 8
	out[off] = f.Flags
	off++
	out[off] = uint8(len(f.Target))
	off++
	copy(out[off:], f.Target)
	off += len(f.Target)
	binary.BigEndian.PutUint32(out[off:], uint32(len(f.Payload)))
	off += 4
	copy(out[off:], f.Payload)
	return out, nil
}

// Unmarshal parses a frame produced by Marshal. Returns the number of bytes
// consumed (which equals len(data) for a well-formed single frame).
func Unmarshal(data []byte) (*Frame, int, error) {
	if len(data) < SessionIDLen+8+1+1+4 {
		return nil, 0, errors.New("frame: short header")
	}
	f := &Frame{}
	off := 0
	copy(f.SessionID[:], data[off:off+SessionIDLen])
	off += SessionIDLen
	f.Seq = binary.BigEndian.Uint64(data[off:])
	off += 8
	f.Flags = data[off]
	off++
	tlen := int(data[off])
	off++
	if len(data) < off+tlen+4 {
		return nil, 0, errors.New("frame: short target/len")
	}
	if tlen > 0 {
		f.Target = string(data[off : off+tlen])
	}
	off += tlen
	plen := int(binary.BigEndian.Uint32(data[off:]))
	off += 4
	if plen > maxPayloadSize {
		return nil, 0, fmt.Errorf("frame: payload too large: %d", plen)
	}
	if len(data) < off+plen {
		return nil, 0, errors.New("frame: short payload")
	}
	if plen > 0 {
		// Zero-copy slice into caller's buffer. Safe when the caller (DecodeBatch)
		// owns the backing buffer and does not reuse it — which is always the case
		// since c.Open allocates a fresh plaintext slice on every call.
		f.Payload = data[off : off+plen]
	}
	off += plen
	return f, off, nil
}
