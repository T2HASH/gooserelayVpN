package frame

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Crypto wraps an AES-256-GCM AEAD with the relay-tunnel envelope format:
//
//	nonce (12 bytes) || ciphertext+tag (Seal output, tag is the trailing 16 bytes)
type Crypto struct {
	aead cipher.AEAD
}

// b64Encoding is the encoding used on the wire. RawStdEncoding (no '=' padding)
// shaves ~0.5–1.5% of bytes off every batch versus StdEncoding. The decoder is
// tolerant of either form (it strips trailing '=' before decoding) so an
// upgraded peer can still talk to a legacy peer that emits padded output.
var b64Encoding = base64.RawStdEncoding

// NewCryptoFromHexKey parses a 64-char hex string into a 32-byte AES-256 key
// and constructs a Crypto. The same key must be configured on both client and VPS server.
func NewCryptoFromHexKey(hexKey string) (*Crypto, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Crypto{aead: gcm}, nil
}

// Seal encrypts plaintext and returns nonce||ciphertext (tag appended by GCM).
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce read: %w", err)
	}
	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open inverts Seal. Returns an error on auth-tag failure (tampered ciphertext,
// nonce, or tag, or wrong key).
func (c *Crypto) Open(envelope []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(envelope) < ns+c.aead.Overhead() {
		return nil, errors.New("crypto: envelope too short")
	}
	nonce := envelope[:ns]
	ct := envelope[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return pt, nil
}

// ClientIDLen is the length of the per-process client identifier prepended to
// every batch. Clients pick a random ClientID once at startup; the server uses
// it to partition sessions so that downstream frames generated for one client
// are never delivered to a different client polling the same server.
const ClientIDLen = 16

// batchPool reuses the marshaled-slice scratch and the plaintext header
// buffer across EncodeBatch calls. Without pooling, each batch allocates two
// fresh buffers (the plain header + the marshaled-frame slice header), which
// is meaningful at our drain rate (≤ every 350 ms per worker, 3 workers).
var (
	encPlainPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, 0, 64*1024)
		return &buf
	}}
	encMarshaledPool = sync.Pool{New: func() interface{} {
		buf := make([][]byte, 0, 32)
		return &buf
	}}
	// zstdEncPool and zstdDecPool are used by EncodeBatch/DecodeBatch.
	// Pooling avoids re-initialising the encoder's internal state on every batch.
	// SpeedFastest (level 1) is ~2× faster than DEFLATE BestSpeed and produces
	// 10–15% smaller output on compressible text/HTTP traffic.
	zstdEncPool = sync.Pool{New: func() interface{} {
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		return enc
	}}
	zstdDecPool = sync.Pool{New: func() interface{} {
		dec, _ := zstd.NewReader(nil)
		return dec
	}}
)

const (
	// batchFlagRaw marks an uncompressed plaintext payload.
	batchFlagRaw = byte(0x00)
	// batchFlagFlate is the legacy DEFLATE flag. No longer emitted by this
	// version; retained so updated binaries can still decode batches sent by
	// older peers that have not been redeployed yet.
	batchFlagFlate = byte(0x01)
	// batchFlagZstd marks a Zstandard-compressed plaintext payload.
	batchFlagZstd = byte(0x02)

	// compressMinSize is the minimum payload size (excluding the flags byte)
	// before compression is attempted. Tiny batches (SYN/FIN/keepalive) are
	// unlikely to benefit.
	compressMinSize = 512
)

// EncodeBatch packs zero or more frames into a base64-encoded HTTP body.
//
// Wire format (before base64):
//
//	nonce (12 bytes) || AES-GCM ciphertext+tag over:
//	    flags (1 byte)  — 0x00 raw | 0x01 DEFLATE-compressed body
//	    client_id (16 bytes)
//	    u16 frame_count
//	    for each frame: u32 marshaled_len || marshaled_frame_bytes
//	    (above three fields are DEFLATE-compressed when flags == 0x01)
//
// The entire batch is sealed once, replacing the old per-frame envelope scheme.
// This reduces crypto overhead from O(N) nonces+tags to one, cutting both CPU
// and wire bytes significantly for large batches.
// base64 is retained for Apps Script's ContentService text requirement.
//
// The client_id is sent inside the encrypted plaintext (not as an HTTP header)
// because the Apps Script forwarder only relays the request body — headers do
// not survive the hop. Sealing it under AES-GCM also means a passive observer
// of the relay traffic cannot tell two clients apart by their IDs.
func EncodeBatch(c *Crypto, clientID [ClientIDLen]byte, frames []*Frame) ([]byte, error) {
	if len(frames) > 0xFFFF {
		return nil, fmt.Errorf("batch: too many frames: %d", len(frames))
	}

	// Marshal all frames first so we know the exact plaintext size.
	marshaledP := encMarshaledPool.Get().(*[][]byte)
	marshaled := (*marshaledP)[:0]
	defer func() {
		for i := range marshaled {
			marshaled[i] = nil
		}
		marshaled = marshaled[:0]
		*marshaledP = marshaled
		encMarshaledPool.Put(marshaledP)
	}()

	plainSize := 1 + ClientIDLen + 2 // flags byte + client_id + u16 frame count
	for _, f := range frames {
		raw, err := f.Marshal()
		if err != nil {
			return nil, fmt.Errorf("batch: marshal frame: %w", err)
		}
		marshaled = append(marshaled, raw)
		plainSize += 4 + len(raw) // u32 length prefix + frame bytes
	}

	// Pull a plaintext scratch buffer from the pool; grow if needed.
	plainP := encPlainPool.Get().(*[]byte)
	plain := (*plainP)[:0]
	if cap(plain) < plainSize {
		plain = make([]byte, 0, plainSize)
	}
	defer func() {
		// Reset and return to pool. The capacity is preserved so the next
		// EncodeBatch reuses the same underlying allocation.
		plain = plain[:0]
		*plainP = plain
		encPlainPool.Put(plainP)
	}()

	plain = append(plain, 0x00) // flags placeholder at index 0
	plain = append(plain, clientID[:]...)
	plain = append(plain, byte(len(frames)>>8), byte(len(frames)))
	for _, raw := range marshaled {
		plain = append(plain,
			byte(len(raw)>>24), byte(len(raw)>>16), byte(len(raw)>>8), byte(len(raw)))
		plain = append(plain, raw...)
	}

	// Attempt Zstandard compression on the payload section (everything after
	// the flags byte at index 0). Only worthwhile for batches large enough that
	// the overhead is amortised; small control batches (SYN/FIN/keepalive) are
	// sent raw. If compression does not shrink the data (e.g. already-encrypted
	// TLS payloads) we fall back to raw transparently.
	sealInput := plain // default: raw, flags byte already 0x00
	if len(plain)-1 >= compressMinSize {
		enc := zstdEncPool.Get().(*zstd.Encoder)
		// EncodeAll appends compressed bytes to dst. The [:1:1] cap trick gives
		// us a fresh backing array with the flags placeholder at [0], so the
		// pool-owned plain buffer is never modified.
		compressed := enc.EncodeAll(plain[1:], plain[:1:1])
		zstdEncPool.Put(enc)
		if len(compressed)-1 < len(plain)-1 {
			compressed[0] = batchFlagZstd
			sealInput = compressed
		} else {
			plain[0] = batchFlagRaw
		}
	} else {
		plain[0] = batchFlagRaw
	}

	sealed, err := c.Seal(sealInput)
	if err != nil {
		return nil, fmt.Errorf("batch: seal: %w", err)
	}
	// Pre-size the destination so we encode directly into a []byte rather
	// than the EncodeToString -> string -> []byte intermediate copy.
	out := make([]byte, b64Encoding.EncodedLen(len(sealed)))
	b64Encoding.Encode(out, sealed)
	return out, nil
}

// DecodeBatch is the inverse of EncodeBatch. The entire batch is authenticated
// as a single unit; any corruption causes the whole batch to be rejected.
//
// Zero-copy contract: when the batch is uncompressed (batchFlagRaw), Frame.Payload
// slices point directly into the plaintext buffer allocated by c.Open — callers
// must treat them as read-only. For compressed batches (batchFlagFlate) the
// payloads point into the decompressed buffer, which is also heap-allocated and
// must not be modified by callers.
func DecodeBatch(c *Crypto, body []byte) ([ClientIDLen]byte, []*Frame, error) {
	var zeroID [ClientIDLen]byte
	if len(body) == 0 {
		return zeroID, nil, nil
	}
	// bytes.TrimSpace returns a subslice (no alloc); Decode writes into a
	// pre-allocated buffer — together this is one allocation instead of three.
	// Strip trailing '=' so we can decode either RawStdEncoding (preferred,
	// what we now emit) or legacy StdEncoding (with padding) bodies. This
	// keeps the upgrade backward-compatible: an updated client/server can
	// still talk to a peer that hasn't been redeployed.
	trimmed := bytes.TrimRight(bytes.TrimSpace(body), "=")
	sealed := make([]byte, b64Encoding.DecodedLen(len(trimmed)))
	n, err := b64Encoding.Decode(sealed, trimmed)
	if err != nil {
		return zeroID, nil, fmt.Errorf("batch: base64 decode: %w", err)
	}
	sealed = sealed[:n]

	rawPlain, err := c.Open(sealed)
	if err != nil {
		return zeroID, nil, fmt.Errorf("batch: open: %w", err)
	}

	// Decode the leading flags byte. Both peers must run the same version;
	// an unrecognised flag byte is rejected so a protocol mismatch surfaces
	// immediately rather than producing silent corruption.
	if len(rawPlain) == 0 {
		return zeroID, nil, errors.New("batch: empty plaintext")
	}
	var plain []byte
	switch rawPlain[0] {
	case batchFlagRaw:
		plain = rawPlain[1:]
	case batchFlagFlate:
		// Legacy path: decode batches from older peers that still emit DEFLATE.
		r := flate.NewReader(bytes.NewReader(rawPlain[1:]))
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			return zeroID, nil, fmt.Errorf("batch: flate decompress: %w", err)
		}
		r.Close()
		plain = buf.Bytes()
	case batchFlagZstd:
		dec := zstdDecPool.Get().(*zstd.Decoder)
		decompressed, err := dec.DecodeAll(rawPlain[1:], nil)
		zstdDecPool.Put(dec)
		if err != nil {
			return zeroID, nil, fmt.Errorf("batch: zstd decompress: %w", err)
		}
		plain = decompressed
	default:
		return zeroID, nil, fmt.Errorf("batch: unknown flags byte 0x%02x", rawPlain[0])
	}

	if len(plain) < ClientIDLen+2 {
		return zeroID, nil, errors.New("batch: short header")
	}
	var clientID [ClientIDLen]byte
	copy(clientID[:], plain[:ClientIDLen])
	off := ClientIDLen
	count := int(binary.BigEndian.Uint16(plain[off : off+2]))
	off += 2
	frames := make([]*Frame, 0, count)
	for i := 0; i < count; i++ {
		if len(plain) < off+4 {
			return zeroID, nil, errors.New("batch: short frame length")
		}
		flen := int(binary.BigEndian.Uint32(plain[off:]))
		off += 4
		if len(plain) < off+flen {
			return zeroID, nil, errors.New("batch: short frame body")
		}
		f, _, err := Unmarshal(plain[off : off+flen])
		if err != nil {
			return zeroID, nil, fmt.Errorf("batch: unmarshal frame %d: %w", i, err)
		}
		frames = append(frames, f)
		off += flen
	}
	return clientID, frames, nil
}
