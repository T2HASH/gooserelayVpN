package protocol

import (
	"bytes"
	"encoding/json"
)

const (
	ProtocolVersion = 1
	ProbePrefix     = "goose_version_probe:v1"
)

type VersionInfo struct {
	OK             bool     `json:"ok"`
	Protocol       int      `json:"protocol"`
	ServerVersion  string   `json:"server_version"`
	MaxFramePayload int     `json:"max_frame_payload"`
	Features       []string `json:"features"`
}

type VersionProbe struct {
	Type          string `json:"type"`
	ClientVersion string `json:"client_version"`
	Protocol      int    `json:"protocol"`
}

func EncodeProbePayload(clientVersion string) []byte {
	probe := VersionProbe{
		Type:          "version_probe",
		ClientVersion: clientVersion,
		Protocol:      ProtocolVersion,
	}
	b, _ := json.Marshal(probe)
	return append([]byte(ProbePrefix+"|"), b...)
}

func IsProbePayload(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(ProbePrefix+"|")) || bytes.Equal(payload, []byte(ProbePrefix))
}

func DecodeVersionInfo(payload []byte) (*VersionInfo, error) {
	var info VersionInfo
	if err := json.Unmarshal(bytes.TrimSpace(payload), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func EncodeVersionInfo(serverVersion string, maxFramePayload int, features []string) ([]byte, error) {
	info := VersionInfo{
		OK:              true,
		Protocol:        ProtocolVersion,
		ServerVersion:   serverVersion,
		MaxFramePayload: maxFramePayload,
		Features:        features,
	}
	return json.Marshal(info)
}
