package iputils

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAllIPv4ForInterface(t *testing.T) {
}

func TestMaskIPv4(t *testing.T) {
}

func TestIpv4ToUint(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(
		uint32(0xffffffff),
		ipv4ToUint([]byte{255, 255, 255, 255}),
		"check max val of uin32 fail",
	)

	assert.Equal(
		binary.BigEndian.Uint32([]byte{192, 168, 28, 69}),
		ipv4ToUint([]byte{192, 168, 28, 69}),
		"check byte slice of len == 4",
	)

	assert.Equal(
		binary.BigEndian.Uint32([]byte{192, 172, 10, 20}),
		ipv4ToUint([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 172, 10, 20}),
		"check byte slice of len == 16",
	)
}

func TestUintToIpv4(t *testing.T) {
}

func TestMaskToUint(t *testing.T) {
}

func TestUintToMask(t *testing.T) {
}
