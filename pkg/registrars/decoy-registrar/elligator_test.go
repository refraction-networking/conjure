package decoy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	pb "github.com/refraction-networking/conjure/proto"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

var representativeAndFSPLen = 54

func tryDecrypt(b []byte, sharedSecret []byte) (*pb.ClientToStation, *oldSharedKeys, error) {
	l := len(b)
	if l-92 < 0 {
		return nil, nil, fmt.Errorf("payload too small %d", l)
	}
	b = b[5:]

	// We have the shared secret already so we don't need to generate it from the tag.
	// Instead we can generate the keys directly.
	keys, err := builldClientSharedKeysOld(sharedSecret)
	if err != nil {
		return nil, nil, err
	}

	//======================================================================
	// Starting from 92 byte from the end of the TLS payload extract
	// stego'd data from each block of 4 bytes (if the payload length isn't
	// a multiple of 4, just ignore the tail). Continue until we have run
	// out of input data, or room in the output buffer.
	//     See Registration-Tagging-and-Signaling on the wiki for an explanation
	//  of the 92 byte magic number here.
	fspCipher := make([]byte, representativeAndFSPLen)

	outOffset := 0
	for inOffset := l - 92; inOffset < (l-3) && outOffset < (representativeAndFSPLen-2); {
		b1, err := extractStegoBytes(b[inOffset : inOffset+4])
		if err != nil {
			return nil, keys, err
		}
		copy(fspCipher[outOffset:outOffset+3], b1)
		inOffset += 4
		outOffset += 3
	}

	// Initialize FSP AES cipher
	block, err := aes.NewCipher(keys.FspKey)
	if err != nil {
		return nil, keys, err
	}
	nonce := keys.FspIv
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, keys, err
	}
	// Decrypt the Fixed size payload using the known FSP size
	fspPlain, err := aesgcm.Open(nil, nonce, fspCipher[32:54], nil)
	if err != nil {
		return nil, keys, fmt.Errorf("failed decrypting fsp: %w", err)
	}

	fsp := &FSP{}
	err = fsp.Unmarshal(fspPlain)
	if err != nil {
		return nil, keys, err
	}

	if fsp.VspSize < 16 {
		return nil, keys, fmt.Errorf("vsp size too small")
	} else if fsp.VspSize%3 != 0 {
		return nil, keys, fmt.Errorf("Variable Stego Payload Size %d non-divisible by 3", fsp.VspSize)
	}
	encryptedVsp := make([]byte, fsp.VspSize)
	outOffset = 0
	stegoSize := fsp.VspSize / 3 * 4 // translate to encoded length.
	if l-92-int(stegoSize) < 0 {
		return nil, keys, fmt.Errorf("Stego Payload Size %d does not fit into TLS record of size %d", fsp.VspSize, l)
	}

	for inOffset := l - 92 - int(stegoSize); inOffset < (l-3) && outOffset < (int(fsp.VspSize)-2); {
		b1, err := extractStegoBytes(b[inOffset : inOffset+4])
		if err != nil {
			return nil, keys, err
		}
		copy(encryptedVsp[outOffset:outOffset+3], b1)
		inOffset += 4
		outOffset += 3
	}

	// Initialize VSP AES cipher
	blockV, err := aes.NewCipher(keys.VspKey)
	if err != nil {
		return nil, keys, err
	}
	nonceV := keys.VspIv
	aesgcmV, err := cipher.NewGCM(blockV)
	if err != nil {
		return nil, keys, err
	}
	// Decrypt the Variable size payload using the size specified in the fixed sized payload
	vspPlain, err := aesgcmV.Open(nil, nonceV, encryptedVsp[:fsp.VspSize], nil)
	if err != nil {
		return nil, keys, fmt.Errorf("failed decrypting vsp: %w", err)
	}

	c2s := &pb.ClientToStation{}
	err = proto.Unmarshal(vspPlain, c2s)
	if err != nil {
		return nil, keys, err
	}
	return c2s, keys, nil
}

var testECDSAPrivateKey, _ = x509.ParseECPrivateKey(fromHex("3081dc0201010442019883e909ad0ac9ea3d33f9eae661f1785206970f8ca9a91672f1eedca7a8ef12bd6561bb246dda5df4b4d5e7e3a92649bc5d83a0bf92972e00e62067d0c7bd99d7a00706052b81040023a18189038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b"))
var testECDSACertificate = fromHex("3082020030820162020900b8bf2d47a0d2ebf4300906072a8648ce3d04013045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c7464301e170d3132313132323135303633325a170d3232313132303135303633325a3045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c746430819b301006072a8648ce3d020106052b81040023038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b300906072a8648ce3d040103818c0030818802420188a24febe245c5487d1bacf5ed989dae4770c05e1bb62fbdf1b64db76140d311a2ceee0b7e927eff769dc33b7ea53fcefa10e259ec472d7cacda4e970e15a06fd00242014dfcbe67139c2d050ebd3fa38c25c13313830d9406bbd4377af6ec7ac9862eddd711697f857c56defb31782be4c7780daecbbe9e4e3624317b6a0f399512078f2a")

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// Below is for testing that SharedSecret and ConjureSeed match with old client version.
type oldSharedKeys struct {
	SharedSecret, Representative                               []byte
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, ConjureSeed []byte
	reader                                                     io.Reader
}

func builldClientSharedKeysOld(sharedSecret []byte) (*oldSharedKeys, error) {

	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := &oldSharedKeys{
		SharedSecret:    sharedSecret,
		FspKey:          make([]byte, 16),
		FspIv:           make([]byte, 12),
		VspKey:          make([]byte, 16),
		VspIv:           make([]byte, 12),
		NewMasterSecret: make([]byte, 48),
		ConjureSeed:     make([]byte, 16),
		reader:          tdHkdf,
	}

	if _, err := tdHkdf.Read(keys.FspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.FspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.NewMasterSecret); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}
	return keys, nil
}

func unwrap[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

// Extracts 3 stego'd bytes inBuf to 'outBuf', from the 4 bytes of AES
// ciphertext at 'inBuf'.
func extractStegoBytes(inBuf []byte) ([]byte, error) {
	outBuf := make([]byte, 3)
	if len(inBuf) != 4 || len(outBuf) != 3 {
		return nil, fmt.Errorf("extract_stego_bytes: bad input lengths")
	}

	x := uint32(inBuf[0]&0x3f) * uint32(64*64*64)
	x += uint32(inBuf[1]&0x3f) * uint32(64*64)
	x += uint32(inBuf[2]&0x3f) * uint32(64)
	x += uint32(inBuf[3] & 0x3f)

	outBuf[0] = byte((x >> 16) & 0xff)
	outBuf[1] = byte((x >> 8) & 0xff)
	outBuf[2] = byte((x) & 0xff)
	return outBuf, nil
}

type FSP struct {
	VspSize uint16
	Flags   uint8
	bytes   []byte
}

func (f *FSP) Unmarshal(b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("fsp: not enough bytes")
	}

	f.VspSize = uint16(b[0])<<8 + uint16(b[1])
	f.Flags = b[2]
	f.bytes = b
	return nil
}

func TestFSPUnmarshall(t *testing.T) {
	fsp := &FSP{}
	err := fsp.Unmarshal([]byte{0x01, 0x02, 0x03, 0x11, 0x12, 0x13})
	if err != nil {
		t.Fatal(err)
	}
	if fsp.VspSize != 0x0102 {
		t.Fatal("wrong vsp size")
	}
	if fsp.Flags != 0x03 {
		t.Fatal("wrong flags")
	}
}
