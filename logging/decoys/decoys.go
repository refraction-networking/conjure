package decoys

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/big"
	"sync"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

var globalAssets *assets
var ccFileNames = map[uint]string{
	0: "ClientConf.dev",
	//	538: "ClientConf",
}

// Decoy -- Registration decoy from ClientConf
type Decoy struct {
	ip  string
	sni string
}

const (
	V4 uint = iota
	V6
	Both
)

var assetsOnce sync.Once

type assets struct {
	decoys map[uint][]*Decoy
}

func Assets() *assets {
	_initAssets := func() { initAssets() }
	assetsOnce.Do(_initAssets)
	return globalAssets
}

func initAssets() {
	globalAssets = &assets{decoys: make(map[uint][]*Decoy)}

	for ver, cc := range ccFileNames {
		globalAssets.AddClientConf(ver, cc)
	}
}

func (a *assets) AddClientConf(ccv uint, fname string) {

	func(filename string) error {
		buf, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		clientConf := pb.ClientConf{}
		err = proto.Unmarshal(buf, &clientConf)
		if err != nil {
			return err
		}
		decoyList := clientConf.GetDecoyList().GetTlsDecoys()
		a.decoys[ccv] = make([]*Decoy, len(decoyList))
		for i := range decoyList {
			decoy := decoyList[i]
			a.decoys[ccv][i] = &Decoy{ip: decoy.GetIpAddrStr(), sni: decoy.GetHostname()}
		}
		return nil
	}(fname)
}

func (a *assets) GetAllDecoys(ccv uint) []*Decoy {
	return a.decoys[ccv]
}

func (a *assets) GetV4Decoys(ccv uint) []*Decoy {
	// DO NOT USE (INCOMPLETE)
	return a.decoys[ccv]
}

func (a *assets) GetV6Decoys(ccv uint) []*Decoy {
	// DO NOT USE (INCOMPLETE)
	return a.decoys[ccv]
}

func conjureHMAC(key []byte, str string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(str))
	return hash.Sum(nil)
}

// SelectDecoys -- Get all decoys chosen deterministically using HMAC(SharedSecret)
//
// 	Note: This DOES NOT WORK for V4/V6 exclusive yet. Both is the only option currently
//		working because that is the only option implemented in the client currently.
func SelectDecoys(sharedSecret []byte, ccv uint, width uint, ipv uint) []*Decoy {

	//[reference] prune to v6 only decoys if useV6 is true
	var allDecoys []*Decoy
	switch ipv {
	case V6:
		allDecoys = Assets().GetV6Decoys(ccv)
	case V4:
		allDecoys = Assets().GetV4Decoys(ccv)
	case Both:
		allDecoys = Assets().GetAllDecoys(ccv)
	default:
		allDecoys = Assets().GetAllDecoys(ccv)
	}

	decoys := make([]*Decoy, width)
	numDecoys := big.NewInt(int64(len(allDecoys)))
	hmacInt := new(big.Int)
	idx := new(big.Int)

	//[reference] select decoys
	for i := uint(0); i < width; i++ {
		macString := fmt.Sprintf("registrationdecoy%d", i)
		hmac := conjureHMAC(sharedSecret, macString)
		hmacInt = hmacInt.SetBytes(hmac[:8])
		hmacInt.SetBytes(hmac)
		hmacInt.Abs(hmacInt)
		idx.Mod(hmacInt, numDecoys)
		decoys[i] = allDecoys[int(idx.Int64())]
	}
	return decoys
}
