package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"./decoys"
	"./rx"
)

// SessionStats -- Tracked items associated with one client session lifecycle
type SessionStats struct {
	Phantom      string
	Mask         string
	Covert       string
	Transport    int
	SharedSecret []byte
	Liveness     string
	ccVersion    int // NOT CURRENTLY IMPLEMENTED
	width        int // NOT CURRENTLY IMPLEMENTED

	BytesUp int64
	BytesDn int64

	RegConns    []string
	ExpRegConns []string

	RegTime  time.Time
	ConnTime time.Time
	Reg2Conn int64
	Reg2Exp  int64
	Duration int64

	clientRegIP  string
	clientConnIP string
}

// OperationStats -- periodic performance metrics
type OperationStats struct {
	// LivePhantoms -- phantomIP: number of hits
	LivePhantoms              map[string]int
	uniqueRegsForLivePhantoms int

	newRegistrations int
	registrations    int // NOT CURRENTLY TRACKED
	sessions         int // NOT CURRENTLY TRACKED

	// MissedRegistrations -- Map of decoyID to sessionIDs that missed it.
	MissedRegistrations map[string][]string
	uniqueMissedRegs    int

	TotalBytesUp int64 // NOT CURRENTLY TRACKED
	TotalBytesDn int64 // NOT CURRENTLY TRACKED

	// PossibleProbes -- map of phantomIP to array of clientIPs seen and probe time.
	// 		May allow us to plot latency for followup probes.
	PossibleProbes map[string][]struct {
		clientIP string
		ts       time.Time
	}
}

// Trial -- Cumulative metrics and stats from a set of logs
type Trial struct {
	//Sessions -- Map of RegistrationID (truncated shared secret) to session stats
	Sessions map[string]*SessionStats

	//Metrics --Map of interval end time to interval metrics
	Metrics map[time.Time]*OperationStats
}

type sessionEnd struct {
	From     string
	Duration int64
	Written  int64
	Tag      string
	Err      string
}

func (tr *Trial) ParseApplication(fname string) {
	ar := rx.GetAppRx()

	// ****tmp-test*****
	var reg2conn []float64
	// ****/tmp-test****

	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, match := ar.Check(scanner.Text())
		switch key {
		case "valid-connection":
			//fmt.Printf("%v -- %v\n", key, match)
			f, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				reg2conn = append(reg2conn, f/1000)
			}
		case "new-registration":
		case "session-end":
			var sessionStats sessionEnd
			err = json.Unmarshal([]byte(match[2]), &sessionStats)
			// if sessionStats.Duration > 0 {
			// 	fmt.Printf("%v\n", sessionStats.Duration)
			// }
		case "no-match":
			continue
		default:
			fmt.Printf("Unknown match -- \"%v\" -- please define case in Detector", key)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for i := range reg2conn {
		fmt.Println(reg2conn[i])
	}
}

// GetDecoySelections -- Gets the deterministically selected decoys that should be seen registering
//		for this sression.
//
// 	Note: Can only be used if SessionStats has the SharedSecret defined ([upcoming] and registration width )
func (s *SessionStats) GetDecoySelections(width uint, ccVersion uint) []*decoys.Decoy {
	return decoys.SelectDecoys(s.SharedSecret, ccVersion, width, decoys.Both) // add v6support
}

func (tr *Trial) ParseDetector(fname string) {
	dr := rx.GetDetectorRx()

	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, match := dr.Check(scanner.Text())
		switch key {
		case "stats-logline":
			//fmt.Printf("%v -- %v\n", key, match)
		case "new-registration":
			if tr.Sessions[match[3]] == nil {
				tr.Sessions[match[3]] = &SessionStats{RegConns: []string{match[2]}}
				tr.Sessions[match[3]].SharedSecret, _ = hex.DecodeString(match[3])
				tr.Sessions[match[3]].GetDecoySelections(5, 0) // static width and ClientConf Version for now.

			} else {
				tr.Sessions[match[3]].RegConns = append(tr.Sessions[match[3]].RegConns, match[2])
			}
			//fmt.Printf("%v -- %v\n", match[3][:16], tr.Sessions[match[3]].RegConns)
		case "no-match":
			continue
		default:
			fmt.Printf("Unknown match -- \"%v\" -- please define case in Detector", key)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	tr := Trial{Sessions: make(map[string]*SessionStats)}

	tr.ParseApplication("./application_12-16.log")
	// tr.ParseDetector("./detector_12-16.log")

	for _, session := range tr.Sessions {
		fmt.Println(len(session.RegConns))
	}
}
