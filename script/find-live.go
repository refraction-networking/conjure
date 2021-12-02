
package main

import (
    "fmt"
    "os"
    "compress/gzip"
    "bufio"
    "strings"
    "log"
    "encoding/json"
)

/*
{"event":{"module":"system","dataset":"system.syslog","timezone":"-05:00"},"@version":"1","system":{"syslog":{"timestamp":"Nov 30 19:00:35","message":"[ZMQ] 2021/11/30 19:00:35.130586 New registration: 7267cfd7f9adad51 {\"Phantom\":\"192.122.190.158\",\"SharedSecret\":\"7267cfd7f9adad51f766a5f9052df4999231eb0fe61c07c32ca98989d1e6be50\",\"Covert\":\"\",\"Mask\":\"\",\"Flags\":{\"prescanned\":true},\"Transport\":1,\"RegTime\":\"2021-11-30T19:00:35.124257989-05:00\",\"DecoyListVersion\":1153,\"Source\":3}","pid":"21612","hostname":"decoy-tap","program":"conjure","timestamp_tz":"Nov 30 19:00:35 -05:00"}},"@timestamp":"2021-12-01T00:00:35.000Z","fileset":{"name":"syslog"},"log":{"file":{"path":"/var/log/syslog"},"offset":1945258447},"service":{"type":"system"},"agent":{"version":"7.12.0","name":"decoy-tap","type":"filebeat","hostname":"decoy-tap","ephemeral_id":"63323dd7-e77b-436b-a104-1646dec3e257","id":"4843a509-c709-4dc1-9d48-50e35ce1a12e"},"host":{"containerized":false,"name":"decoy-tap","architecture":"x86_64","hostname":"decoy-tap","mac":["0c:c4:7a:c3:67:4a","0c:c4:7a:c3:67:4b","3c:fd:fe:9d:91:78","3c:fd:fe:9d:91:79"],"ip":["192.122.200.166","2001:48a8:7fff:b::2","fe80::ec4:7aff:fec3:674a","10.0.0.3","fe80::3efd:feff:fe9d:9178","fe80::3efd:feff:fe9d:9179"],"os":{"kernel":"4.4.0-124-generic","version":"16.04.5 LTS (Xenial Xerus)","platform":"ubuntu","name":"Ubuntu","type":"linux","family":"debian","codename":"xenial"},"id":"d2be336232a54d168106506770837db0"},"ecs":{"version":"1.8.0"},"tags":["beats_input_codec_plain_applied"],"input":{"type":"log"}}
*/

type LogLine struct {
    Event struct {
        Module string   `json:"module"`
        Dataset string  `json:"dataset"`
        Timezone string `json:"timezone"`
    } `json:"event"`
    Version string      `json:"@version"`
    System struct {
        Syslog struct {
            Timestamp string `json:"timestamp"`
            Message string   `json:"message"`
            Pid string       `json:"pid"`
            Hostname string  `json:"hostname"`
            Program string   `json:"program"`
        } `json: "syslog"`
    } `json: "system"`
    // etc..
}

func getMessage(line string) string {
    var obj LogLine
    err := json.Unmarshal([]byte(line), &obj)
    if err != nil {
        fmt.Println(line)
        fmt.Println(err)
    }
    return obj.System.Syslog.Message
}

//Dec 01 18:23:15 rnd-artemis conjure[3973007]: [ZMQ] 2021/12/01 18:23:15.016600 New registration: bc075982d03fd5dd {"Phantom":"35.6.81.134","SharedSecret":"bc075982d03fd5ddfcd9a14a854cd5dde4bd2180c5e4b93132964314066c5a15","Covert":"","Mask":"","Flags":{"upload_only":false,"proxy_header":true,"use_TIL":true},"Transport":1,"RegTime":"2021-12-01T18:23:15.016145664-05:00","DecoyListVersion":1153,"Source":2}
type Reg struct {
    Phantom string `json:"Phantom"`
    SharedSecret string `json:"SharedSecret"`
    // etc...
}

func main() {
    f, err := os.Open(os.Args[1])
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    gr, err := gzip.NewReader(f)
    if err != nil {
        log.Fatal(err)
    }
    defer gr.Close()

    contents := bufio.NewScanner(gr)

    cbuffer := make([]byte, 0, bufio.MaxScanTokenSize)
    contents.Buffer(cbuffer, bufio.MaxScanTokenSize*50)  // Otherwise long lines crash the scanner.


    var proc int
    phantoms := make(map[string]string) // regId => phantom
    for contents.Scan() {
        line := getMessage(contents.Text())
        if strings.Contains(line, "New registration") {
            var mdy, t string
            var regId string
            var regStr string
            _, err := fmt.Sscanf(line, "[ZMQ] %s %s New registration: %s %s",
                            &mdy, &t, &regId, &regStr)
            if err != nil {
                continue
                fmt.Printf("Err: %v for line %v\n", err, line)
            }
            var reg Reg
            err = json.Unmarshal([]byte(regStr), &reg)
            if err != nil {
                fmt.Printf("Err: %v unmarshalling %v\n", err, regStr)
            }
            //fmt.Printf("%s => %s\n", regId, reg.Phantom)
            phantoms[regId] = reg.Phantom
        } else if strings.Contains(line, "live phantom") {
            var mdy, t string
            var regId string
            _, err := fmt.Sscanf(line, "[ZMQ] %s %s Dropping registration %s -- live phantom:",
                &mdy, &t, &regId)
            if err != nil {
                fmt.Println(line)
                fmt.Println(err)
            }
            if val, ok := phantoms[regId]; ok {
                fmt.Printf("%s %s Live phantom %s\n", mdy, t, val)
            }

        }

    }
    fmt.Println(proc)
}

/*
Dec 01 18:17:30 rnd-artemis conjure[3973007]: [ZMQ] 2021/12/01 18:17:30.160543 Dropping registration 332ea3f0328a91b9 -- live phantom: phantom picked up the connection
Dec 01 18:17:31 rnd-artemis conjure[3973007]: [ZMQ] 2021/12/01 18:17:31.764430 Dropping registration 8e784df440780a36 -- live phantom: cached live host

*/
