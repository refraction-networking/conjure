package main

import (
    zmq "github.com/pebbe/zmq4"
    "encoding/hex"
    "log"
    "os"
    "time"
    "flag"
)

func main() {

    var addr string
    var sub bool
    var bind bool
    var sleep int
    var timeout int
    flag.StringVar(&addr, "addr", "ipc://@zmq-proxy", "Address of ZMQ proxy")
    flag.BoolVar(&sub, "sub", false, "don't forget to like and SUBSCRIBE")
    flag.BoolVar(&bind, "bind", false, "If we should bind (otherwise we connect)")
    flag.IntVar(&sleep, "sleep", 1000, "Milliseconds we should sleep between sends")
    flag.IntVar(&timeout, "timeout", 0, "Milliseconds we should timeout/send heartbeats")
    flag.Parse()

    logger := log.New(os.Stdout, "[ZMQ-DEBUG]", log.Ldate|log.Lmicroseconds)
    pubsub := zmq.PUB
    if sub {
        pubsub = zmq.SUB
    }
    sock, err := zmq.NewSocket(pubsub)
    if err != nil {
        logger.Printf("can't create socket: %v\n", err)
        return
    }
    defer sock.Close()


    err = sock.SetHeartbeatTimeout(time.Duration(timeout)*time.Millisecond)
    if err != nil {
        logger.Printf("can't set hearbeat: %v\n", err)
    }

    sock.SetHeartbeatIvl(time.Duration(timeout)*time.Millisecond)
    if err != nil {
        logger.Printf("can't set interval: %v\n", err)
    }

    if bind {
        logger.Printf("Binding to %s\n", addr)
        err = sock.Bind(addr)
    } else {
        logger.Printf("Connecting to %s\n", addr)
        err = sock.Connect(addr)
    }
    if err != nil {
        logger.Printf("can't Bind/connect: %v\n", err)
        return
    }

    if sub {
        logger.Printf("subscribing...")
        sock.SetSubscribe("")
        for {
            msg, err := sock.RecvBytes(0)
            if err != nil {
                logger.Printf("error reading from socket: %v\n", err)
                return
            }
            logger.Printf("Got %d bytes: %s\n", len(msg), hex.EncodeToString(msg))
        }
    } else {
        msg_hx := "0a209caf15b7092507f20b4dfe7059a2af9f599f20da5aec1f3e86901bb89fa924261a2c10df086001a2011033312e32342e3232342e32383a343433b00101b80101c20106080018012001a20602000020013204057e022f3a042308981c"

        msg, _ := hex.DecodeString(msg_hx)
        i := 0
        for {
            n, err := sock.SendBytes(msg, 0)
            if err != nil {
                logger.Printf("Error sending: %v\n", err)
                return
            }
            logger.Printf("(%d) Sent %d bytes\n", i, n)
            time.Sleep(time.Duration(sleep)*time.Millisecond)
            i += 1

        }
    }
}
