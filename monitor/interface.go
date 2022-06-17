package monitor

import (
	"log"
	"time"

	"github.com/dustin/go-humanize"
)

type PacketInfos struct {
  SrcAddr []byte
  DestAddr []byte
  Length uint64
  GlobalLength uint64
}

const FILTER = "tcp && port 80 or port 443"
const SAVING_TIMING = 10 * time.Second

func Start() {
  activeInterfaces := detectNetworkingActivity()

  fileDescriptor := openFile()
  defer fileDescriptor.Close()

  var packetInfos = make(chan PacketInfos)
  var lastValue string = "0 kB"
  var globalLength uint64 = 0
  var lastValueInserted uint64 = 0

  go getDataFromReceivedPackets(activeInterfaces, packetInfos, FILTER)
  // Save into a file every SAVE_TIMING seconds
  go func() {
    for {
      <-time.After(SAVING_TIMING)
      insertNewLineToFile(fileDescriptor, globalLength - lastValueInserted)
      lastValueInserted = globalLength
    }
  }()

  for {
    packetInfo, ok := <-packetInfos
    if lastValue != humanize.Bytes(packetInfo.GlobalLength){
      log.Println(humanize.Bytes(packetInfo.GlobalLength))
    } 
    lastValue = humanize.Bytes(packetInfo.GlobalLength)
    globalLength = packetInfo.GlobalLength
    if ok == false {
      log.Println("Channel close", ok)
    }
  }
}
