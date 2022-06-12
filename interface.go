package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketInfos struct {
  SrcAddr []byte
  DestAddr []byte
  Length uint64
  GlobalLength uint64
}

const FILTER = "tcp && port 80 or port 443"

func timeout(hasBeenPicked chan bool) {
  time.Sleep(2 * time.Second)
  hasBeenPicked <-false
}

func getPackets(packetSource *gopacket.PacketSource, hasBeenPicked chan bool, interfaceName string) {
  for range packetSource.Packets() {
   hasBeenPicked <-true
  }
}

func openFile() *os.File {
  f, err := os.OpenFile("/tmp/cyclone", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
  if err != nil {
	  log.Println(err)
  }
  return f
}

func openPacketSource(interfaceName string, BFPFilter string) bool {
  hasBeenPicked := make(chan bool)
  if handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever); err != nil {
    log.Println(err)
    return false;
  } else if err := handle.SetBPFFilter(BFPFilter); err != nil {
    log.Println(err)
    return false
  }else {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    go timeout(hasBeenPicked)
    go getPackets(packetSource, hasBeenPicked, interfaceName)
    
    isActive := <-hasBeenPicked
    return isActive
  }
}

func updateLocalFile(fileDescriptor *os.File, dataToInsert uint64) {
  now := time.Now()
  formattedDate := fmt.Sprintf("%d/%d/%d %d:%d:%d",
		now.Year(),
		now.Month(),
		now.Day(),
		now.Hour(),
		now.Hour(),
		now.Second())
  if _, err := fileDescriptor.WriteString(formattedDate + " " + strconv.FormatUint(dataToInsert, 10) + "\n"); err != nil {
    log.Println(err)
  }
  log.Println("Writting to file")
}

func main() {
  var detectPacketActivityGrp sync.WaitGroup
  var deviceScanned int
  var activeInterfaces []net.Interface

  ints, err := net.Interfaces()
  if err != nil {
    fmt.Println(err)
  }
  for _, networkInt := range ints {
    detectPacketActivityGrp.Add(1)

    networkInt := networkInt

    go func() {
      log.Println("Testing interface ", networkInt.Name, "...")
      defer detectPacketActivityGrp.Done()
      isActive := openPacketSource(networkInt.Name, FILTER)
      deviceScanned += 1
      if isActive {
        activeInterfaces = append(activeInterfaces, networkInt)
      }
      log.Println("RESULT:", networkInt.Name, isActive)
    }()
  }
  detectPacketActivityGrp.Wait()
  log.Println("Device scanned:", deviceScanned, "/", len(ints))
  log.Println("Device Actives:", len(activeInterfaces), "/", len(ints))


  fileDescriptor := openFile()
  defer fileDescriptor.Close()
  var packetInfos = make(chan PacketInfos)
  var lastValue string = "0 kB"
  var globalLength uint64 = 0
  var lastValueInserted uint64 = 0
  go GetPacketsUnderMonitoring(activeInterfaces, packetInfos, FILTER)
  go func() {
    for {
      <-time.After(10 * time.Second)
      updateLocalFile(fileDescriptor, globalLength - lastValueInserted)
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
    // var srcAddrFormated [4]string;
		// // var destAddrFormated [4]string;
		// for i, data := range packetInfo.SrcAddr {
		// 	srcAddrFormated[i] = strconv.Itoa(int(data))
		// }
		// srcNets, err := net.LookupAddr(strings.Join(srcAddrFormated[:], "."))
		// if err != nil {
		// 	log.Println(err)
		// }
		// fmt.Println(srcNets)
		// for i, data := range destAddr {
		// 	destAddrFormated[i] = strconv.Itoa(int(data))
		// }
		// destNets, err := net.LookupAddr(strings.Join(destAddrFormated[:], "."))
		// if err != nil {
		// 	log.Println(err)
		// }
		// fmt.Println("Src address:", srcNets)
		// fmt.Println("Destination address:", destNets)
  }
}
