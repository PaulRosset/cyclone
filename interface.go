package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func timeout(hasBeenPicked chan bool) {
  time.Sleep(2 * time.Second)
  hasBeenPicked <-false
}

func getPackets(packetSource *gopacket.PacketSource, hasBeenPicked chan bool, interfaceName string) {
  for range packetSource.Packets() {
   hasBeenPicked <-true
  }
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
      isActive := openPacketSource(networkInt.Name, "tcp && port 80 or port 443")
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

  GetPacketsUnderMonitoring(activeInterfaces, "tcp && port 80 or port 443")
}
