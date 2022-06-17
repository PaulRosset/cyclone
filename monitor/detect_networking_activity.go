package monitor

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const TIMEOUT_WAIT_PACKET = 2 * time.Second

/*
	Open a stream of incoming and outgoing packet under a filter.
	Then, wait for the stream to transmit data under TIMEOUT_WAIT_PACKET, if the stream is not
	sending data under TIMEOUT_WAIT_PACKET, consider it unactive. 
*/
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
	  go func() {
		time.Sleep(TIMEOUT_WAIT_PACKET)
  		hasBeenPicked <-false
	  }()
	  go func() {
		for range packetSource.Packets() {
			hasBeenPicked <-true
		}
	  }()
	  
	  isActive := <-hasBeenPicked
	  return isActive
	}
}

/*
	Try to detect network activity on the current devices by looking at Network Interfaces
	return a list of network interface that are actives.
*/
func detectNetworkingActivity() []net.Interface {
	var detectPacketActivityGrp sync.WaitGroup
	var deviceScanned int
	var activeInterfaces []net.Interface
  
	interfaces, err := net.Interfaces()
	if err != nil {
	  log.Println(err)
	}

	for _, networkInt := range interfaces {
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

	log.Println("Device scanned:", deviceScanned, "/", len(interfaces))
	log.Println("Device Actives:", len(activeInterfaces), "/", len(interfaces))

	return activeInterfaces
}