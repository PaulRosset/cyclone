package main

import (
	"log"
	"net"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Header struct {
	UserDataMaxSize uint32
	HeaderOffset uint32
	UserDataSize uint32
	_ [5]byte
	Starcraft2 [22]byte
}

func ByteCounter(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func GetPacketsUnderMonitoring(networkInts []net.Interface, BFPFilter string) {
	var packetCapturedLength int64 = 0
	if len(networkInts) != 1 {
		panic("Multiple or no active interface have been found, where only one can be monitored.")
	}

	networkInt := networkInts[0]

  if handle, err := pcap.OpenLive(networkInt.Name, 1600, true, pcap.BlockForever); err != nil {
    log.Println(err)
  } else if err := handle.SetBPFFilter(BFPFilter); err != nil {
    log.Println(err)
  } else {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
		packetCapturedLength += int64(packet.Metadata().Length)
		log.Println(ByteCounter(packetCapturedLength))
	}
  }
}
