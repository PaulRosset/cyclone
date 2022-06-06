package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func GetPacketsUnderMonitoring(networkInts []net.Interface, packetInfos chan PacketInfos, BFPFilter string) {
	var packetCapturedLength uint64 = 0
	if len(networkInts) != 1 {
			panic("Multiple or no active interface have been found, where only one can be monitored.")
	}
		
	networkInt := networkInts[0]

  if handle, err := pcap.OpenLive(networkInt.Name, 1600, true, pcap.BlockForever); err != nil {
    log.Println(err)
  } else {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
		packetLength := uint64(packet.Metadata().Length)
		packetData := packet.Data()
		srcAddr := packetData[26:30]
		destAddr := packetData[30:34]
		packetCapturedLength += packetLength
		packetInfosData := PacketInfos{
			SrcAddr: srcAddr,
			DestAddr: destAddr,
			Length: uint64(packet.Metadata().Length),
			GlobalLength: packetCapturedLength,
		}
		packetInfos <- packetInfosData
	}
  }
}


// 68 2f 67 91 52 7e 00 10  db ff 10 02 08 00 45 00
// 00 3c 00 00 40 00 f1 06  ea c7 34 49 36 4c 0a 01
// 2a 5e 01 bb dc cd 87 7b  9e e4 40 f4 5b b2 a0 12
// 68 df 2a 8d 00 00 02 04  05 b4 04 02 08 0a 6e 36
// 19 92 eb 1c 01 1a 01 03  03 08

// Result IP target => 52.73.54.76


// 34 49 36 4C => Hexa => base 16
// 52 73 54 76  => Decimal => base 10