package monitor

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func getDataFromReceivedPackets(networkInts []net.Interface, packetInfos chan PacketInfos, BFPFilter string) {
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