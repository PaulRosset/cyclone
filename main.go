package main

import (
	"log"

	"github.com/PaulRosset/cyclone/monitor"
)

func main() {
	log.Println("Starting monitoring...")
	monitor.Start()
}