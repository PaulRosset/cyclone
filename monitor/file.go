package monitor

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

/*
	Insert a string line in the given file descriptor in parameter, under the following format:
	- YYYY/MM/DD HH:MM:SS [data]
*/
func insertNewLineToFile(fileDescriptor *os.File, dataToInsert uint64) {
	now := time.Now()
	formattedDate := fmt.Sprintf("%d/%d/%d %d:%d:%d",
		  now.Year(),
		  now.Month(),
		  now.Day(),
		  now.Hour(),
		  now.Minute(),
		  now.Second())
	if _, err := fileDescriptor.WriteString(formattedDate + " " + strconv.FormatUint(dataToInsert, 10) + "\n"); err != nil {
	  log.Println(err)
	}
	log.Println("Writting to file...")
}


/*
  Open a file name located in /tmp/cyclone and return a file descriptor.
*/
func openFile() *os.File {
	fd, err := os.OpenFile("/tmp/cyclone", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	return fd
}