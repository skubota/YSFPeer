package main

// import
import "log"

// var
var Level = [5]string{"NONE", "ERROR", "WARN", "INFO", "DEBUG"}

// Log
func logging(ln int, way, str string) {
	if ln <= Loglevel {
		esc := "\x1b[0m"
		switch ln {
		case 1:
			esc = "\x1b[41m"
		case 2:
			esc = "\x1b[43m"
		case 3:
			esc = "\x1b[44m"
		case 4:
			esc = "\x1b[45m"
		}
		switch way {
		case "SEND":
			way = "\x1b[31mSEND\x1b[0m"
		case "RECV":
			way = "\x1b[32mRECV\x1b[0m"
		case "BRIDGE":
			way = "\x1b[33mBRIDGE\x1b[0m"
		case "BLOCK":
			way = "\x1b[35mBLOCK\x1b[0m"
		}
		log.Printf("%s%-6s\x1b[0m : %s %s", esc, Level[ln], way, str)
	}
}

