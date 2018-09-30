package main

// import
import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	yml "gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// struct
type yaml struct {
	Peer      []peer    `yaml:"Peer"`
	Reflector reflector `yaml:"Reflector"`
	My        my        `yaml:"My"`
	Log       logs      `yaml:"Log"`
}

type peer struct {
	BSN  string `yaml:"BSN"`
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	Pass string `yaml:"name"`
}

type my struct {
	BSN  string `yaml:"BSN"`
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	Pass string `yaml:"name"`
}

type reflector struct {
	BSN  string `yaml:"BSN"`
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	Name string `yaml:"name"`
}

type logs struct {
	Loglevel int `yaml:"level"`
}

// var
var Version string
var instanceYaml *yaml
var Loglevel int = 3
var Hash [256]string
var Num int = 0

// IDLE,OPEN,ESTABLISHED,CLOSED
var PeerState = make(map[string]string, 256)
var PeerAlive = make(map[string]int, 256)

// Yaml
func Yaml(c string) *yaml {
	initializeYaml(c)
	return instanceYaml
}

func initializeYaml(c string) {
	buf, err := ioutil.ReadFile(c)
	if err != nil {
		log.Fatalln(err)
	}
	instanceYaml = &yaml{}
	err = yml.Unmarshal(buf, instanceYaml)
	if err != nil {
		log.Fatalln(err)
	}
}

// BS
func format_bsn(bsn string) (ret string) {
	if len(bsn) > 3 {
		ret = strings.ToUpper(fmt.Sprintf("%04s", bsn[0:4]))
		if len(ret) != 4 {
			log.Fatalln("BSN wrong format", bsn)
		}
	} else {
		log.Fatalln("BS Format error", len(bsn))
	}
	return ret
}

// for reflector
func ref_polling(conn *net.UDPConn, my_bsn, callsign string) {
	for {
		n, err := conn.Write([]byte(fmt.Sprintf("YSFP%-10s", callsign)))
		if err != nil {
			logging(1, "Reflector", fmt.Sprintf("BS%s CLOSED %s (POLLING) %d", my_bsn, err, n))
			PeerState[my_bsn] = "CLOSED"
			log.Fatalln(err, n)
		}
		logging(4, "SEND", fmt.Sprintf("Reflector [%s%-10s]", "YSFP", callsign))
		time.Sleep(REFLECTOR_POLLING_INTERVAL * time.Second)
	}
}

func ref_reader(conn *net.UDPConn, BSN string, back_lane map[string](chan []byte)) {
	for {
		// Read
		recvBuf := make([]byte, 384)
		n, addr, err := conn.ReadFromUDP(recvBuf)
		if err != nil {
			logging(1, "Reflector", fmt.Sprintf("BS%s CLOSED %s (READ) %s %d", BSN, addr.String(), err, n))
			PeerState[BSN] = "CLOSED"
			log.Fatalln(err)
		}
		data_b := recvBuf[:n]
		data_s := string(data_b)
		skip := 0
		// YSFD
		if strings.HasPrefix(data_s, "YSFD") {
			now_hash := fmt.Sprintf("%x", md5.Sum(data_b))
			logging(4, "Reflector", fmt.Sprintf("BS%s RECV YSFD %d", BSN, len(data_s)))

			// HASH
			for i := 0; i < len(Hash); i++ {
				if Hash[i] == now_hash {
					logging(4, "BLOCK", fmt.Sprintf("Reflector %d:[%s]", i, now_hash))
					skip++
					break
				}
			}
			// Bridge
			if skip == 0 {
				Hash[Num] = now_hash
				if Num == 255 {
					Num = 0
				} else {
					Num++
				}
				for peer_bsn := range PeerState {
					if PeerState[peer_bsn] == "ESTABLISHED" {
						if peer_bsn != BSN {
							pkt := []byte(fmt.Sprintf("BD%02X%sFFFF%s", DEFAULT_TTL, BSN, data_b))
							back_lane[peer_bsn] <- pkt
							logging(4, "BRIDGE", fmt.Sprintf("Reflector BS%s -> Peer BS%s send channel done %d", BSN, peer_bsn, len(data_s)))
						}
					}
				}
			}
			// Other
		} else {
			logging(4, "RECV", fmt.Sprintf("Reflector [%s]", data_s))
		}
	}
}

func ref_writer(conn *net.UDPConn, my_bsn string, back_lane chan []byte) {
	for {
		// Send
		send_buf := <-back_lane
		if len(send_buf) > 0 {
			n, err := conn.Write(send_buf)
			if err != nil {
				log.Fatalln(err)
			}
			logging(4, "SEND", fmt.Sprintf("Reflector (%d)", n))
			logging(4, "hex\n", hex.Dump(send_buf))
		}
	}
}

func ref_connect(config string, back_lane map[string](chan []byte)) {
	// init
	y := Yaml(config)
	my_bsn := format_bsn(y.My.BSN)
	host := y.Reflector.Host
	port := y.Reflector.Port
	name := y.Reflector.Name

	// connection
	udpAddr, err := net.ResolveUDPAddr("udp", host+":"+port)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatalln(err)
	}

	// polling
	PeerState[my_bsn] = "ESTABLISHED"
	logging(3, "Reflector", fmt.Sprintf("BS%s ESTABLISHED %-10s (%s:%s)", my_bsn, name, host, port))
	go ref_polling(conn, my_bsn, name)
	go ref_reader(conn, my_bsn, back_lane)
	go ref_writer(conn, my_bsn, back_lane[my_bsn])

}

// for peers
func peer_listner(conf *yaml, back_lane map[string](chan []byte)) {

	my_bsn := format_bsn(conf.My.BSN)

	addr_table := make(map[string]string)
	passes := make(map[string][]byte)
	for n := range conf.Peer {
		passes[conf.Peer[n].BSN] = []byte(conf.Peer[n].Pass)
	}

	service := ":" + conf.My.Port
	udpAddr, err := net.ResolveUDPAddr("udp", service)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}

	logging(3, "Server", fmt.Sprintf("BS%s Listen start port:%s", my_bsn, conf.My.Port))

	for {
		listner_client(my_bsn, conn, addr_table, passes, back_lane)
	}
}

func listner_client(my_bsn string, conn *net.UDPConn, addr_table map[string]string, passes map[string][]byte, back_lane map[string](chan []byte)) {
	buf := make([]byte, 1024)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return
	}
	data_b := buf[:n]
	data_s := string(data_b)
	if strings.HasPrefix(data_s, "BC") {
		if len(data_s) > 43 {
			ttl := data_b[2:4]
			from := string(data_b[4:8])
			to := string(data_b[8:12])
			pass_hash := fmt.Sprintf("%x", md5.Sum(passes[from]))

			if pass_hash == string(data_b[12:44]) && my_bsn == to && PeerState[from] == "CLOSED" {
				conn.WriteTo([]byte(fmt.Sprintf("BC01%s%s%s", to, from, pass_hash)), addr)
				PeerState[from] = "ESTABLISHED"
				PeerAlive[from] = PEER_KEEPALIVE
				addr_table[addr.String()] = from
				logging(3, "Peer", fmt.Sprintf("BS%s ESTABLISHED(LISTEN) %s %s %s.", from, ttl, to, addr))
				// peer routine
				go peer_polling(conn, my_bsn, from, addr)
				time.Sleep(3 * time.Second)
				go peer_writer(conn, from, back_lane[from], addr)
			} else {
				logging(4, "Peer", fmt.Sprintf("BS%s missmatch(LISTEN).", from))
				conn.WriteTo([]byte(fmt.Sprintf("BU01%s%s", to, from)), addr)
			}
		}
	} else {
		if len(data_s) > 11 {
			from := string(data_b[4:8])
			if from == addr_table[addr.String()] {
				read_packet(data_b, my_bsn, from, back_lane)
			} else {
				logging(4, "Peer", fmt.Sprintf("BS%s != %s wrong BSN %s (LISTEN).", from, addr_table[addr.String()], addr.String()))
			}
		}
	}

}

func peer_watcher(my_bsn string, p peer, back_lane map[string](chan []byte)) {
	var c int = 0
	for {
		// sleep
		time.Sleep(PEER_WATCHER_INTERVAL * time.Second)
		// format
		peer_bsn := format_bsn(p.BSN)
		// decrement keepalive
		PeerAlive[peer_bsn]--

		// close -> reconnect
		if PeerState[peer_bsn] == "CLOSED" {
			logging(2, "Peer", fmt.Sprintf("BS%s RECONNECT by watcher", peer_bsn))
			PeerState[peer_bsn] = "IDLE"
			go peer_connect(my_bsn, p, back_lane)

			// open or idle
		} else if PeerState[peer_bsn] != "CLOSED" && PeerState[peer_bsn] != "ESTABLISHED" && c > 1 {
			PeerState[peer_bsn] = "CLOSED"
			logging(2, "Peer", fmt.Sprintf("BS%s CLOSED by watcher", peer_bsn))
			c = 0

			// logging
		} else {
			logging(4, "Peer", fmt.Sprintf("BS%s %s (keepalive:%d) by watcher", peer_bsn, PeerState[peer_bsn], PeerAlive[peer_bsn]))
			if PeerState[peer_bsn] != "ESTABLISHED" {
				c++
			}
		}
		// keepalive close
		if PeerAlive[peer_bsn] <= 0 {
			PeerState[peer_bsn] = "CLOSED"
			logging(2, "Peer", fmt.Sprintf("BS%s CLOSED no keepalive by watcher", peer_bsn))
			c = 0
		}
	}
}

// keepalive polling
func peer_polling(conn *net.UDPConn, my_bsn, peer_bsn string, addr net.Addr) {
	for {
		if PeerState[peer_bsn] == "ESTABLISHED" {
			var err error
			if addr != nil {
				// from listner
				_, err = conn.WriteTo([]byte(fmt.Sprintf("BP01%s%s", my_bsn, peer_bsn)), addr)
			} else {
				// fro client
				_, err = conn.Write([]byte(fmt.Sprintf("BP01%s%s", my_bsn, peer_bsn)))
			}
			if err != nil {
				logging(1, "Peer", fmt.Sprintf("BS%s CLOSED (POLLING) %s", peer_bsn, err))
				PeerState[peer_bsn] = "CLOSED"
				return
			}
			logging(4, "SEND", fmt.Sprintf("Peer BS%s [%s01%s%s]", peer_bsn, "BP", my_bsn, peer_bsn))
			time.Sleep(PEER_POLLING_INTERVAL * time.Second)
		}
	}
}

// reader
func peer_reader(conn *net.UDPConn, my_bsn, peer_bsn string, back_lane map[string](chan []byte)) {
	for {
		// Read
		if PeerState[peer_bsn] == "ESTABLISHED" {
			recvBuf := make([]byte, 384)
			n, addr, err := conn.ReadFromUDP(recvBuf)
			if err != nil {
				logging(1, "Peer", fmt.Sprintf("BS%s CLOSED (READ) %s %s %d", peer_bsn, err, addr.String(), n))
				PeerState[peer_bsn] = "CLOSED"
				return
			}
			read_packet(recvBuf[:n], my_bsn, peer_bsn, back_lane)
		}
	}
}

// read packet
func read_packet(data_b []byte, my_bsn, peer_bsn string, back_lane map[string](chan []byte)) {
	data_s := string(data_b)
	skip := 0
	// Peer Packet
	if len(data_s) > 11 {
		ttl := data_b[2:4]
		from := data_b[4:8]
		to := data_b[8:12]

		// Data
		if strings.HasPrefix(data_s, "BD") {
			payload := data_b[12:]
			now_hash := fmt.Sprintf("%x", md5.Sum(payload))

			// HASH
			for i := 0; i < 255; i++ {
				if Hash[i] == now_hash {
					logging(4, "BLOCK", fmt.Sprintf("Peer %d:[%s]", i, now_hash))
					skip++
					break
				}
			}
			// Bridge
			if skip == 0 {
				Hash[Num] = now_hash
				if Num == 255 {
					Num = 0
				} else {
					Num++
				}
				for p := range PeerState {
					if p == my_bsn {
						// Peer to Reflector without Bridge header(payload)
						back_lane[my_bsn] <- payload
						logging(4, "BRIDGE", fmt.Sprintf("Peer BS%s -> Reflector BS%s send channel done %d", peer_bsn, my_bsn, len(data_s)))
					} else if p != string(from) {
						// Peer to Peer and split horizon with Bridge header(data_b)
						if PeerState[p] == "ESTABLISHED" && p != peer_bsn {
							back_lane[p] <- data_b
							logging(4, "BRIDGE", fmt.Sprintf("Peer BS%s -> Peer BS%s send channel done %d", peer_bsn, p, len(data_s)))
						}
					}
				}
			}
		} else if strings.HasPrefix(data_s, "BP") {
			if string(from) == peer_bsn && PeerState[peer_bsn] == "ESTABLISHED" {
				PeerAlive[peer_bsn] = PEER_KEEPALIVE
			}
		} else if strings.HasPrefix(data_s, "BU") {
			if string(from) == peer_bsn && PeerState[peer_bsn] == "ESTABLISHED" {

				back_lane[peer_bsn] <- []byte(fmt.Sprintf("BU01%s%s", my_bsn, peer_bsn))
				logging(3, "Peer", fmt.Sprintf("BS%s CLOSED (UNLINK)", peer_bsn))
				PeerState[peer_bsn] = "CLOSED"
				return
			} else {
				logging(4, "RECV", fmt.Sprintf("Peer BS%s Unkown BU [%s]", peer_bsn, data_s))
			}

		} else {
			// Other
			logging(4, "RECV", fmt.Sprintf("Peer BS=%s,ttl=%s,from=%s,to=%s [%s]", peer_bsn, ttl, from, to, data_s))
		}
	} else {
		logging(4, "RECV", fmt.Sprintf("Peer BS%s msg too small.(%d)", peer_bsn, len(data_s)))
	}
}

func peer_writer(conn *net.UDPConn, peer_bsn string, back_lane chan []byte, addr net.Addr) {
	for {
		send_buf := <-back_lane
		data_s := string(send_buf)
		if PeerState[peer_bsn] == "ESTABLISHED" || (PeerState[peer_bsn] == "CLOSED" && strings.HasPrefix(data_s, "BU")) {
			ttl, _ := strconv.ParseUint(string(send_buf[2:4]), 16, 0)
			ttl--
			if ttl > 0 {
				var err error
				if addr != nil {
					// from listner
					_, err = conn.WriteTo(send_buf, addr)
				} else {
					// from client
					_, err = conn.Write(send_buf)
				}
				if err != nil {
					logging(1, "Peer", fmt.Sprintf("BS%s UNLINK/CLOSED (WRITE) %s", peer_bsn, err))
					PeerState[peer_bsn] = "CLOSED"
					return
				}
				logging(4, "SEND", fmt.Sprintf("Peer BS%s", peer_bsn))
				logging(4, "hex\n", hex.Dump(send_buf))
			}
		}
	}
}

func peer_connect(my_bsn string, p peer, back_lane map[string](chan []byte)) {
	peer_bsn := format_bsn(p.BSN)
	host := p.Host
	port := p.Port
	pass := []byte(p.Pass)
	pass_hash := fmt.Sprintf("%x", md5.Sum(pass))
	// connection
	udpAddr, err := net.ResolveUDPAddr("udp", host+":"+port)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logging(1, "Peer", fmt.Sprintf("BS%s %s by peer_connect", peer_bsn, err))
		return
	}
	logging(3, "Peer", fmt.Sprintf("BS%s OPEN (%s:%s)", peer_bsn, host, port))
	PeerState[peer_bsn] = "OPEN"

	// Send BC
	buf := fmt.Sprintf("BC01%s%s%s", my_bsn, peer_bsn, pass_hash)
	n, err := conn.Write([]byte(buf))
	if err != nil {
		logging(1, "Peer", fmt.Sprintf("BS%s %s(%d) by peer_connect", peer_bsn, err, n))
		return
	}
	for {
		recvBuf := make([]byte, 384)
		n, addr, err := conn.ReadFromUDP(recvBuf)
		if err != nil {
			logging(1, "Peer", fmt.Sprintf("BS%s %s %s by peer_connect", peer_bsn, err, addr.String()))
			PeerState[peer_bsn] = "CLOSED"
			return
		}
		data_b := recvBuf[:n]
		data_s := string(data_b)
		str := fmt.Sprintf("BC01%s", peer_bsn)
		if strings.HasPrefix(data_s, str) {
			if len(data_s) > 43 {
				if pass_hash == string(data_b[12:44]) {
					PeerState[peer_bsn] = "ESTABLISHED"
					PeerAlive[peer_bsn] = PEER_KEEPALIVE
					logging(3, "Peer", fmt.Sprintf("BS%s ESTABLISHED.", peer_bsn))
					break
				} else {
					logging(4, "Peer", fmt.Sprintf("BS%s password mis match.", peer_bsn))
					return
				}
			}
		}
	}

	// peer routine
	go peer_polling(conn, my_bsn, peer_bsn, nil)
	go peer_reader(conn, my_bsn, peer_bsn, back_lane)
	time.Sleep(3 * time.Second)
	go peer_writer(conn, peer_bsn, back_lane[peer_bsn], nil)
}

// main
func main() {

	// Flag
	c := flag.String("c", "YSFPeer.yml", "Config file")
	debug := flag.Bool("d", false, "Debug flag")
	pprof := flag.Bool("p", false, "enable pprof flag")
	pprof_serve := flag.String("s", "localhost:6060", "pprof serve host:port")
	flag.Parse()

	// pprof
	if *pprof {
		go func() {
			logging(3, "pprof", fmt.Sprintf("pprof serve %s", *pprof_serve))
			http.ListenAndServe(*pprof_serve, nil)
		}()
	}

	// START
	if *debug {
		Loglevel = 4
	} else if Yaml(*c).Log.Loglevel > 0 {
		Loglevel = Yaml(*c).Log.Loglevel
	}
	my_bsn := format_bsn(Yaml(*c).My.BSN)

	logging(3, "Start", fmt.Sprintf("YSFPeer Ver:%s , BS%s , Loglevel= %d:%s", Version, my_bsn, Loglevel, Level[Loglevel]))

	// create channel
	back_lane := make(map[string](chan []byte), 384)

	// Bridge
	back_lane[my_bsn] = make(chan []byte, 384)
	PeerState[my_bsn] = "IDLE"
	go ref_connect(*c, back_lane)

	// Peers
	for n := range Yaml(*c).Peer {
		peer_bsn := format_bsn(Yaml(*c).Peer[n].BSN)
		back_lane[peer_bsn] = make(chan []byte, 384)
		PeerState[peer_bsn] = "IDLE"
		go peer_connect(my_bsn, Yaml(*c).Peer[n], back_lane)
		go peer_watcher(my_bsn, Yaml(*c).Peer[n], back_lane)
	}
	go peer_listner(Yaml(*c), back_lane)

	// Signal handle
	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan,
		syscall.SIGUSR1,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)

	exit_chan := make(chan int)
	for {
		s := <-signal_chan
		switch s {
		case syscall.SIGUSR1:
			// killall YSFPeer -s SIGUSR1
			logging(3, "SIGUSR1", "-----------------------------")
			for p := range PeerState {
				if p == my_bsn {
					logging(3, "SIGUSR1", fmt.Sprintf("Reflector BS%s %s", p, PeerState[p]))
				} else {
					logging(3, "SIGUSR1", fmt.Sprintf("Peer      BS%s %s", p, PeerState[p]))
				}
			}
			logging(3, "SIGUSR1", "-----------------------------")

		case syscall.SIGINT:
			logging(3, "Stop", "YSFPeer SIGINT")
			os.Exit(0)

		case syscall.SIGTERM:
			logging(3, "Stop", "YSFPeer SIGTERM")
			os.Exit(0)

		default:
			exit_chan <- 1
		}
	}
}
