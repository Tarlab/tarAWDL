package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gitlab.com/jtaimisto/bluewalker/hci"
	"gitlab.com/jtaimisto/bluewalker/host"
)

const (
	// Default HCI device to use
	defaulDevice string = "hci0"
)

const (
	typeWifiJoin int = 0x0f
	typeAirdrop      = 0x05
	typeHotspot      = 0x0e
	typeNearby       = 0x10
	typeWifiSet      = 0x0d
)

var dataTypes = map[string]int{
	"wifi_join": typeWifiJoin,
	"airdrop":   typeAirdrop,
	"hotspot":   typeHotspot,
	"nearby":    typeNearby,
	"wifi_set":  typeWifiSet,
}

type params struct {
	device  string
	debug   bool
	raw     string
	ids     [4]string
	fields  [5]string
	pktType string
}

// command line paramters are read into this
var settings params

func init() {
	flag.StringVar(&settings.device, "device", defaulDevice, "HCI device to use")
	flag.BoolVar(&settings.debug, "debug", false, "Enable debug messages")
	flag.StringVar(&settings.raw, "raw", "", "Raw advertising data payload (Do not include the vendor code)")
	flag.StringVar(&settings.ids[0], "id1", "", "ID for slot 1")
	flag.StringVar(&settings.ids[1], "id2", "", "ID for slot 2")
	flag.StringVar(&settings.ids[2], "id3", "", "ID for slot 3")
	flag.StringVar(&settings.ids[3], "id4", "", "ID for slot 4")
	flag.StringVar(&settings.fields[0], "f1", "", "Data for field1")
	flag.StringVar(&settings.fields[1], "f2", "", "Data for field2")
	flag.StringVar(&settings.fields[2], "f3", "", "Data for field3")
	flag.StringVar(&settings.fields[3], "f4", "", "Data for field4")
	flag.StringVar(&settings.fields[4], "f5", "", "Data for field5")
	flag.StringVar(&settings.pktType, "type", "", "Data type to create")
}

// Create the default "flags" AD Structure we are going to send
func createDefaultFlags() *hci.AdStructure {

	return &hci.AdStructure{
		Typ:  hci.AdFlags,
		Data: []byte{0x1a},
	}
}

func parseByteArray(st string, length int) ([]byte, error) {
	st = strings.TrimSpace(st)
	if strings.HasPrefix(st, "0x") {
		st = st[2:]
	}
	bytes, err := hex.DecodeString(st)
	if err != nil {
		return nil, err
	}
	if length > 0 && length != len(bytes) {
		return nil, fmt.Errorf("Expected %d bytes, got %d", length, len(bytes))
	}
	return bytes, nil

}

// Calculate "ID hash" value for given ID.
func calculateIDHash(wr io.Writer, id string, len int) {
	if id == "" {
		// not ID, just return zeroes
		wr.Write(make([]byte, len))
	} else {
		sum := sha256.Sum256([]byte(id))
		wr.Write(sum[0:len])
	}
}

func createAppleVendorSpecific(data []byte) *hci.AdStructure {

	fullData := make([]byte, len(data)+2)
	// Start with manufacturer ID ...
	fullData[0] = 0x4c
	fullData[1] = 0x00
	// followed by the actual data
	copy(fullData[2:], data[0:])

	return &hci.AdStructure{
		Typ:  hci.AdManufacturerSpecific,
		Data: fullData,
	}

}

func createIDArray(wr io.Writer, ids [4]string, idlen int) {

	for i := 0; i < len(ids); i++ {
		calculateIDHash(wr, ids[i], idlen)
	}
}

func createTlV(typ byte, data []byte) []byte {
	result := make([]byte, len(data)+2)
	result[0] = typ
	result[1] = byte(len(data))
	copy(result[2:], data)
	return result
}

type fparam []byte

func (f fparam) or(value []byte) []byte {
	if len(f) == 0 {
		return value
	}
	return []byte(f)
}

func createWifiJoin(f1 fparam, f2 fparam, f3 fparam, ids [4]string) []byte {

	buf := bytes.Buffer{}
	buf.Write(f1.or([]byte{0x00}))             // flags
	buf.Write(f2.or([]byte{0x08}))             // type
	buf.Write(f3.or([]byte{0x00, 0x00, 0x00})) // auth tag
	createIDArray(&buf, ids, 3)                // 3 3-byte ID's
	return buf.Bytes()
}

func createAirdrop(f1 fparam, f2 fparam, end fparam, ids [4]string) []byte {

	buf := bytes.Buffer{}
	buf.Write(f1.or([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})) // leading zeroes
	buf.Write(f2.or([]byte{0x01}))                                           // st
	createIDArray(&buf, ids, 2)                                              // 4 2-byte ID's
	buf.Write(end.or([]byte{0x00}))                                          // ending zero
	return buf.Bytes()
}

func createNearby(f1 fparam, f2 fparam, f3 fparam) []byte {
	buf := bytes.Buffer{}
	buf.Write(f1.or([]byte{0x51}))     // status
	buf.Write(f2.or([]byte{0x1e}))     // wifi state
	buf.Write(f3.or([]byte{0x000000})) // data
	return buf.Bytes()
}

func createHotspot(f1 fparam, f2 fparam, f3 fparam, f4 fparam, f5 fparam) []byte {
	buf := bytes.Buffer{}

	buf.Write(f1.or([]byte{0x01, 0x00})) // data1
	buf.Write(f2.or([]byte{0x64}))       // battery
	buf.Write(f3.or([]byte{0x00}))       // data2
	buf.Write(f4.or([]byte{0x06}))       // Cell srv
	buf.Write(f5.or([]byte{0x04}))       // Cell bars
	return buf.Bytes()
}

func createWifiSet(f1 fparam) []byte {

	buf := bytes.Buffer{}
	buf.Write(f1.or([]byte{0x00, 0x00, 0x00, 0x00})) // IcloudID?
	return buf.Bytes()
}

func expandParams(params []string) []fparam {

	var ret = make([]fparam, len(params))
	for i, param := range params {
		if param == "" {
			// valid, indicate with empty array, no nils
			ret[i] = make([]byte, 0)
		} else {
			var err error
			if ret[i], err = parseByteArray(param, -1); err != nil {
				fmt.Printf("Error: Invalid data for paramater %d (%v)", i+1, err)
				os.Exit(255)
			}
		}
	}
	return ret
}

func createPayload(p *params) []byte {
	var payload []byte
	if p.raw != "" {
		var err error
		payload, err = parseByteArray(p.raw, 0)
		if err != nil {
			fmt.Printf("Error: Invalid raw data: %v \n", err)
			os.Exit(255)
		}
	} else {

		t, f := dataTypes[p.pktType]
		if !f {
			fmt.Printf("Error: Invalid packet type %s\n", p.pktType)
			os.Exit(255)
		}

		var data []byte
		switch t {
		case typeWifiJoin:
			plist := expandParams(p.fields[0:3])
			data = createWifiJoin(plist[0], plist[1], plist[2], p.ids)
		case typeAirdrop:
			plist := expandParams(p.fields[0:3])
			data = createAirdrop(plist[0], plist[1], plist[2], p.ids)
		case typeNearby:
			plist := expandParams(p.fields[0:3])
			data = createNearby(plist[0], plist[1], plist[2])
		case typeHotspot:
			plist := expandParams(p.fields[0:5])
			data = createHotspot(plist[0], plist[1], plist[2], plist[3], plist[4])
		case typeWifiSet:
			plist := expandParams(p.fields[0:1])
			data = createWifiSet(plist[0])
		default:
			fmt.Printf("Error: unsupported packet type %s\n", p.pktType)
			os.Exit(255)
		}
		payload = createTlV(byte(t), data)
	}
	return payload
}

func main() {

	flag.Parse()

	if !settings.debug {
		log.SetOutput(ioutil.Discard)
	}

	payload := createPayload(&settings)
	flags := createDefaultFlags()
	vendor := createAppleVendorSpecific(payload)

	fmt.Printf("Created AdStructures:\n")
	fmt.Printf("\t%s\n", flags.String())
	fmt.Printf("\t%s\n", vendor.String())

	trp, err := hci.Raw(settings.device)
	if err != nil {
		fmt.Printf("Error: Can not open %s : %v\n", settings.device, err)
		os.Exit(255)
	}
	h := host.New(trp)
	if err := h.Init(); err != nil {
		fmt.Printf("Error: Can not initialize host: %v\n", err)
		os.Exit(255)
	}

	defer h.Deinit()

	params := hci.DefaultAdvParameters()
	params.IntervalMin = 0x0200
	params.IntervalMax = 0x0400
	params.Type = hci.AdvInd
	params.ChannelMap = hci.AdvChannelAll

	if err := h.SetAdvertisingParams(params); err != nil {
		fmt.Printf("Error: Can not set Advertising Params: %v\n", err)
		os.Exit(255)
	}

	if err := h.SetAdvertisingData([]*hci.AdStructure{flags, vendor}); err != nil {
		fmt.Printf("Error: Can not send Advertising Data: %v\n", err)
		os.Exit(255)
	}

	if err := h.StartAdvertising(); err != nil {
		fmt.Printf("Error: Can not start Advertising: %v\n", err)
		os.Exit(255)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sig:

	}
	fmt.Printf("Stopping ...\n")
	h.StopAdvertising()
}
