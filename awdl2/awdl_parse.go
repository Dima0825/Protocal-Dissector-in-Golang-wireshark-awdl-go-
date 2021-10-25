package awdl2

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	AWDL_SSTH_REQUEST_TLV uint8 = iota
	AWDL_SERVICE_REQUEST_TLV
	AWDL_SERVICE_RESPONSE_TLV
	AWDL_UNKNOWN_3_TLV
	AWDL_SYNCHRONIZATON_PARAMETERS_TLV
	AWDL_ELECTION_PARAMETERS_TLV
	AWDL_SERVICE_PARAMETERS_TLV
	AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV
	AWDL_ENHANCED_DATA_RATE_OPERATION_TLV
	AWDL_INFRA_TLV
	AWDL_INVITE_TLV
	AWDL_DBG_STRING_TLV
	AWDL_DATA_PATH_STATE_TLV
	AWDL_ENCAPSULATED_IP_TLV
	AWDL_DATAPATH_DEBUG_PACKET_LIVE_TLV
	AWDL_DATAPATH_DEBUG_AF_LIVE_TLV
	AWDL_ARPA_TLV
	AWDL_IEEE80211_CONTAINER_TLV
	AWDL_CHAN_SEQ_TLV
	AWDL_UNKNOWN_19_TLV
	AWDL_SYNCHRONIZATION_TREE_TLV
	AWDL_VERSION_TLV
	AWDL_BLOOM_FILTER_TLV
	AWDL_NAN_SYNC_TLV
	AWDL_ELECTION_PARAMETERS_V2_TLV
)

type Channel struct {
	Flag   uint8
	Number uint8
}
type Synchronization struct {
	NewAwChannel                    uint8
	TxCounter                       uint16
	MasterChannel                   uint8
	GuardTime                       uint8
	AvailabilityWindowPeriod        uint16
	ActionFrame                     uint16
	AwdlFlags                       uint16
	AvailabilityWindowExtLen        uint16
	AvailabilityWindowCommonLen     uint16
	RemainingAvailabilityWindowlen  uint16
	MinExtensionCount               uint8
	MaxExtensionCountForMulticast   uint8
	MaxExtensionCountForUnicast     uint8
	MaxExtensionCountForActionFrame uint8
	MasterAddress                   [6]byte
	PresenceMode                    uint8
	Unknown                         uint8
	AwSequenceNum                   uint16
	ApBeaconAlignmentDelta          uint16
	NumChannels                     uint8
	Encoding                        uint8
	Duplicate                       uint8
	StepCount                       uint8
	FillChannel                     uint16
	ChannelList                     [16]Channel
	Padding                         uint16
}

type TLV struct {
	TagNumber uint8
	TagLength uint16
	TagData   []byte
}

type AWDL struct {
	CategoryCode uint8
	Oui          [3]byte
	Type         uint8
	Version      uint8 // change it to a different type having major minor
	Subtype      uint8
	Reserved     uint8
	PhyTxTime    [4]byte
	TgtTxTime    [4]byte
	Tags         []TLV
}

func ProcessTag(tlv TLV) interface{} {
	sync := Synchronization{}

	// length check

	// for _, tlv := range tlvs {
	switch tlv.TagNumber {

	case AWDL_SYNCHRONIZATON_PARAMETERS_TLV:
		sync.NewAwChannel = tlv.TagData[0]
		sync.TxCounter = uint16(tlv.TagData[2])<<8 + uint16(tlv.TagData[1])
		sync.MasterChannel = tlv.TagData[3]
		sync.GuardTime = tlv.TagData[4]
		sync.AvailabilityWindowPeriod = uint16(tlv.TagData[6])<<8 + uint16(tlv.TagData[5])
		sync.ActionFrame = uint16(tlv.TagData[8])<<8 + uint16(tlv.TagData[7])
		sync.AwdlFlags = uint16(tlv.TagData[10])<<8 + uint16(tlv.TagData[9])
		sync.AvailabilityWindowExtLen = uint16(tlv.TagData[12])<<8 + uint16(tlv.TagData[11])
		sync.AvailabilityWindowCommonLen = uint16(tlv.TagData[14])<<8 + uint16(tlv.TagData[13])
		sync.RemainingAvailabilityWindowlen = uint16(tlv.TagData[16])<<8 + uint16(tlv.TagData[15])
		sync.MinExtensionCount = tlv.TagData[17]
		sync.MaxExtensionCountForMulticast = tlv.TagData[18]
		sync.MaxExtensionCountForUnicast = tlv.TagData[19]
		sync.MaxExtensionCountForActionFrame = tlv.TagData[20]
		copy(sync.MasterAddress[:], tlv.TagData[21:27])
		sync.PresenceMode = tlv.TagData[27]
		sync.Unknown = tlv.TagData[28]
		sync.AwSequenceNum = uint16(tlv.TagData[30])<<8 + uint16(tlv.TagData[29])
		sync.ApBeaconAlignmentDelta = uint16(tlv.TagData[32])<<8 + uint16(tlv.TagData[31])
		sync.NumChannels = tlv.TagData[33]
		sync.Encoding = tlv.TagData[34]
		sync.Duplicate = tlv.TagData[35]
		sync.StepCount = tlv.TagData[36]
		sync.FillChannel = uint16(tlv.TagData[38])<<8 + uint16(tlv.TagData[37])

		loop := 0
		index := 39
		for loop < 16 {
			sync.ChannelList[loop].Flag = tlv.TagData[index]
			index++
			sync.ChannelList[loop].Number = tlv.TagData[index]
			index++
			loop++
		}

		sync.Padding = uint16(tlv.TagData[index+1])<<8 + uint16(tlv.TagData[index])

	default:
		return nil
	}

	return &sync
}

func DecodeAwdData(data []byte) {
	fmt.Println("calling DecodeAwdData")

	fmt.Println("type :", data[0])
	fmt.Println("version :", data[1]>>4, ".", data[1]&0x0F)
	fmt.Println("subtype :", data[2])
	fmt.Println()
}

func (awdl *AWDL) decodeFixedParams(data []byte) {

	//todo: add length check 12 is required

	awdl.Type = data[0]
	awdl.Version = data[1]
	awdl.Subtype = data[2]
	awdl.Reserved = data[3]
	copy(awdl.PhyTxTime[:], data[4:8])
	copy(awdl.TgtTxTime[:], data[8:12])
}

func (awdl *AWDL) decodeTags(data []byte) {

	//todo: add length check
	var totalData int
	var index uint16
	totalData = len(data)
	index = 0

	for totalData > 0 {
		//todo: length checks

		var tlvData TLV

		tlvData.TagNumber = data[index]
		index++
		totalData--

		tlvData.TagLength = uint16(data[index+1])<<8 + uint16(data[index])
		index += 2
		totalData -= 2

		// tlvData.TagData = append([]byte(nil), data[index:index+tlvData.TagLength])
		// tlvData.TagData = append([]byte(nil), data[1:5])
		tlvData.TagData = make([]byte, tlvData.TagLength)
		copy(tlvData.TagData, data[index:index+tlvData.TagLength])
		index += tlvData.TagLength
		totalData -= int(tlvData.TagLength)

		awdl.Tags = append(awdl.Tags, tlvData)
	}

}
func InitAwdlParser(packet gopacket.Packet) (*AWDL, error) {

	awdl := AWDL{}
	dot11Layer := packet.Layer(layers.LayerTypeDot11)

	if dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)

		// the dot11 payload is the 802.11 fixed params + AWDL data.
		var awdlData []byte = dot11.Payload

		// type and subtype are stored in 'Type' variable as follows.
		//		type is 2 bits(bit 0 to 1).
		// 		subtype is 4 bits(bit 2 to 5)

		// however as per 802.11 protocol the 802.11 Frame Control Field 8 bit definition is as follows
		//		version is 2 bits (bit 0 to 1) which is not part of the dot11.Type field.
		//		type is 2 bits (bit 2 to 3)
		//		subtype is 4 bits (bit 4 to 7)

		f_type := (((dot11.Type << 2) & 0x0F) >> 2)
		f_subtype := (((dot11.Type << 2) & 0xF0) >> 4)

		var categoryCode uint8
		var oui [3]byte // organizational unit identifier

		if f_type == 0 && f_subtype == 0xD {
			// to be AWL following conditions must be satisfied:
			//		the bssid should be of apple device.
			// 		category code must be 127
			// 		OUI must be 00:17:F2
			if bytes.Equal(dot11.Address3, []byte{0x00, 0x25, 0x00, 0xff, 0x94, 0x73}) {
				if len(awdlData) > 0 {
					categoryCode = awdlData[0]
					awdl.CategoryCode = categoryCode
				}

				// 127 is vendor specific
				if categoryCode == 127 {
					copy(oui[:], awdlData[1:4])
					awdl.Oui = oui

					// 		OUI must be 00:17:F2
					if oui[0] == 0x00 && oui[1] == 0x17 && oui[2] == 0xF2 {
						// 802.11 fields
						// fmt.Println("frame type = management")
						// fmt.Println("frame subtype = action")
						// fmt.Println("bssid :", dot11.Address3)
						// fmt.Println("category code :", categoryCode)
						// fmt.Println("OUI :", oui)

						// AWS specific Data
						// DecodeAwdData(awdlData[4:])
						// fmt.Println("type :", awdlData[4])
						// fmt.Println("version :", awdlData[5]>>4, ".", awdlData[5]&0x0F)
						// fmt.Println("subtype :", awdlData[6])
						// fmt.Println()

						awdl.decodeFixedParams(awdlData[4:])
						awdl.decodeTags(awdlData[16:])

						return &awdl, nil
					} else {
						return nil, errors.New("OUI is not 00:17:F2")
					}
				} else {
					return nil, errors.New("CategoryCode is not 127")
				}
			} else {
				return nil, errors.New("BSSID is not 00:25:00:FF:94:73")
			}
		} else {
			return nil, errors.New("Frame type is not management and(or) Subtype is not action")
		}
	} else {
		return nil, errors.New("802.11 layer not found")
	}
}
