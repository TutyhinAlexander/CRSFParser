#ifndef _CRSFPARSER_H_
#define _CRSFPARSER_H_

#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <queue>

// Full description of CRSF protocol: https://github.com/tbs-fpv/tbs-crsf-spec/blob/main/crsf.md#crsf-protocol

// CRSF format: [sync] [len] [type] [payload] [crc8] with a maximum total size of 64 bytes
//	 SYNC: All serial CRSF packets begin with the CRSF SYNC byte 0xC8, except for EdgeTX's outgoing channel/telemetry packets, which start with 0xEE. For compatibility, the new code should support the SYNC byte, but all transmitted packets begin with 0xC8. I2C CRSF packets start with a CRSF address.
//   LEN: Length of bytes that follow, including type, payload, and CRC (PayloadLength + 2). The packet length is PayloadLength + 4 (sync, len, type, crc) or LEN + 2 (sync, len).
//   TYPE: The type of CRSF frame.
//   PAYLOAD: Data specific to the frame type. Maximum of 60 bytes.
//   CRC: CRC8 using poly 0xD5, includes all bytes from type (buffer[2]) to the end of the payload.

#define CRSF_BAUDRATE 420000
#define CRSF_PROTOCOL_PACKET_MIN_LEN 4	//	[sync] [len] [type] [payload?] [crc8]
#define CRSF_PROTOCOL_PACKET_MAX_LEN 64
#define CRSF_RC_CHANNELS_COUNT 16
#define CRSF_RC_BITS_PER_CHANNEL 11

namespace CRSFAnalyser
{
     enum class CRSFAddresType : uint8_t 
     {
          BROADCAST = 0x00,
          USB = 0x10,
          TBS_CORE_PNP_PRO = 0x80,
          RESERVED1 = 0x8A,
          CURRENT_SENSOR = 0xC0,
          GPS = 0xC2,
          TBS_BLACKBOX = 0xC4,
          FLIGHT_CONTROLLER = 0xC8,
          RESERVED2 = 0xCA,
          RACE_TAG = 0xCC,
          RADIO_TRANSMITTER = 0xEA,
          CRSF_RECEIVER = 0xEC,
          CRSF_TRANSMITTER = 0xEE
      };
      
     enum class CRSFPayloadSize : uint8_t 
     {
          GPS = 15,
          BATTERY_SENSOR = 8,
          LINK_STATISTICS = 10,
          RC_CHANNELS = CRSF_RC_CHANNELS_COUNT * CRSF_RC_BITS_PER_CHANNEL / 8, ///< 11 bits per channel * 16 channels = 22 bytes.
          ATTITUDE = 6,
     };

     enum class CRSFPacketType : uint8_t
     {
          GPS = 0x02,					// GPS position, ground speed, heading, altitude, satellite count.
          VARIO = 0x07,					// Vertical speed.
          BATTERY_SENSOR = 0x08,				// Battery voltage, current, mAh, remaining percent.
          BARO_ALTITUDE = 0x09,				// Barometric altitude
          HEARTBEAT = 0x0B,					// Heartbeat
          VIDEO_TRANSMITTER = 0x0F,
          LINK_STATISTICS = 0x14,				// Signal information. Uplink/Downlink RSSI, SNR, Link Quality (LQ), RF mode, transmit power
          RC_CHANNELS_PACKED = 0x16,				// Channels data (both handset to TX and RX to flight controller)
          SUBSET_RC_CHANNELS_PACKED = 0x17,			// Channels subset data
          LINK_RX_ID = 0x1C,					// Receiver RSSI percent, power?
          LINK_TX_ID = 0x1D,					// Transmitter RSSI percent, power, fps?
          ATTITUDE = 0x1E,					// Attitude: pitch, roll, yaw.
          FLIGHT_MODE = 0x21,				// Flight controller flight mode string.
          DEVICE_PING = 0x28,				// Sender requesting DEVICE_INFO from all destination devices.
          DEVICE_INFO = 0x29,				// Device name, firmware version, hardware version, serial number (PING response).
          PARAMETER_SETTINGS_ENTRY = 0x2B,			// Configuration item data chunk
          PARAMETER_READ = 0x2C,				// Configuration item read request
          PARAMETER_WRITE = 0x2D,				// Configuration item write request
          ELRS_STATUS = 0x2E,				// !!Non Standard!! ExpressLRS good/bad packet count, status flags
          COMMAND	= 0x32, 				// CRSF command execute
          RADIO_ID = 0x3A,					// Extended type used for OPENTX_SYNC
          KISS_REQ = 0x78,					// KISS request
          KISS_RESP = 0x79, 					// KISS response
          MSP_REQ = 0x7A,					// MSP parameter request / command
          MSP_RESP = 0x7B, 					// MSP parameter response chunk
          MSP_WRITE = 0x7C,					// MSP parameter write
          DISPLAYPORT_CMD = 0x7D,				// MSP DisplayPort control command
          ARDUPILOT_RESP = 0x80,				// Ardupilot output?
     };
     
     enum RCChannel
     {
          CHANNEL_1 = 0,
          CHANNEL_2 = 1,
          CHANNEL_3 = 2,
          CHANNEL_4 = 3,
          CHANNEL_5 = 4,
          CHANNEL_6 = 5,
          CHANNEL_7 = 6,
          CHANNEL_8 = 7,
          CHANNEL_9 = 8,
          CHANNEL_10 = 9,
          CHANNEL_11 = 10,
          CHANNEL_12 = 11,
          CHANNEL_13 = 12,
          CHANNEL_14 = 13,
          CHANNEL_15 = 14,
          CHANNEL_16 = 15,
     };

     #pragma pack(push, 1)
     struct CRSFPayloadRCChannelsData
     {
          // 176 bits of data (11 bits per channel * 16 channels) = 22 bytes
          unsigned chan0 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan1 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan2 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan3 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan4 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan5 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan6 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan7 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan8 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan9 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan10 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan11 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan12 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan13 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan14 : CRSF_RC_BITS_PER_CHANNEL;
          unsigned chan15 : CRSF_RC_BITS_PER_CHANNEL;
     };

     struct CRSFPayloadGPSData
     {
          int32_t latitude;
          int32_t longitude;
          uint16_t groundspeed;
          uint16_t gps_heading;
          uint16_t altitude;
          uint8_t num_satellites;
     };

     struct CRSFPayloadBatteryData
     {
          uint16_t voltage;
          uint16_t current;
          uint32_t fuel : 24;
          uint8_t remaining;
     };

     struct CRSFPayloadAttitudeData
     {
          uint16_t pitch;
          uint16_t roll;
          uint16_t yaw;
     };

     struct CRSFPayloadLinkStatData
     {
          uint8_t up_rssi_ant1;       // Uplink RSSI Antenna 1 (dBm * -1)
          uint8_t up_rssi_ant2;       // Uplink RSSI Antenna 2 (dBm * -1)
          uint8_t up_link_quality;    // Uplink Package success rate / Link quality (%)
          int8_t up_snr;              // Uplink SNR (dB)
          uint8_t active_antenna;     // number of currently best antenna
          uint8_t rf_profile;         // enum {4fps = 0 , 50fps, 150fps}
          uint8_t up_rf_power;        // enum {0mW = 0, 10mW, 25mW, 100mW, 500mW, 1000mW, 2000mW, 250mW, 50mW}
          uint8_t down_rssi;          // Downlink RSSI (dBm * -1)
          uint8_t down_link_quality;  // Downlink Package success rate / Link quality (%)
          int8_t down_snr;            // Downlink SNR (dB)
     };

     struct CRSFPayloadELRSStatusData
     {
          uint8_t packetsBad;	// Bad packet (failed CRC) count in the past second
          uint16_t packetsGood;	// Good packet (passed CRC) count in the past second
          uint8_t flags;		// Higher values have higher priority { 0x00 - No flags, 0x01 - Connected, 0x04 - Model Mismatch, 0x08 - Armed, 0x20 - Not while connected (not used), 0x40 - Baud rate too low (not used)}
          //char* message; 		// Display message
     };

     #pragma pack(pop)



     class CRSFParser
     {
     private:
          std::vector<uint8_t> uncompletedPacket;
          static uint8_t crc8_table[];
          std::map<uint8_t, int> parserStatistics;
          std::map<uint8_t, uint8_t> replaceAddrs; // replace CRSF addr from <key> to <val>
          uint16_t channelsValue[16];
          
          uint8_t CalculateCRC8(uint8_t* data, uint32_t len);
          // Convert between RC [172, 1811] and PWM value [1000, 2000]
          uint16_t ConvertChannelValue(unsigned channelValue, bool forward = true);
          
          void ParseFCGPSData(CRSFPayloadGPSData* data);
          void ParseFCBatteryData(CRSFPayloadBatteryData* data);
          void ParseFCRCChannelsData(CRSFPayloadRCChannelsData* channelsData);
          void ParseFCAttitudeData(CRSFPayloadAttitudeData* data);
          void ParseFCLinkStatData(CRSFPayloadLinkStatData* data);
          void ParseFCELRSStatusData(CRSFPayloadELRSStatusData* data);
          
          const char* PacketTypeToStr(uint8_t packetType);
          
     public:
          void ParseFCPacket(std::vector<uint8_t>* packet);
          void ParseFCPacket(std::vector<uint8_t> packet);
          void ParseFCPacket(uint8_t* packet, size_t packetLen);
          void LogParserStatistics();
          void ReplaceAddr(uint8_t from, uint8_t to);
          uint16_t GetChannelValue(RCChannel channelId);
          
          void CreateCRSF_RCChannelsPacket(CRSFAddresType addr, CRSFPayloadRCChannelsData& channelsData, std::vector<uint8_t>& result);
     };

} // namespace CRSFAnalyser

#endif // _CRSFPARSER_H_
