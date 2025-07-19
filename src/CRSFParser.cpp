#include <vector>
#include <string>
#include <string.h>
#include "CRSFParser/CRSFParser.h"
#include "Logger/Logger.h"

using namespace DebugTools;

namespace CRSFAnalyser
{
	const char* CRSFParser::PacketTypeToStr(uint8_t packetType)
	{
		switch (packetType) 
		{
			case (int)CRSFPacketType::GPS: return "GPS";
			case (int)CRSFPacketType::VARIO: return "VARIO Vertical speed";
			case (int)CRSFPacketType::BATTERY_SENSOR: return "BATTERY_SENSOR Battery stat";
			case (int)CRSFPacketType::BARO_ALTITUDE: return "BARO_ALTITUDE Barometric altitude";
			case (int)CRSFPacketType::HEARTBEAT: return "HEARTBEAT";
			case (int)CRSFPacketType::VIDEO_TRANSMITTER: return "VIDEO_TRANSMITTER";
			case (int)CRSFPacketType::LINK_STATISTICS: return "LINK_STATISTICS Signal information";
			case (int)CRSFPacketType::RC_CHANNELS_PACKED: return "RC_CHANNELS_PACKED";
			case (int)CRSFPacketType::SUBSET_RC_CHANNELS_PACKED: return "SUBSET_RC_CHANNELS_PACKEDChannels subset data";
			case (int)CRSFPacketType::LINK_RX_ID: return "LINK_RX_IDReceiver RSSI percent";
			case (int)CRSFPacketType::LINK_TX_ID: return "LINK_TX_ID Transmitter RSSI percent";
			case (int)CRSFPacketType::ATTITUDE: return "ATTITUDE: pitch, roll, yaw";
			case (int)CRSFPacketType::FLIGHT_MODE: return "FLIGHT_MODE Flight controller flight mode string";
			case (int)CRSFPacketType::DEVICE_PING: return "DEVICE_PING";
			case (int)CRSFPacketType::DEVICE_INFO: return "DEVICE_INFO";
			case (int)CRSFPacketType::PARAMETER_SETTINGS_ENTRY: return "PARAMETER_SETTINGS_ENTRY Configuration item data chunk";
			case (int)CRSFPacketType::PARAMETER_READ: return "PARAMETER_READ Configuration item read request";
			case (int)CRSFPacketType::PARAMETER_WRITE: return "PARAMETER_WRITE Configuration item write request";
			case (int)CRSFPacketType::ELRS_STATUS: return "ELRS_STATUS ExpressLRS good/bad packet count";
			case (int)CRSFPacketType::COMMAND: return "COMMAND CRSF command execute";
			case (int)CRSFPacketType::RADIO_ID: return "RADIO_ID Extended type used for OPENTX_SYNC";
			case (int)CRSFPacketType::KISS_REQ: return "KISS_REQ KISS request";
			case (int)CRSFPacketType::KISS_RESP: return "KISS_RESP KISS response";
			case (int)CRSFPacketType::MSP_REQ: return "MSP_REQ MSP parameter request / command";
			case (int)CRSFPacketType::MSP_RESP: return "MSP_RESP MSP parameter response chunk";
			case (int)CRSFPacketType::MSP_WRITE: return "MSP_WRITE MSP parameter write";
			case (int)CRSFPacketType::DISPLAYPORT_CMD: return "DISPLAYPORT_CMD MSP DisplayPort control command";
			case (int)CRSFPacketType::ARDUPILOT_RESP: return "ARDUPILOT_RESP";
			default: return "Unknown";
		}	
	}
	
	uint8_t CRSFParser::crc8_table[] = {
	  0x00, 0xD5, 0x7F, 0xAA, 0xFE, 0x2B, 0x81, 0x54, 0x29, 0xFC, 0x56, 0x83, 0xD7, 0x02, 0xA8, 0x7D,
	  0x52, 0x87, 0x2D, 0xF8, 0xAC, 0x79, 0xD3, 0x06, 0x7B, 0xAE, 0x04, 0xD1, 0x85, 0x50, 0xFA, 0x2F,
	  0xA4, 0x71, 0xDB, 0x0E, 0x5A, 0x8F, 0x25, 0xF0, 0x8D, 0x58, 0xF2, 0x27, 0x73, 0xA6, 0x0C, 0xD9,
	  0xF6, 0x23, 0x89, 0x5C, 0x08, 0xDD, 0x77, 0xA2, 0xDF, 0x0A, 0xA0, 0x75, 0x21, 0xF4, 0x5E, 0x8B,
	  0x9D, 0x48, 0xE2, 0x37, 0x63, 0xB6, 0x1C, 0xC9, 0xB4, 0x61, 0xCB, 0x1E, 0x4A, 0x9F, 0x35, 0xE0,
	  0xCF, 0x1A, 0xB0, 0x65, 0x31, 0xE4, 0x4E, 0x9B, 0xE6, 0x33, 0x99, 0x4C, 0x18, 0xCD, 0x67, 0xB2,
	  0x39, 0xEC, 0x46, 0x93, 0xC7, 0x12, 0xB8, 0x6D, 0x10, 0xC5, 0x6F, 0xBA, 0xEE, 0x3B, 0x91, 0x44,
	  0x6B, 0xBE, 0x14, 0xC1, 0x95, 0x40, 0xEA, 0x3F, 0x42, 0x97, 0x3D, 0xE8, 0xBC, 0x69, 0xC3, 0x16,
	  0xEF, 0x3A, 0x90, 0x45, 0x11, 0xC4, 0x6E, 0xBB, 0xC6, 0x13, 0xB9, 0x6C, 0x38, 0xED, 0x47, 0x92,
	  0xBD, 0x68, 0xC2, 0x17, 0x43, 0x96, 0x3C, 0xE9, 0x94, 0x41, 0xEB, 0x3E, 0x6A, 0xBF, 0x15, 0xC0,
	  0x4B, 0x9E, 0x34, 0xE1, 0xB5, 0x60, 0xCA, 0x1F, 0x62, 0xB7, 0x1D, 0xC8, 0x9C, 0x49, 0xE3, 0x36,
	  0x19, 0xCC, 0x66, 0xB3, 0xE7, 0x32, 0x98, 0x4D, 0x30, 0xE5, 0x4F, 0x9A, 0xCE, 0x1B, 0xB1, 0x64,
	  0x72, 0xA7, 0x0D, 0xD8, 0x8C, 0x59, 0xF3, 0x26, 0x5B, 0x8E, 0x24, 0xF1, 0xA5, 0x70, 0xDA, 0x0F,
	  0x20, 0xF5, 0x5F, 0x8A, 0xDE, 0x0B, 0xA1, 0x74, 0x09, 0xDC, 0x76, 0xA3, 0xF7, 0x22, 0x88, 0x5D,
	  0xD6, 0x03, 0xA9, 0x7C, 0x28, 0xFD, 0x57, 0x82, 0xFF, 0x2A, 0x80, 0x55, 0x01, 0xD4, 0x7E, 0xAB,
	  0x84, 0x51, 0xFB, 0x2E, 0x7A, 0xAF, 0x05, 0xD0, 0xAD, 0x78, 0xD2, 0x07, 0x53, 0x86, 0x2C, 0xF9
	};

	uint8_t CRSFParser::CalculateCRC8(uint8_t* data, uint32_t len) 
	{
		uint8_t crc = 0;
		for (uint32_t i = 0; i < len; ++i) 
		{
			crc = crc8_table[crc ^ *data++];
		}
		return crc;
	}

	uint16_t CRSFParser::ConvertChannelValue(unsigned channelValue, bool forward)
	{
		/*
		*       RC     PWM
		* min  172 ->  988us
		* mid  992 -> 1500us
		* max 1811 -> 2012us
		*/
		static constexpr float scale = (2012.f - 988.f) / (1811.f - 172.f);
		static constexpr float offset = 988.f - 172.f * scale;
		uint16_t result;
		if(forward)
			result = (scale * channelValue) + offset;
		else
			result = (channelValue - offset) / scale;
		//LOG("  ChannelValue = %i result = %i\n", channelValue, result);
		return result;
	}
	
	// !!! Untested !!!
	void CRSFParser::ParseFCGPSData(CRSFPayloadGPSData* data)
	{
		LOG("  latitude = %i\n", data->latitude);
		LOG("  longitude = %i\n", data->longitude);
		LOG("  groundspeed = %i\n", data->groundspeed);
		LOG("  gps_heading = %i\n", data->gps_heading);
		LOG("  altitude = %i\n", data->altitude);
		LOG("  num_satellites = %i\n", data->num_satellites);
	}

	// !!! Untested !!!
	void CRSFParser::ParseFCBatteryData(CRSFPayloadBatteryData* data)
	{
		LOG("  voltage = %i\n", data->voltage);
		LOG("  current = %i\n", data->current);
		LOG("  fuel = %i\n", data->fuel);
		LOG("  remaining = %i\n", data->remaining);
	}

	void CRSFParser::ParseFCRCChannelsData(CRSFPayloadRCChannelsData* channelsData)
	{
		channelsValue[0] = ConvertChannelValue(channelsData->chan0);
		channelsValue[1] = ConvertChannelValue(channelsData->chan1);
		channelsValue[2] = ConvertChannelValue(channelsData->chan2);
		channelsValue[3] = ConvertChannelValue(channelsData->chan3);
		channelsValue[4] = ConvertChannelValue(channelsData->chan4);
		channelsValue[5] = ConvertChannelValue(channelsData->chan5);
		channelsValue[6] = ConvertChannelValue(channelsData->chan6);
		channelsValue[7] = ConvertChannelValue(channelsData->chan7);
		channelsValue[8] = ConvertChannelValue(channelsData->chan8);
		channelsValue[9] = ConvertChannelValue(channelsData->chan9);
		channelsValue[10] = ConvertChannelValue(channelsData->chan10);
		channelsValue[11] = ConvertChannelValue(channelsData->chan11);
		channelsValue[12] = ConvertChannelValue(channelsData->chan12);
		channelsValue[13] = ConvertChannelValue(channelsData->chan13);
		channelsValue[14] = ConvertChannelValue(channelsData->chan14);
		channelsValue[15] = ConvertChannelValue(channelsData->chan15);
		
		for(int i = 0; i < 16; ++i)
		{
			LOG("  Channel_%i val = %i\n", i+1, channelsValue[i]);
		}
	}
	
	uint16_t CRSFParser::GetChannelValue(RCChannel channelId)
	{
		return channelsValue[(int)channelId];
	}

	// !!! Untested !!!
	void CRSFParser::ParseFCAttitudeData(CRSFPayloadAttitudeData* data)
	{
		LOG("  pitch = %i\n", data->pitch);
		LOG("  roll = %i\n", data->roll);
		LOG("  yaw = %i\n", data->yaw);
	}

	void CRSFParser::ParseFCLinkStatData(CRSFPayloadLinkStatData* data)
	{
		LOG("LinkStatData:\n");
		LOG("  Uplink RSSI Antenna 1 (dBm * -1) %i\n", data->up_rssi_ant1);
		LOG("  Uplink RSSI Antenna 2 (dBm * -1) %i\n", data->up_rssi_ant2);
		LOG("  Uplink Package success rate / Link quality (%%) %i\n", data->up_link_quality);
		LOG("  Uplink SNR (dB) %i\n", data->up_snr);
		LOG("  number of currently best antenna %i\n", data->active_antenna);
		if(data->rf_profile == 0)
			LOG("  rf_profile = 4fps\n");	
		else if(data->rf_profile == 1)
			LOG("  rf_profile = 50fps\n");	
		else if(data->rf_profile == 2)
			LOG("  rf_profile = 150fps\n");	
		else
			LOG("  rf_profile - unknown for %i\n", data->rf_profile);
			
		if(data->up_rf_power == 0)
			LOG("  up_rf_power = 0mW\n");	
		else if(data->up_rf_power == 1)
			LOG("  up_rf_power = 10mW\n");
		else if(data->up_rf_power == 2)
			LOG("  up_rf_power = 25mW\n");
		else if(data->up_rf_power == 3)
			LOG("  up_rf_power = 100mW\n");
		else if(data->up_rf_power == 4)
			LOG("  up_rf_power = 500mW\n");
		else if(data->up_rf_power == 5)
			LOG("  up_rf_power = 1000mW\n");
		else if(data->up_rf_power == 6)
			LOG("  up_rf_power = 2000mW\n");
		else if(data->up_rf_power == 7)
			LOG("  up_rf_power = 250mW\n");
		else if(data->up_rf_power == 8)
			LOG("  up_rf_power = 50mW\n");
		else
			LOG("  up_rf_power - unknown for %i\n", data->up_rf_power);
			
		LOG("  Downlink RSSI (dBm * -1) %i\n", data->down_rssi);
		LOG("  Downlink Package success rate / Link quality (%%) %i\n", data->down_link_quality);
		LOG("  Downlink SNR (dB) %i\n", data->down_snr);	
	}

	void CRSFParser::ParseFCELRSStatusData(CRSFPayloadELRSStatusData* data)
	{
		LOG("ELRSStatusData\n");
		LOG("  packetsBad = %i\n", data->packetsBad);
		LOG("  packetsGood = %i\n", data->packetsGood);
		LOG("  flags: ");
		if(data->flags == 0x00)
			LOG("No");
		else
		{
			if((data->flags & 0x01) == 0x01)
				LOG("Connected, ");
			if((data->flags & 0x04) == 0x04)
				LOG("Model Mismatch, ");
			if((data->flags & 0x08) == 0x08)
				LOG("Armed, ");
			if((data->flags & 0x20) == 0x20)
				LOG("Not while connected (not used), ");
			if((data->flags & 0x40) == 0x40)
				LOG("Baud rate too low (not used) ");
		}
		LOG("\n");
	}

	void CRSFParser::ParseFCPacket(uint8_t* packet, size_t packetLen)
	{
		LOG("============\nFCPacket: [");
		for(size_t i = 0; i < packetLen; i++)
		{
			LOG(" 0x%02X,", packet[i]);
		}
		LOG(" ]\n");
		
		if(packetLen < CRSF_PROTOCOL_PACKET_MIN_LEN)
		{
			LOG("[ERROR] Wrong packet length %i\n", packetLen );
			return;
		}
			
		int frameIndex = 0;
		while(frameIndex < packetLen)
		{
			uint8_t addr = packet[frameIndex];
			if(replaceAddrs.count(addr) > 0)
				addr = replaceAddrs[addr];

			if(addr != (uint8_t)CRSFAddresType::FLIGHT_CONTROLLER)
			{
				LOG("[ERROR] Wrong packet CRSF addr %i\n", addr );
				return;
			}
		
			uint8_t frameLen = packet[++frameIndex];
			if(frameLen > packetLen - 2 || frameLen > CRSF_PROTOCOL_PACKET_MAX_LEN)
			{
				LOG("[ERROR] Wrong frame length!!! frameLen=%i packetLen=%i\n", frameLen, packetLen);
				return;
			}
		
			uint8_t crcByte = packet[frameIndex + frameLen];
			//LOG("Processing crc crcByte=0x%02X frameIndex=%i\n", crcByte, frameIndex );
			++frameIndex;
			uint8_t crc = CalculateCRC8(packet + frameIndex, frameLen - 1);
			if (crcByte != crc) 
			{
				LOG("[ERROR] Wrong CRC! Expected: 0x%02X, Actual: 0x%02X\n", crcByte, crc);
				return;
			}
			
			uint8_t frameType = packet[frameIndex];
			//LOG("frameType=%i", frameType );
			switch (frameType) 
			{
				case (int)CRSFPacketType::GPS:
					{
						LOG("%s Data:\n", PacketTypeToStr(frameType));
						if(frameLen - 2 != (int)CRSFPayloadSize::GPS)
						{
							LOG("[ERROR] Wrong payload size for GPS frame: %i\n", frameLen);
							return;
						}
						ParseFCGPSData((CRSFPayloadGPSData*)(&packet[frameIndex + 1]));
					}
					break;
				case (int)CRSFPacketType::BATTERY_SENSOR:
					{
						LOG("%s Data:\n", PacketTypeToStr(frameType));
						if(frameLen - 2 != (int)CRSFPayloadSize::BATTERY_SENSOR)
						{
							LOG("[ERROR] Wrong payload size for Battery sensor frame: %i\n", frameLen);
							return;
						}
						ParseFCBatteryData((CRSFPayloadBatteryData*)(&packet[frameIndex + 1]));
					}
					break;
				case (int)CRSFPacketType::RC_CHANNELS_PACKED:
					{
						LOG("%s Channels data:\n", PacketTypeToStr(frameType));
						if(frameLen - 2 != (int)CRSFPayloadSize::RC_CHANNELS)
						{
							LOG("[ERROR] Wrong payload size for RC_CHANNELS frame: %i\n", frameLen);
							return;
						}
						ParseFCRCChannelsData((CRSFPayloadRCChannelsData*)(&packet[frameIndex + 1]));
					}
					break;
				case (int)CRSFPacketType::ATTITUDE:
					{
						LOG("%s Data:\n", PacketTypeToStr(frameType));
						if(frameLen - 2 != (int)CRSFPayloadSize::ATTITUDE)
						{
							LOG("[ERROR] Wrong payload size for ATTITUDE frame: %i\n", frameLen);
							return;
						}
						ParseFCAttitudeData((CRSFPayloadAttitudeData*)(&packet[frameIndex + 1]));
					}
					break;
				case (int)CRSFPacketType::LINK_STATISTICS:
					{
						LOG("%s Data:\n", PacketTypeToStr(frameType));
						if(frameLen - 2 != (int)CRSFPayloadSize::LINK_STATISTICS)
						{
							LOG("[ERROR] Wrong payload size for LINK_STATISTICS frame: %i\n", frameLen);
							return;
						}
						ParseFCLinkStatData((CRSFPayloadLinkStatData*)(&packet[frameIndex + 1]));
					}
					break;
				case (int)CRSFPacketType::ELRS_STATUS:
					{
						LOG("%s Data:\n", PacketTypeToStr(frameType));
						ParseFCELRSStatusData((CRSFPayloadELRSStatusData*)(&packet[frameIndex + 1]));
					}
					break;
				default:
					LOG("%s\n", PacketTypeToStr(frameType));
					break;
			}
			frameIndex += frameLen;
			parserStatistics[frameType] = (parserStatistics.find(frameType) == parserStatistics.end() ? 1 : parserStatistics[frameType] + 1);
		}	
	}

	void CRSFParser::ParseFCPacket(std::vector<uint8_t>* byteStream)
	{
		size_t streamLen = byteStream->size();
		if(streamLen == 0)
			return;
		
		int streamIndex = 0;
		size_t packetLen = 0;
		size_t uncompletedPacketLen = uncompletedPacket.size();	
		LOG("CRSFParser::ParseFCPacket uncompletedPacketLen=%d\n", uncompletedPacketLen );			
		while(streamIndex < streamLen)
		{
			if(uncompletedPacketLen > 0)
			{
				if(uncompletedPacketLen == 1) // addr
				{
					packetLen = (*byteStream)[streamIndex++];
					LOG("CRSFParser::ParseFCPacket packetLen=%d\n", packetLen );						
					uncompletedPacket.push_back(packetLen);
				}
				else
				{
					packetLen = uncompletedPacket[1] - (uncompletedPacketLen - 2); // bytes left to read
					LOG("CRSFParser::ParseFCPacket packetLen=%d uncompletedPacket[1]=%d uncompletedPacketLen=%d\n", packetLen, uncompletedPacket[1], uncompletedPacketLen);
				}
					
				if(packetLen > CRSF_PROTOCOL_PACKET_MAX_LEN)
				{
					LOG("[ERROR] wrong packet length %d\n", packetLen );
					packetLen = 0;
					uncompletedPacket.clear();
					return;
				}
				else
				{
					while(packetLen > 0 && streamIndex < streamLen)
					{
						uncompletedPacket.push_back((*byteStream)[streamIndex++]);
						--packetLen;
					}
					if(packetLen == 0)
					{
						LOG("packet ready; streamIndex=%d streamLen=%d\n", streamIndex, streamLen);
						ParseFCPacket(uncompletedPacket.data(), uncompletedPacket.size());
						uncompletedPacket.clear();
						uncompletedPacketLen = 0;
					}
				}
			}
			else
			{
				uncompletedPacket.push_back((*byteStream)[streamIndex++]);
				++uncompletedPacketLen;
			}
		}
	}

	void CRSFParser::ParseFCPacket(std::vector<uint8_t> byteStream)
	{
		ParseFCPacket(&byteStream);
	}

	void CRSFParser::LogParserStatistics()
	{
		LOG("\nCRSF Parser statistics:\n");
		for(std::map<uint8_t, int>::iterator it = parserStatistics.begin(); it != parserStatistics.end(); it++)
		{
			LOG("packet type %s (0x%2X) count = %i\n", PacketTypeToStr(it->first), it->first, it->second);
		}
	}

	void CRSFParser::CreateCRSF_RCChannelsPacket(CRSFAddresType addr, CRSFPayloadRCChannelsData& channelsData, std::vector<uint8_t>& result)
	{
		size_t buffLen = (uint8_t)CRSFPayloadSize::RC_CHANNELS + 4;
		uint8_t buff[buffLen];	

		// header
		buff[0] = (uint8_t)addr;								// addr
		buff[1] = (uint8_t)CRSFPayloadSize::RC_CHANNELS + 2;	// length
		buff[2] = (uint8_t)CRSFPacketType::RC_CHANNELS_PACKED;	// type
		
		CRSFPayloadRCChannelsData sendData;
		sendData.chan0 = ConvertChannelValue(channelsData.chan0, false);
		sendData.chan1 = ConvertChannelValue(channelsData.chan1, false);
		sendData.chan2 = ConvertChannelValue(channelsData.chan2, false);
		sendData.chan3 = ConvertChannelValue(channelsData.chan3, false);
		sendData.chan4 = ConvertChannelValue(channelsData.chan4, false);
		sendData.chan5 = ConvertChannelValue(channelsData.chan5, false);
		sendData.chan6 = ConvertChannelValue(channelsData.chan6, false);
		sendData.chan7 = ConvertChannelValue(channelsData.chan7, false);
		sendData.chan8 = ConvertChannelValue(channelsData.chan8, false);
		sendData.chan9 = ConvertChannelValue(channelsData.chan9, false);
		sendData.chan10 = ConvertChannelValue(channelsData.chan10, false);
		sendData.chan11 = ConvertChannelValue(channelsData.chan11, false);
		sendData.chan12 = ConvertChannelValue(channelsData.chan12, false);
		sendData.chan13 = ConvertChannelValue(channelsData.chan13, false);
		sendData.chan14 = ConvertChannelValue(channelsData.chan14, false);
		sendData.chan15 = ConvertChannelValue(channelsData.chan15, false);
		
		memcpy(buff + 3, (uint8_t*)&sendData, (uint8_t)CRSFPayloadSize::RC_CHANNELS);
		
		buff[buffLen - 1] = CRSFParser::CalculateCRC8(buff + 2, buffLen - 3);
		result.assign(buff, buff + buffLen);
	}
	
	void CRSFParser::ReplaceAddr(uint8_t from, uint8_t to)
	{
		replaceAddrs[from] = to;
	}

} // namespace CRSFAnalyser
