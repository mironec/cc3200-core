/*
 WiFiClientSecure.h - Adaptation of Arduino WiFi library for Energia and CC3200 launchpad
 Modified: Noah Luskey | LuskeyNoah@gmail.com, Miron Zelina
 
 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.
 
 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.
 
 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef wificlientsecure_h
#define wificlientsecure_h
#include <Arduino.h>
#include <IPAddress.h>
#include <Stream.h>
#include <Client.h>
#include "WiFiClient.h"

class WiFiClientSecure : public WiFiClient {
    
public:
    WiFiClientSecure();
    WiFiClientSecure(uint8_t sock);
    ~WiFiClientSecure();
	virtual int connect(IPAddress ip, uint16_t port);
    virtual int connect(const char *host, uint16_t port);
	virtual int useRootCA(void);
	virtual int32_t sslGetReasonID(void);
    virtual const char *sslGetReason(void);
	
	boolean sslIsVerified;

protected:
	boolean sslVerifyStrict;
    boolean hasRootCA;
    int32_t sslLastError;
};

#endif
