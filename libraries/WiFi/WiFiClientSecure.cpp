/* TO DO:
 *   1) Add a way to check if the connection has been dropped by the server
 * X 2) Make this an extension of the print class in print.cpp
 *   3) Figure out what status is supposed to do
 *   4) Prevent the wrong methods from being called based on server or client side
 *
 */

/*
 WiFiClientSecure.cpp - Adaptation of Arduino WiFi library for Energia and CC3200 launchpad
 Author: Noah Luskey | LuskeyNoah@gmail.com, Miron Zelina
 
 WiFiClient objects suffer from a bit of an existential crisis, where really
 the same class serves two separate purposes. Client instances can exist server
 side (as a wrapper for a port to send messages to), or client side, as the 
 object attempting to make a connection. Only certain calls should be made in 
 each instance, and effort has been made to prevent the user from being able
 to mess things up with the wrong function calls.
 
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

extern "C" {
  #include "utility/wl_definitions.h"
  #include "utility/socket.h"
}

#include "WiFi.h"
#include "WiFiClientSecure.h"
#include "WiFiServer.h"

#define ROOTCA_PEM_FILE "/cert/ca.der"
#define CLIENT_PEM_FILE "/cert/cert.der"
#define CLIENT_KEY_FILE "/cert/key.der"

//--tested, working--//
//--client side--//
WiFiClientSecure::WiFiClientSecure() : WiFiClient() {
	socketOptListHead = NULL;
	socketOptListTail = NULL;
}

//--tested, working--//
//--server side--//
WiFiClientSecure::WiFiClientSecure(uint8_t socketIndex) : WiFiClient(socketIndex) {}


WiFiClientSecure::~WiFiClientSecure() {
	removeSocketOpts();
}

void WiFiClientSecure::addConnectSocketOpt(_i16 level, _i16 optname, const void *optval, SlSocklen_t optlen){
	socketOptList_t * opt = new socketOptList_t();
	opt->level = level;
	opt->optname = optname;
	opt->optval = optval;
	opt->optlen = optlen;
	opt->next = NULL;
	if(socketOptListTail != NULL) {
		socketOptListTail->next = opt;
	}
	else socketOptListHead = opt;
	socketOptListTail = opt;
}

void WiFiClientSecure::removeSocketOpts(){
	socketOptList_t *prev;
	while(socketOptListHead != NULL){
		prev = socketOptListHead;
		socketOptListHead = socketOptListHead->next;
		delete prev;
	}
	socketOptListTail = NULL;
}

//--tested, working--//
//--client side--//
int WiFiClientSecure::connect(const char* host, uint16_t port)
{
    //
    //get the host ip address
    //
    IPAddress hostIP(0,0,0,0);
    int success = WiFi.hostByName((char*)host, hostIP);
    if (!success) {
        return false;
    }
    
    return connect(hostIP, port);
}

//--tested, working--//
//--client side--//
int WiFiClientSecure::connect(IPAddress ip, uint16_t port)
{
    //
    //this function should only be called once and only on the client side
    //
    if (_socketIndex != NO_SOCKET_AVAIL) {
        return false;
    }
    
    
    //
    //get a socket index and attempt to create a socket
    //note that the socket is intentionally left as BLOCKING. This allows an
    //abusive user to send as many requests as they want as fast as they can try
    //and it won't overload simplelink.
    //
    int socketIndex = WiFiClass::getSocket();
    if (socketIndex == NO_SOCKET_AVAIL) {
        return false;
    }


    int socketHandle = sl_Socket(SL_AF_INET, SL_SOCK_STREAM, SL_SEC_SOCKET);
    if (socketHandle < 0) {
        return false;
    }

    // Utilize rootCA file for verifying server certificate if it's been supplied with .sslRootCA() previously
    if (hasRootCA) {
		addConnectSocketOpt(SL_SOL_SOCKET, SL_SO_SECURE_FILES_CA_FILE_NAME, ROOTCA_PEM_FILE, strlen(ROOTCA_PEM_FILE));
    }
	
	socketOptList_t *currentOpt = socketOptListHead;
	while(currentOpt != NULL){
		int iRet = sl_SetSockOpt(socketHandle, currentOpt->level, currentOpt->optname, currentOpt->optval, currentOpt->optlen);
		if(iRet < 0) {
			sslLastError = iRet;
			return false;
		}
		currentOpt = currentOpt->next;
	}
	removeSocketOpts();
	
    sslIsVerified = true;

    //
    //connect the socket to the requested IP address and port. Check for success
    //

    SlSockAddrIn_t server = {0};
    server.sin_family = SL_AF_INET;
    server.sin_port = sl_Htons(port);
    server.sin_addr.s_addr = ip;
    int iRet = sl_Connect(socketHandle, (SlSockAddr_t*)&server, sizeof(SlSockAddrIn_t));

    if ( iRet < 0 && (iRet != SL_ESECSNOVERIFY && iRet != SL_ESECDATEERROR) ) {
        sslLastError = iRet;
        sl_Close(socketHandle);
        return false;
    }

    // If the remote-end server cert could not be verified, and we demand strict verification, ABORT.
    if ( sslVerifyStrict && (iRet == SL_ESECSNOVERIFY || iRet == SL_ESECDATEERROR) ) {
        sslLastError = iRet;
        sl_Close(socketHandle);
        return false;
    }

    if (iRet == SL_ESECSNOVERIFY || iRet == SL_ESECDATEERROR) {
        sslLastError = iRet;
        sslIsVerified = false;
    }

    int enableOption = 1;
    sl_SetSockOpt(socketHandle, SL_SOL_SOCKET, SL_SO_NONBLOCKING, &enableOption, sizeof(enableOption));
    sl_SetSockOpt(socketHandle, SL_SOL_SOCKET, SL_SO_KEEPALIVE, &enableOption, sizeof(enableOption));

    //
    //we've successfully created a socket and connected, so store the
    //information in the arrays provided by WiFiClass
    //
    _socketIndex = socketIndex;
    WiFiClass::_handleArray[socketIndex] = socketHandle;
    WiFiClass::_typeArray[socketIndex] = TYPE_TCP_CLIENT;
    WiFiClass::_portArray[socketIndex] = port;
    return true;
}

int32_t WiFiClientSecure::sslGetReasonID(void)
{
    return sslLastError;
}

const char * WiFiClientSecure::sslGetReason(void)
{
    switch (sslLastError) {
        case SL_SOC_OK:
            return "OK";
        case SL_ESECSNOVERIFY:
            return "SL_ESECSNOVERIFY - SSL verification not enabled";
        case SL_ESECDATEERROR:
            return "SL_ESECDATEERROR - Connected, but RootCA date error";
        case SL_ESEC_ASN_SIG_CONFIRM_E:
            return "SL_ESEC_ASN_SIG_CONFIRM_E - RootCA could not verify site cert";
        case SL_ESECBADCAFILE:
            return "SL_ESECBADCAFILE - Bad RootCA file (needs DER binary format, not PEM)";
		case SL_ECONNREFUSED:
			return "SL_ECONNREFUSED - Connection refused";
    }
    return "UNKNOWN";
}

/*
void WiFiClient::sslStrict(boolean yesno)
{
    sslVerifyStrict = yesno;
}

int WiFiClient::sslRootCA(const uint8_t *rootCAfilecontents, const size_t filelen)
{
    int32_t i, fh;
    uint32_t tok;
    size_t maxsize;

    sl_FsDel((uint8_t*)ROOTCA_PEM_FILE, 0);

    if (rootCAfilecontents == NULL || filelen == 0) {
	hasRootCA = false;
        return true;
    }

    maxsize = (filelen / 512) * 512 + (filelen % 512);
    i = sl_FsOpen((uint8_t*)ROOTCA_PEM_FILE, FS_MODE_OPEN_CREATE(maxsize, _FS_FILE_OPEN_FLAG_COMMIT | _FS_FILE_OPEN_FLAG_NO_SIGNATURE_TEST), &tok, &fh);
    if (i != SL_FS_OK) {
        return false;
    }

    i = sl_FsWrite(fh, 0, (uint8_t *)rootCAfilecontents, filelen);
    sl_FsClose(fh, NULL, NULL, 0);

    if (i != filelen)
        return false;

    hasRootCA = true;
    return true;
}
*/

// Checks if an existing copy of /cert/rootCA.pem is on the Serial Flash; if so, use it!
int WiFiClientSecure::useRootCA(void)
{
    int32_t i;
    SlFsFileInfo_t fi;

    i = sl_FsGetInfo((uint8_t*)ROOTCA_PEM_FILE, 0, &fi);
    if (i != SL_FS_OK)
        return false;

    hasRootCA = true;
    return true;
}
