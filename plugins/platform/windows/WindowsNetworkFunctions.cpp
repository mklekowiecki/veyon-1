/*
 * WindowsNetworkFunctions.cpp - implementation of WindowsNetworkFunctions class
 *
 * Copyright (c) 2017-2026 Tobias Junghans <tobydox@veyon.io>
 *
 * This file is part of Veyon - https://veyon.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program (see COPYING); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 */

#define INITGUID
#include <winsock2.h>
#include <windows.h>
#include <netfw.h>
#include <netioapi.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <fwpmu.h>

#include <array>

#include <QHostAddress>
#include <QProcess>
#include <QUuid>

#include "HostAddress.h"
#include "WindowsCoreFunctions.h"
#include "WindowsNetworkFunctions.h"


static HRESULT WindowsFirewallInitialize2( INetFwPolicy2** fwPolicy2 )
{
	HRESULT hr = S_OK;

	// Create an instance of the firewall settings manager.
	hr = CoCreateInstance( CLSID_NetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
							IID_INetFwPolicy2, reinterpret_cast<void**>( fwPolicy2 ) );
	if( FAILED( hr ) )
	{
		vCritical() << "CoCreateInstance() returned" << hr;
	}

	return hr;
}


static void WindowsFirewallCleanup2( INetFwPolicy2* fwPolicy2 )
{
	if( fwPolicy2 != nullptr )
	{
		fwPolicy2->Release();
	}
}



static HRESULT WindowsFirewallAddApp2( INetFwPolicy2* fwPolicy2,
									   const wchar_t* fwApplicationPath,
									   const wchar_t* fwName )
{
	HRESULT hr = S_OK;
	BSTR fwBstrRuleName = nullptr;
	BSTR fwBstrApplicationPath = nullptr;
	BSTR fwBstrRuleDescription = nullptr;
	BSTR fwBstrRuleGrouping = nullptr;

	INetFwRules *pFwRules = nullptr;
	INetFwRule *pFwRule = nullptr;

	// Retrieve INetFwRules
	hr = fwPolicy2->get_Rules( &pFwRules );
	if( FAILED( hr ) )
	{
		vCritical() << "get_Rules() returned" << hr;
		goto cleanup;
	}

	// Create an instance of an authorized application.
	hr = CoCreateInstance( CLSID_NetFwRule, nullptr,
							CLSCTX_INPROC_SERVER,
							IID_INetFwRule, reinterpret_cast<void**>( &pFwRule ) );
	if( FAILED( hr ) )
	{
		vCritical() << "CoCreateInstance() returned" << hr;
		goto cleanup;
	}

	fwBstrRuleName = SysAllocString( fwName );
	fwBstrApplicationPath = SysAllocString( fwApplicationPath );
	fwBstrRuleDescription = SysAllocString( fwName );
	fwBstrRuleGrouping = SysAllocString( fwName );

	// Set the rule
	pFwRule->put_Name( fwBstrRuleName );
	pFwRule->put_ApplicationName( fwBstrApplicationPath );
	pFwRule->put_Description( fwBstrRuleDescription );
	pFwRule->put_Grouping( fwBstrRuleGrouping );

	pFwRule->put_Action( NET_FW_ACTION_ALLOW );
	pFwRule->put_Enabled( VARIANT_TRUE );
	pFwRule->put_Protocol( NET_FW_IP_PROTOCOL_TCP );
	pFwRule->put_Profiles( NET_FW_PROFILE2_ALL );


	// Add the application to the collection.
	hr = pFwRules->Add( pFwRule );
	if( FAILED( hr ) )
	{
		vCritical() << "Add() returned" << hr;
		goto cleanup;
	}

cleanup:
	// Free the BSTRs.
	SysFreeString( fwBstrRuleName );
	SysFreeString( fwBstrApplicationPath );
	SysFreeString( fwBstrRuleDescription );
	SysFreeString( fwBstrRuleGrouping );

	if( pFwRule != nullptr )
	{
		pFwRule->Release();
	}

	if( pFwRules != nullptr )
	{
		pFwRules->Release();
	}

	return hr;
}



static HRESULT WindowsFirewallRemoveApp2( INetFwPolicy2 * fwPolicy2,
										  const wchar_t* fwName )
{
	HRESULT hr = S_OK;
	BSTR fwBstrRuleName = SysAllocString( fwName );

	INetFwRules *pFwRules = nullptr;

	// Retrieve INetFwRules
	hr = fwPolicy2->get_Rules( &pFwRules );
	if( FAILED( hr ) )
	{
		vCritical() << "get_Rules() returned" << hr;
		goto cleanup;
	}

	// Remove rule
	hr = pFwRules->Remove( fwBstrRuleName );
	if( FAILED( hr ) )
	{
		vCritical() << "Remove() returned" << hr;
		goto cleanup;
	}

cleanup:
	// Free the BSTRs.
	SysFreeString( fwBstrRuleName );

	if( pFwRules != nullptr )
	{
		pFwRules->Release();
	}

	return hr;
}



static bool configureFirewallException( INetFwPolicy2* fwPolicy2, const wchar_t* fwApplicationPath, const wchar_t* fwName, bool enabled )
{
	// always remove firewall exception first
	WindowsFirewallRemoveApp2( fwPolicy2, fwName );

	if( enabled )
	{
		// add service to the list of authorized applications
		const auto hr = WindowsFirewallAddApp2( fwPolicy2, fwApplicationPath, fwName );
		if( hr != S_OK )
		{
			// failed because firewall service not running / disabled?
			if( hr == WindowsNetworkFunctions::WindowsFirewallServiceError )
			{
				// then assume this is intended, log a warning and
				// pretend everything went well
				vWarning() << "Windows Firewall service not running or disabled - can't add or remove firewall exception!";
				return true;
			}

			vCritical() << "WindowsFirewallAddApp2() returned" << hr;
			return false;
		}
	}

	return true;
}



WindowsNetworkFunctions::WindowsNetworkFunctions() : PlatformNetworkFunctions()
{
	WSADATA wsadata;
	const auto error = WSAStartup( MAKEWORD(2,0), &wsadata );
	if( error != S_OK )
	{
		vCritical() << "failed to initialize WinSock:" << error;
	}
}



WindowsNetworkFunctions::PingResult WindowsNetworkFunctions::ping(const QString& hostAddress)
{
	auto result = PingResult::Unknown;

	const auto ipAddress = HostAddress(hostAddress).convert(HostAddress::Type::IpAddress);
	if (ipAddress.isEmpty() == false)
	{
		const auto addressProtocol = QHostAddress(ipAddress).protocol();

		if (addressProtocol == QAbstractSocket::IPv4Protocol && pingIPv4Address(ipAddress, &result))
		{
			return result;
		}

		if (addressProtocol == QAbstractSocket::IPv6Protocol && pingIPv6Address(ipAddress, &result))
		{
			return result;
		}
	}

	if (pingViaUtility(hostAddress, &result))
	{
		return result;
	}

	return PingResult::Unknown;
}



bool WindowsNetworkFunctions::configureFirewallException( const QString& applicationPath, const QString& description, bool enabled )
{
	HRESULT hr = S_OK;

	// initialize COM
	HRESULT comInit = CoInitializeEx( nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE );

	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if( comInit != RPC_E_CHANGED_MODE )
	{
		hr = comInit;
		if( FAILED( hr ) )
		{
			vCritical() << "CoInitializeEx() returned" << hr;
			return false;
		}
	}

	// retrieve current firewall profile
	INetFwPolicy2 *fwPolicy2 = nullptr;
	hr = WindowsFirewallInitialize2( &fwPolicy2 );
	if( FAILED( hr ) )
	{
		vCritical() << "WindowsFirewallInitialize2() returned" << hr;
		return false;
	}

	bool result = ::configureFirewallException( fwPolicy2,
												WindowsCoreFunctions::toConstWCharArray( applicationPath ),
												WindowsCoreFunctions::toConstWCharArray( description ),
												enabled );

	WindowsFirewallCleanup2( fwPolicy2 );

	// Uninitialize COM.
	if( SUCCEEDED( comInit ) )
	{
		CoUninitialize();
	}

	return result;
}



// the MinGW-w64 headers lack the definitions of WFP layers, conditions and session flags
static constexpr GUID WfpLayerAleAuthConnectV4{0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
static constexpr GUID WfpLayerAleAuthConnectV6{0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
static constexpr GUID WfpConditionIpRemoteAddress{0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};
static constexpr UINT32 WfpSessionFlagDynamic = 0x00000001;



static DWORD addInternetAccessFilter(HANDLE engine, const GUID& subLayerKey, const GUID& layerKey,
									 FWP_ACTION_TYPE action, UINT8 weight,
									 FWPM_FILTER_CONDITION0* conditions, UINT32 conditionCount)
{
	FWPM_FILTER0 filter{};
	filter.displayData.name = const_cast<wchar_t *>(L"Veyon internet access control");
	filter.layerKey = layerKey;
	filter.subLayerKey = subLayerKey;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = weight;
	filter.action.type = action;
	filter.numFilterConditions = conditionCount;
	filter.filterCondition = conditions;

	return FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
}



static DWORD addInternetAccessFilters(HANDLE engine)
{
	static constexpr UINT8 BlockWeight = 1;
	static constexpr UINT8 PermitWeight = 2;

	// loopback, private, link-local, multicast and broadcast addresses remain reachable
	std::array<FWP_V4_ADDR_AND_MASK, 7> localNetworksV4{{
		{0x7F000000, 0xFF000000}, // 127.0.0.0/8
		{0x0A000000, 0xFF000000}, // 10.0.0.0/8
		{0xAC100000, 0xFFF00000}, // 172.16.0.0/12
		{0xC0A80000, 0xFFFF0000}, // 192.168.0.0/16
		{0xA9FE0000, 0xFFFF0000}, // 169.254.0.0/16
		{0xE0000000, 0xF0000000}, // 224.0.0.0/4
		{0xFFFFFFFF, 0xFFFFFFFF}  // 255.255.255.255/32
	}};

	std::array<FWP_V6_ADDR_AND_MASK, 4> localNetworksV6{{
		{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128}, // ::1/128
		{{0xFE, 0x80}, 10}, // fe80::/10
		{{0xFC}, 7}, // fc00::/7
		{{0xFF}, 8} // ff00::/8
	}};

	// multiple conditions for the same field are combined using a logical OR
	std::array<FWPM_FILTER_CONDITION0, localNetworksV4.size()> conditionsV4{};
	for (size_t i = 0; i < localNetworksV4.size(); ++i)
	{
		conditionsV4[i].fieldKey = WfpConditionIpRemoteAddress;
		conditionsV4[i].matchType = FWP_MATCH_EQUAL;
		conditionsV4[i].conditionValue.type = FWP_V4_ADDR_MASK;
		conditionsV4[i].conditionValue.v4AddrMask = &localNetworksV4[i];
	}

	std::array<FWPM_FILTER_CONDITION0, localNetworksV6.size()> conditionsV6{};
	for (size_t i = 0; i < localNetworksV6.size(); ++i)
	{
		conditionsV6[i].fieldKey = WfpConditionIpRemoteAddress;
		conditionsV6[i].matchType = FWP_MATCH_EQUAL;
		conditionsV6[i].conditionValue.type = FWP_V6_ADDR_MASK;
		conditionsV6[i].conditionValue.v6AddrMask = &localNetworksV6[i];
	}

	// use a random key so that servers of multiple sessions do not conflict
	FWPM_SUBLAYER0 subLayer{};
	subLayer.subLayerKey = QUuid::createUuid();
	subLayer.displayData.name = const_cast<wchar_t *>(L"Veyon internet access control");
	subLayer.weight = 0xFFFF;

	auto error = FwpmSubLayerAdd0(engine, &subLayer, nullptr);
	if (error != ERROR_SUCCESS)
	{
		return error;
	}

	error = addInternetAccessFilter(engine, subLayer.subLayerKey, WfpLayerAleAuthConnectV4,
									FWP_ACTION_BLOCK, BlockWeight, nullptr, 0);
	if (error != ERROR_SUCCESS)
	{
		return error;
	}

	error = addInternetAccessFilter(engine, subLayer.subLayerKey, WfpLayerAleAuthConnectV4,
									FWP_ACTION_PERMIT, PermitWeight, conditionsV4.data(), conditionsV4.size());
	if (error != ERROR_SUCCESS)
	{
		return error;
	}

	error = addInternetAccessFilter(engine, subLayer.subLayerKey, WfpLayerAleAuthConnectV6,
									FWP_ACTION_BLOCK, BlockWeight, nullptr, 0);
	if (error != ERROR_SUCCESS)
	{
		return error;
	}

	return addInternetAccessFilter(engine, subLayer.subLayerKey, WfpLayerAleAuthConnectV6,
								   FWP_ACTION_PERMIT, PermitWeight, conditionsV6.data(), conditionsV6.size());
}



bool WindowsNetworkFunctions::setInternetAccessBlocked(bool blocked)
{
	if (blocked == isInternetAccessBlocked())
	{
		return true;
	}

	if (blocked == false)
	{
		// all filters belong to a dynamic session and are removed along with it
		FwpmEngineClose0(m_internetAccessFilterEngine);
		m_internetAccessFilterEngine = nullptr;
		return true;
	}

	// use a dynamic session so that internet access is restored automatically
	// whenever the process exits or crashes
	FWPM_SESSION0 session{};
	session.displayData.name = const_cast<wchar_t *>(L"Veyon internet access control");
	session.flags = WfpSessionFlagDynamic;

	HANDLE engine = nullptr;
	auto error = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine);
	if (error != ERROR_SUCCESS)
	{
		vCritical() << "FwpmEngineOpen0() returned" << error;
		return false;
	}

	error = FwpmTransactionBegin0(engine, 0);
	if (error == ERROR_SUCCESS)
	{
		error = addInternetAccessFilters(engine);
	}
	if (error == ERROR_SUCCESS)
	{
		error = FwpmTransactionCommit0(engine);
	}

	if (error != ERROR_SUCCESS)
	{
		vCritical() << "failed to add filters for blocking internet access:" << error;
		// closing the session aborts the pending transaction
		FwpmEngineClose0(engine);
		return false;
	}

	m_internetAccessFilterEngine = engine;

	return true;
}



bool WindowsNetworkFunctions::isInternetAccessBlocked() const
{
	return m_internetAccessFilterEngine != nullptr;
}



bool WindowsNetworkFunctions::configureSocketKeepalive( Socket socket, bool enabled, int idleTime, int interval, int probes )
{
	Q_UNUSED(probes)

	DWORD optval;
	int optlen = sizeof(optval);

	optval = enabled ? 1 : 0;
	if( setsockopt( socket, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>( &optval ), optlen ) != 0 )
	{
		int error = WSAGetLastError();
		vWarning() << "could not set SO_KEEPALIVE" << error;
		return false;
	}

	tcp_keepalive keepalive{};
	keepalive.onoff = enabled ? 1 : 0;
	keepalive.keepalivetime = static_cast<u_long>( idleTime );
	keepalive.keepaliveinterval = static_cast<u_long>( interval );

	DWORD bytesReturned = 0;

	if( WSAIoctl( socket, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), nullptr, 0,
				  &bytesReturned, nullptr, nullptr ) != 0 )
	{
		int error = WSAGetLastError();
		vWarning() << "could not set keepalive parameters" << error;
		return false;
	}

	return true;
}



QNetworkInterface WindowsNetworkFunctions::defaultRouteNetworkInterface()
{
	QNetworkInterface networkInterface;

	for (const auto addressFamily : {AF_INET, AF_INET6})
	{
		PMIB_IPFORWARD_TABLE2 ipForwardTable = nullptr;
		if (GetIpForwardTable2(addressFamily, &ipForwardTable) != NO_ERROR)
		{
			continue;
		}

		for (ULONG i = 0; i < ipForwardTable->NumEntries; ++i)
		{
			const MIB_IPFORWARD_ROW2& row = ipForwardTable->Table[i];

			bool isDefault = false;
			if (addressFamily == AF_INET)
			{
				isDefault =
						row.DestinationPrefix.Prefix.si_family == AF_INET &&
						row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr == 0 &&
						row.DestinationPrefix.PrefixLength == 0;
			}
			else
			{
				const uint8_t* addr = row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte;
				bool allZero = true;
				for (size_t j = 0; j < sizeof(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte); ++j)
				{
					if (addr[j] != 0)
					{
						allZero = false;
						break;
					}
				}
				isDefault =
						row.DestinationPrefix.Prefix.si_family == AF_INET6 &&
						allZero &&
						row.DestinationPrefix.PrefixLength == 0;
			}

			if (isDefault)
			{
				networkInterface = QNetworkInterface::interfaceFromIndex(row.InterfaceIndex);
				break;
			}
		}

		FreeMibTable(ipForwardTable);

		if (networkInterface.isValid())
		{
			break;
		}
	}

	return networkInterface;
}



int WindowsNetworkFunctions::networkInterfaceSpeedInMBitPerSecond(const QNetworkInterface& networkInterface)
{

	MIB_IF_ROW2 ifRow;
	SecureZeroMemory((PVOID) &ifRow, sizeof(MIB_IF_ROW2));

	ifRow.InterfaceIndex = networkInterface.index();

	if (GetIfEntry2(&ifRow) == NO_ERROR)
	{
		return ifRow.TransmitLinkSpeed / (1000*1000);
	}

	return 0;
}



bool WindowsNetworkFunctions::pingIPv4Address(const QString& hostAddress, PingResult* result)
{
	if( result == nullptr )
	{
		return false;
	}

	*result = PingResult::Unknown;

	const IPAddr ipAddress = inet_addr(hostAddress.toLatin1().constData());
	if( ipAddress == INADDR_NONE )
	{
		return false;
	}

	struct IcmpHandleTraits
	{
		using Pointer = HANDLE;
		static Pointer invalidValue() noexcept { return INVALID_HANDLE_VALUE; }
		static void close(Pointer h) noexcept { IcmpCloseHandle(h); }
	};
	using SmartIcmpHandle = UniqueResource<IcmpHandleTraits>;

	const SmartIcmpHandle icmpHandle{IcmpCreateFile()};
	if (icmpHandle.isInvalid())
	{
		return false;
	}

	std::array<char, 6> sendData{'V', 'e', 'y', 'o', 'n', 0};
	std::array<char, sizeof(ICMP_ECHO_REPLY) + sendData.size()> replyBuffer;

	const auto success = IcmpSendEcho(icmpHandle.get(), ipAddress, sendData.data(), sendData.size(),
									  nullptr, replyBuffer.data(), replyBuffer.size(), PingTimeout) > 0 &&
						 reinterpret_cast<ICMP_ECHO_REPLY *>(replyBuffer.data())->Status == IP_SUCCESS;

	const auto error = GetLastError();

	if( success )
	{
		*result = PingResult::ReplyReceived;
		return true;
	}

	if (error == IP_REQ_TIMED_OUT)
	{
		*result = PingResult::TimedOut;
		return true;
	}

	return false;
}



bool WindowsNetworkFunctions::pingIPv6Address(const QString& hostAddress, PingResult* result)
{
	if( result == nullptr )
	{
		return false;
	}

	*result = PingResult::Unknown;

	SOCKADDR_IN6 icmp6LocalAddr{};
	icmp6LocalAddr.sin6_addr = in6addr_any;
	icmp6LocalAddr.sin6_family = AF_INET6;

	SOCKADDR_IN6 icmp6RemoteAddr{};
	struct addrinfo hints{};
	struct addrinfo *res = nullptr;

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;

	if( getaddrinfo(hostAddress.toLatin1().constData(), nullptr, &hints, &res) != 0 )
	{
		return false;
	}

	auto resalloc = res;

	while( res != nullptr )
	{
		if( res->ai_family == AF_INET6 )
		{
			memcpy( &icmp6RemoteAddr, res->ai_addr, res->ai_addrlen );
			icmp6RemoteAddr.sin6_family = AF_INET6;
			break;
		}

		res = res->ai_next;
	}

	freeaddrinfo(resalloc);

	if( icmp6RemoteAddr.sin6_family != AF_INET6 )
	{
		return false;
	}

	const auto icmpFile = Icmp6CreateFile();
	if( icmpFile == INVALID_HANDLE_VALUE )
	{
		return false;
	}

	using ICMPV6_ECHO_REPLY = struct {
		IPV6_ADDRESS_EX Address;
		ULONG Status;
		unsigned int RoundTripTime;
	};

	std::array<char, 6> sendData{'V', 'e', 'y', 'o', 'n', 0};
	std::array<char, sizeof(ICMPV6_ECHO_REPLY) + sendData.size()> replyBuffer;

	const auto success = Icmp6SendEcho2(icmpFile, nullptr, nullptr, nullptr,
										 &icmp6LocalAddr,
										 &icmp6RemoteAddr,
										 sendData.data(), sendData.size(),
										 nullptr, replyBuffer.data(), replyBuffer.size(), PingTimeout) > 0 &&
						 reinterpret_cast<ICMPV6_ECHO_REPLY *>(replyBuffer.data())->Status == IP_SUCCESS;

	const auto error = GetLastError();

	IcmpCloseHandle(icmpFile);

	if( success )
	{
		*result = PingResult::ReplyReceived;
		return true;
	}

	if (error == IP_REQ_TIMED_OUT)
	{
		*result = PingResult::TimedOut;
		return true;
	}

	return false;
}



bool WindowsNetworkFunctions::pingViaUtility(const QString& hostAddress, PingResult* result)
{
	if (result == nullptr)
	{
		return false;
	}

	*result = PingResult::Unknown;

	const QStringList pingArguments = {
		QStringLiteral("-n"), QStringLiteral("1"),
		QStringLiteral("-w"), QString::number(PingTimeout),
		hostAddress
	};

	QProcess pingProcess;
	pingProcess.start(QStringLiteral("ping"), pingArguments);
	if (pingProcess.waitForStarted(PingProcessTimeout))
	{
		if (pingProcess.waitForFinished(PingProcessTimeout))
		{
			if (QString::fromUtf8(pingProcess.readAll()).split(QLatin1Char('\n')).filter(QStringLiteral("=")).size() >= 2)
			{
				*result = PingResult::ReplyReceived;
			}
			else if (pingProcess.exitCode() == 1)
			{
				*result = PingResult::NameResolutionFailed;
			}
			else
			{
				*result = PingResult::TimedOut;
			}
		}
		else
		{
			*result = PingResult::NameResolutionFailed;
		}
		return true;
	}

	return false;
}
