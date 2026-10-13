/*
 * InternetAccessControlFeaturePlugin.cpp - implementation of InternetAccessControlFeaturePlugin class
 *
 * Copyright (c) 2026 Marek
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

#include <QMessageBox>

#include "InternetAccessControlFeaturePlugin.h"
#include "ComputerControlInterface.h"
#include "PlatformNetworkFunctions.h"
#include "VeyonServerInterface.h"


InternetAccessControlFeaturePlugin::InternetAccessControlFeaturePlugin( QObject* parent ) :
	QObject( parent ),
	m_blockInternetAccessFeature( QStringLiteral( "InternetAccessBlock" ),
								  Feature::Flag::Action | Feature::Flag::AllComponents,
								  Feature::Uid( "b29584f5-9579-4ee8-b923-8b5ff975cb7d" ),
								  Feature::Uid(),
								  tr( "Block internet" ), {},
								  tr( "Click this button to block internet access on all computers. "
									  "The local network remains accessible." ),
								  QStringLiteral(":/internetaccesscontrol/internet-access-blocked.png") ),
	m_unblockInternetAccessFeature( QStringLiteral( "InternetAccessUnblock" ),
									Feature::Flag::Action | Feature::Flag::AllComponents,
									Feature::Uid( "db164a59-0730-43b0-9830-a1b7d7d6e5a4" ),
									Feature::Uid(),
									tr( "Unblock internet" ), {},
									tr( "Click this button to restore internet access on all computers." ),
									QStringLiteral(":/internetaccesscontrol/internet-access-unblocked.png") ),
	m_features( { m_blockInternetAccessFeature, m_unblockInternetAccessFeature } )
{
	// collect failures of multiple computers and report them in a single message
	m_failureReportTimer.setSingleShot( true );
	m_failureReportTimer.setInterval( FailureReportDelay );
	connect( &m_failureReportTimer, &QTimer::timeout, this, &InternetAccessControlFeaturePlugin::reportFailures );
}



bool InternetAccessControlFeaturePlugin::controlFeature( Feature::Uid featureUid, Operation operation,
														 const QVariantMap& arguments,
														 const ComputerControlInterfaceList& computerControlInterfaces )
{
	Q_UNUSED(arguments)

	if( hasFeature( featureUid ) == false )
	{
		return false;
	}

	if( featureUid == m_blockInternetAccessFeature.uid() && operation == Operation::Start )
	{
		// do not block internet access on the master computer itself if it is just
		// listed as one of multiple room computers
		auto blockControlInterfaces = computerControlInterfaces;
		if( blockControlInterfaces.size() > 1 )
		{
			blockControlInterfaces.removeLocalHostInterfaces();
		}

		sendFeatureMessage( FeatureMessage{ m_blockInternetAccessFeature.uid() }, blockControlInterfaces );

		return true;
	}

	if( ( featureUid == m_blockInternetAccessFeature.uid() && operation == Operation::Stop ) ||
		( featureUid == m_unblockInternetAccessFeature.uid() && operation == Operation::Start ) )
	{
		sendFeatureMessage( FeatureMessage{ m_unblockInternetAccessFeature.uid() }, computerControlInterfaces );

		return true;
	}

	return false;
}



bool InternetAccessControlFeaturePlugin::handleFeatureMessage( ComputerControlInterface::Pointer computerControlInterface,
															   const FeatureMessage& message )
{
	if( hasFeature( message.featureUid() ) == false )
	{
		return false;
	}

	if( message.argument( Argument::Success ).toBool() == false )
	{
		const auto hostName = computerControlInterface->computer().hostName();
		if( message.featureUid() == m_blockInternetAccessFeature.uid() )
		{
			m_failedBlockHosts.append( hostName );
		}
		else
		{
			m_failedUnblockHosts.append( hostName );
		}

		if( m_failureReportTimer.isActive() == false )
		{
			m_failureReportTimer.start();
		}
	}

	return true;
}



bool InternetAccessControlFeaturePlugin::handleFeatureMessage( VeyonServerInterface& server,
															   const MessageContext& messageContext,
															   const FeatureMessage& message )
{
	if( hasFeature( message.featureUid() ) == false )
	{
		return false;
	}

	const auto blocked = message.featureUid() == m_blockInternetAccessFeature.uid();
	const auto success = VeyonCore::platform().networkFunctions().setInternetAccessBlocked( blocked );

	return server.sendFeatureMessageReply( messageContext,
										   FeatureMessage{ message.featureUid() }
										   .addArgument( Argument::Success, success ) );
}



void InternetAccessControlFeaturePlugin::reportFailures()
{
	QStringList messages;

	if( m_failedBlockHosts.isEmpty() == false )
	{
		messages.append( tr( "Internet access could not be blocked on the following computers:\n%1" )
						 .arg( m_failedBlockHosts.join( QLatin1Char('\n') ) ) );
	}

	if( m_failedUnblockHosts.isEmpty() == false )
	{
		messages.append( tr( "Internet access could not be restored on the following computers:\n%1" )
						 .arg( m_failedUnblockHosts.join( QLatin1Char('\n') ) ) );
	}

	m_failedBlockHosts.clear();
	m_failedUnblockHosts.clear();

	if( messages.isEmpty() == false )
	{
		QMessageBox::warning( nullptr, tr( "Internet access control" ), messages.join( QStringLiteral("\n\n") ) );
	}
}



bool InternetAccessControlFeaturePlugin::isFeatureActive( VeyonServerInterface& server, Feature::Uid featureUid ) const
{
	Q_UNUSED(server)

	return featureUid == m_blockInternetAccessFeature.uid() &&
		   VeyonCore::platform().networkFunctions().isInternetAccessBlocked();
}
