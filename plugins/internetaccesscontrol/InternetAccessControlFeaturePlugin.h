/*
 * InternetAccessControlFeaturePlugin.h - declaration of InternetAccessControlFeaturePlugin class
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

#pragma once

#include <QStringList>
#include <QTimer>

#include "FeatureProviderInterface.h"

class InternetAccessControlFeaturePlugin : public QObject, FeatureProviderInterface, PluginInterface
{
	Q_OBJECT
	Q_PLUGIN_METADATA(IID "io.veyon.Veyon.Plugins.InternetAccessControl")
	Q_INTERFACES(PluginInterface FeatureProviderInterface)
public:
	explicit InternetAccessControlFeaturePlugin( QObject* parent = nullptr );
	~InternetAccessControlFeaturePlugin() override = default;

	Plugin::Uid uid() const override
	{
		return Plugin::Uid{ QStringLiteral("0e103e5c-b5cd-433c-9e27-7cdde2d54f7d") };
	}

	QVersionNumber version() const override
	{
		return QVersionNumber( 1, 0 );
	}

	QString name() const override
	{
		return QStringLiteral("InternetAccessControl");
	}

	QString description() const override
	{
		return tr( "Block and unblock internet access of a computer" );
	}

	QString vendor() const override
	{
		return QStringLiteral("Veyon Community");
	}

	QString copyright() const override
	{
		return QStringLiteral("Marek");
	}

	const FeatureList& featureList() const override
	{
		return m_features;
	}

	bool controlFeature( Feature::Uid featureUid, Operation operation, const QVariantMap& arguments,
						const ComputerControlInterfaceList& computerControlInterfaces ) override;

	bool handleFeatureMessage( ComputerControlInterface::Pointer computerControlInterface,
							   const FeatureMessage& message ) override;

	bool handleFeatureMessage( VeyonServerInterface& server,
							   const MessageContext& messageContext,
							   const FeatureMessage& message ) override;

	bool isFeatureActive( VeyonServerInterface& server, Feature::Uid featureUid ) const override;

private:
	enum class Argument
	{
		Success
	};

	static constexpr int FailureReportDelay = 1000;

	void reportFailures();

	const Feature m_blockInternetAccessFeature;
	const Feature m_unblockInternetAccessFeature;
	const FeatureList m_features;

	QStringList m_failedBlockHosts;
	QStringList m_failedUnblockHosts;
	QTimer m_failureReportTimer;

};
