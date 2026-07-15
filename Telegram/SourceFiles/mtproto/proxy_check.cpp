/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy_check.h"

#include "mtproto/facade.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/mtproto_proxy_data.h"

#include <QtCore/QTimer>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpSocket>

namespace MTP {
namespace {

constexpr auto kProbeTimeout = 1 * crl::time(1000);

void probeTcp(
		const QString &host,
		int port,
		QNetworkProxy proxy,
		Fn<void(bool alive)> callback) {
	const auto completed = std::make_shared<bool>(false);
	const auto socket = new QTcpSocket;
	socket->setProxy(proxy);

	QObject::connect(socket, &QTcpSocket::connected, [=] {
		if (*completed) return;
		*completed = true;
		socket->disconnectFromHost();
		socket->deleteLater();
		callback(true);
	});
	QObject::connect(socket, &QTcpSocket::errorOccurred, [=] {
		if (*completed) return;
		*completed = true;
		socket->deleteLater();
		callback(false);
	});

	QTimer::singleShot(kProbeTimeout, socket, [=] {
		if (*completed) return;
		*completed = true;
		socket->abort();
		socket->deleteLater();
		callback(false);
	});

	socket->connectToHost(host, port);
}

} // namespace

using Connection = details::AbstractConnection;

void ResetProxyCheckers(
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6) {
	v4 = nullptr;
	v6 = nullptr;
}

void DropProxyChecker(
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6,
		not_null<Connection*> raw) {
	if (v4.get() == raw) {
		v4 = nullptr;
	} else if (v6.get() == raw) {
		v6 = nullptr;
	}
}

bool HasProxyCheckers(
		const ProxyCheckConnection &v4,
		const ProxyCheckConnection &v6) {
	return v4 || v6;
}

void StartProxyCheck(
		not_null<Instance*> mtproto,
		const ProxyData &proxy,
		bool tryIPv6,
		ProxyCheckConnection &v4,
		ProxyCheckConnection &v6,
		Fn<void(Connection *raw, int ping)> done,
		Fn<void(Connection *raw)> fail,
		ProxyData::ClientHello clientHello) {
	using Variants = DcOptions::Variants;

	ResetProxyCheckers(v4, v6);
	const auto connType = (proxy.type == ProxyData::Type::Http)
		? Variants::Http
		: Variants::Tcp;
	const auto dcId = mtproto->mainDcId();
	const auto setup = [&](ProxyCheckConnection &checker, const bytes::vector &secret) {
		const auto proxyWithHello = ProxyData{
			proxy.type,
			proxy.host,
			proxy.port,
			proxy.user,
			proxy.password,
			clientHello,
		};
		checker = Connection::Create(
			mtproto,
			connType,
			QThread::currentThread(),
			secret,
			proxyWithHello);
		const auto raw = checker.get();
		raw->connect(raw, &Connection::connected, [=] {
			if (done) {
				done(raw, raw->pingTime());
			}
		});
		const auto failed = [=] {
			if (fail) {
				fail(raw);
			}
		};
		raw->connect(raw, &Connection::disconnected, failed);
		raw->connect(raw, &Connection::error, failed);
	};
	if (proxy.type == ProxyData::Type::Mtproto) {
		const auto secret = proxy.secretFromMtprotoPassword();
		setup(v4, secret);
		const auto raw = v4.get();
		probeTcp(
			proxy.host,
			proxy.port,
			QNetworkProxy::NoProxy,
			[=](bool alive) {
				if (!alive) {
					if (fail) {
						fail(raw);
					}
					return;
				}
				raw->connectToServer(
					proxy.host,
					proxy.port,
					secret,
					dcId,
					false);
			});
		return;
	}
	const auto options = mtproto->dcOptions().lookup(
		dcId,
		DcType::Regular,
		true);
	const auto tryConnect = [&](ProxyCheckConnection &checker, Variants::Address address) {
		const auto &list = options.data[address][connType];
		if (list.empty() || ((address == Variants::IPv6) && !tryIPv6)) {
			checker = nullptr;
			return;
		}
		const auto &endpoint = list.front();
		const auto host = QString::fromStdString(endpoint.ip);
		const auto port = endpoint.port;
		const auto secret = endpoint.secret;
		setup(checker, secret);
		const auto raw = checker.get();
		probeTcp(
			host,
			port,
			ToNetworkProxy(proxy),
			[=](bool alive) {
				if (!alive) {
					if (fail) {
						fail(raw);
					}
					return;
				}
				raw->connectToServer(
					host,
					port,
					secret,
					dcId,
					false);
			});
	};
	tryConnect(v4, Variants::IPv4);
	tryConnect(v6, Variants::IPv6);
}

} // namespace MTP
