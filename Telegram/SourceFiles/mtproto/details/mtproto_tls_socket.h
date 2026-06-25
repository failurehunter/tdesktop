/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_abstract_socket.h"
#include "mtproto/mtproto_proxy_data.h"

namespace MTP::details {

class TlsSocket final : public AbstractSocket {
public:
	struct PskData {
		bytes::vector ticket;
		uint32 ticketAgeAdd = 0;
		crl::time timestamp = 0;
	};

	TlsSocket(
		not_null<QThread*> thread,
		const bytes::vector &secret,
		const QNetworkProxy &proxy,
		bool protocolForFiles,
		MTP::ProxyData::ClientHello clientHello = MTP::ProxyData::ClientHello::Default);

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;

private:

private:

	enum class State {
		NotConnected,
		Connecting,
		WaitingHello,
		Connected,
		Error,
	};

	[[nodiscard]] bytes::const_span domainFromSecret() const;
	[[nodiscard]] bytes::const_span keyFromSecret() const;

	void plainConnected();
	void plainDisconnected();
	void plainReadyRead();
	void handleError(int errorCode = 0);
	[[nodiscard]] bool requiredHelloPartReady() const;
	void readHello();
	void checkHelloParts12();
	void checkHelloDigest();
	[[nodiscard]] int SkipTlsRecords(bytes::const_span data) const;
	void readData();
	[[nodiscard]] bool checkNextPacket();
	void shiftIncomingBy(int amount);
	void parseNewSessionTickets();
	bool parseNewSessionTicketData(bytes::const_span data);

	const bytes::vector _secret;
	const MTP::ProxyData::ClientHello _clientHello;
	QTcpSocket _socket;
	State _state = State::NotConnected;
	QByteArray _incoming;
	int _incomingGoodDataOffset = 0;
	int _incomingGoodDataLimit = 0;
	int16 _serverHelloLength = 0;
	std::optional<PskData> _psk;

};

} // namespace MTP::details
