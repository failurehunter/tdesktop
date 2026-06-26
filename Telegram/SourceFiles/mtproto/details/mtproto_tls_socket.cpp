/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_tls_socket.h"

#include "mtproto/details/mtproto_tcp_socket.h"
#include "base/openssl_help.h"
#include "base/bytes.h"
#include "base/invoke_queued.h"
#include "base/random.h"
#include "base/unixtime.h"

#include <QtCore/QtEndian>
#include <range/v3/algorithm/reverse.hpp>
#include <cstring>

namespace MTP::details {
namespace {

constexpr auto kMaxGrease = 8;
constexpr auto kClientHelloLimit = 2048;
constexpr auto kHelloDigestLength = 32;
constexpr auto kLengthSize = sizeof(uint16);
const auto kServerHelloPart1 = qstr("\x16\x03\x03");
const auto kServerHelloPart3 = qstr("\x14\x03\x03\x00\x01\x01\x17\x03\x03");
constexpr auto kServerHelloDigestPosition = 11;
const auto kServerHeader = qstr("\x17\x03\x03");
constexpr auto kClientPartSize = 2878;
const auto kClientPrefix = qstr("\x14\x03\x03\x00\x01\x01");
const auto kClientHeader = qstr("\x17\x03\x03");

constexpr auto kPskKeyExchangeModePskKe = 0x01;
constexpr auto kPskExtensionType = 0x0029;
constexpr auto kPskKeyExchangeModesType = 0x002d;
constexpr auto kSha256Size = 32;

// Precomputed SHA-256("") for PSK binder computation
static const bytes::vector kEmptySha256Hash = [] {
    bytes::vector h(kSha256Size);
    SHA256(nullptr, 0, reinterpret_cast<uint8_t*>(h.data()));
    return h;
}();

// HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM)
[[nodiscard]] bytes::vector HkdfExtractSha256(
        bytes::const_span salt,
        bytes::const_span ikm) {
    auto result = bytes::vector(kSha256Size);
    unsigned int len = kSha256Size;
    HMAC(EVP_sha256(),
        reinterpret_cast<const unsigned char*>(salt.data()),
        salt.size(),
        reinterpret_cast<const unsigned char*>(ikm.data()),
        ikm.size(),
        reinterpret_cast<unsigned char*>(result.data()),
        &len);
    return result;
}

// HKDF-Expand(PRK, info, length)
[[nodiscard]] bytes::vector HkdfExpandSha256(
        bytes::const_span prk,
        bytes::const_span info,
        size_t length) {
    auto result = bytes::vector(length);
    unsigned int len = 0;
    auto t = QByteArray();
    for (uint8_t i = 1; result.size() > t.size(); ++i) {
        len = kSha256Size;
        auto hmacKey = QByteArray(
            reinterpret_cast<const char*>(prk.data()), prk.size());
        auto msg = t;
        msg.append(reinterpret_cast<const char*>(info.data()), info.size());
        msg.append(static_cast<char>(i));
        auto block = bytes::vector(kSha256Size);
        HMAC(EVP_sha256(),
            reinterpret_cast<const unsigned char*>(hmacKey.data()), hmacKey.size(),
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
            reinterpret_cast<unsigned char*>(block.data()),
            &len);
        t.append(reinterpret_cast<const char*>(block.data()), kSha256Size);
    }
    std::memcpy(result.data(), t.constData(), length);
    return result;
}

// HKDF-Expand-Label(Secret, Label, Context, Length)
[[nodiscard]] bytes::vector HkdfExpandLabel(
        bytes::const_span secret,
        const char *label,
        bytes::const_span context,
        size_t length) {
    const QByteArray prefix = "tls13 ";
    const auto labelLen = strlen(label);
    const uint8_t labelPrefixLen = prefix.size() + labelLen;
    const uint8_t contextLen = static_cast<uint8_t>(context.size());
    QByteArray info;
    info.append(static_cast<char>((length >> 8) & 0xFF));
    info.append(static_cast<char>(length & 0xFF));
    info.append(static_cast<char>(labelPrefixLen));
    info.append(prefix.constData(), prefix.size());
    info.append(label, labelLen);
    info.append(static_cast<char>(contextLen));
    if (context.size() > 0) {
        info.append(reinterpret_cast<const char*>(context.data()), context.size());
    }
    return HkdfExpandSha256(secret,
        bytes::make_span(info.data(), info.size()),
        length);
}

// Compute PSK binder (RFC 8446 4.2.11.2)
[[nodiscard]] bytes::vector ComputePskBinder(
        bytes::const_span pskSecret,
        bytes::const_span truncatedCH) {
    const auto binderContext = bytes::make_span(
        reinterpret_cast<const bytes::type*>(kEmptySha256Hash.data()),
        kSha256Size);
    auto earlySecret = HkdfExtractSha256(binderContext, pskSecret);
    auto binderKey = HkdfExpandLabel(
        bytes::make_span(earlySecret),
        "res binder",
        binderContext,
        kSha256Size);
    uint8_t transcriptHash[kSha256Size];
    SHA256(reinterpret_cast<const unsigned char*>(truncatedCH.data()),
        truncatedCH.size(), transcriptHash);
    auto binder = bytes::vector(kSha256Size);
    unsigned int len = kSha256Size;
    HMAC(EVP_sha256(),
        reinterpret_cast<const unsigned char*>(binderKey.data()),
        binderKey.size(),
        transcriptHash,
        kSha256Size,
        reinterpret_cast<unsigned char*>(binder.data()),
        &len);
    return binder;
}


using BigNum = openssl::BigNum;
using BigNumContext = openssl::Context;

[[nodiscard]] MTPTlsClientHello PrepareClientHelloRules() {
	using Scope = QVector<MTPTlsBlock>;
	using Permutation = std::vector<Scope>;
	using StackElement = std::variant<Scope, Permutation>;
	auto stack = std::vector<StackElement>();
	const auto pushToBack = [&](MTPTlsBlock &&block) {
		Expects(!stack.empty());

		if (const auto scope = std::get_if<Scope>(&stack.back())) {
			scope->push_back(std::move(block));
		} else {
			auto &permutation = v::get<Permutation>(stack.back());
			Assert(!permutation.empty());
			permutation.back().push_back(std::move(block));
		}
	};
	const auto S = [&](QByteArray data) {
		pushToBack(MTP_tlsBlockString(MTP_bytes(data)));
	};
	const auto Z = [&](int length) {
		pushToBack(MTP_tlsBlockZero(MTP_int(length)));
	};
	const auto G = [&](int seed) {
		pushToBack(MTP_tlsBlockGrease(MTP_int(seed)));
	};
	const auto R = [&](int length) {
		pushToBack(MTP_tlsBlockRandom(MTP_int(length)));
	};
	const auto D = [&] {
		pushToBack(MTP_tlsBlockDomain());
	};
	const auto K = [&] {
		pushToBack(MTP_tlsBlockPublicKey());
	};
	const auto M = [&] {
		pushToBack(MTP_tlsBlockM());
	};
	const auto E = [&] {
		pushToBack(MTP_tlsBlockE());
	};
	const auto P = [&] {
		pushToBack(MTP_tlsBlockPadding());
	};
	const auto OpenScope = [&] {
		stack.emplace_back(Scope());
	};
	const auto CloseScope = [&] {
		Expects(stack.size() > 1);
		Expects(v::is<Scope>(stack.back()));

		const auto blocks = std::move(v::get<Scope>(stack.back()));
		stack.pop_back();
		pushToBack(MTP_tlsBlockScope(MTP_vector<MTPTlsBlock>(blocks)));
	};
	const auto OpenPermutation = [&] {
		stack.emplace_back(Permutation());
	};
	const auto ClosePermutation = [&] {
		Expects(stack.size() > 1);
		Expects(v::is<Permutation>(stack.back()));

		const auto list = std::move(v::get<Permutation>(stack.back()));
		stack.pop_back();

		const auto wrapped = list | ranges::views::transform([](
				const QVector<MTPTlsBlock> &elements) {
			return MTP_vector<MTPTlsBlock>(elements);
		}) | ranges::to<QVector<MTPVector<MTPTlsBlock>>>();

		pushToBack(MTP_tlsBlockPermutation(
			MTP_vector<MTPVector<MTPTlsBlock>>(wrapped)));
	};
	const auto StartPermutationElement = [&] {
		Expects(stack.size() > 1);
		Expects(v::is<Permutation>(stack.back()));

		v::get<Permutation>(stack.back()).emplace_back();
	};
	const auto Finish = [&] {
		Expects(stack.size() == 1);
		Expects(v::is<Scope>(stack.back()));

		return v::get<Scope>(stack.back());
	};

	stack.emplace_back(Scope());

	S("\x16\x03\x01"_q);
	OpenScope();
	S("\x01\x00"_q);
	OpenScope();
	S("\x03\x03"_q);
	Z(32);
	S("\x20"_q);
	R(32);
	S("\x00\x20"_q);
	G(0);
	S(""
		"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
		"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
		""_q);
	OpenScope();
	G(2);
	S("\x00\x00"_q);
	OpenPermutation(); {
		StartPermutationElement(); {
			S("\x00\x00"_q);
			OpenScope();
			OpenScope();
			S("\x00"_q);
			OpenScope();
			D();
			CloseScope();
			CloseScope();
			CloseScope();
		}
		StartPermutationElement(); {
			S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x0a\x00\x0c\x00\x0a"_q);
			G(4);
			S("\x11\xec\x00\x1d\x00\x17\x00\x18"_q);
		}
		StartPermutationElement(); {
			S("\x00\x0b\x00\x02\x01\x00"_q);
		}
		StartPermutationElement(); {
			S(""
				"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03"
				"\x08\x05\x05\x01\x08\x06\x06\x01"_q);
		}
		StartPermutationElement(); {
			S(""
				"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70"
				"\x2f\x31\x2e\x31"_q);
		}
		StartPermutationElement(); {
			S("\x00\x12\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x17\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x1b\x00\x03\x02\x00\x02"_q);
		}
		StartPermutationElement(); {
			S("\x00\x23\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x2b\x00\x07\x06"_q);
			G(6);
			S("\x03\x04\x03\x03"_q);
		}
		StartPermutationElement(); {
			S("\x00\x2d\x00\x02\x01\x01"_q);
		}
		StartPermutationElement(); {
			S("\x00\x33\x04\xef\x04\xed"_q);
			G(4);
			S("\x00\x01\x00\x11\xec\x04\xc0"_q);
			M();
			K();
			S("\x00\x1d\x00\x20"_q);
			K();
		}
		StartPermutationElement(); {
			S("\x44\xcd\x00\x05\x00\x03\x02\x68\x32"_q);
		}
		StartPermutationElement(); {
			S("\xfe\x0d"_q);
			OpenScope();
			S("\x00\x00\x01\x00\x01"_q);
			R(1);
			S("\x00\x20"_q);
			R(32);
			OpenScope();
			E();
			CloseScope();
			CloseScope();
		}
		StartPermutationElement(); {
			S("\xff\x01\x00\x01\x00"_q);
		}
	} ClosePermutation();
	G(3);
	S("\x00\x01\x00"_q);
	P();
	CloseScope();
	CloseScope();
	CloseScope();

	return MTP_tlsClientHello(MTP_vector<MTPTlsBlock>(Finish()));
}

[[nodiscard]] bytes::vector PrepareGreases() {
	auto result = bytes::vector(kMaxGrease);
	bytes::set_random(result);
	for (auto &byte : result) {
		byte = bytes::type((uchar(byte) & 0xF0) + 0x0A);
	}
	static_assert(kMaxGrease % 2 == 0);
	for (auto i = 0; i != kMaxGrease; i += 2) {
		if (result[i] == result[i + 1]) {
			result[i + 1] = bytes::type(uchar(result[i + 1]) ^ 0x10);
		}
	}
	return result;
}

[[nodiscard]] bytes::vector GeneratePublicKey() {
	const auto context = EVP_PKEY_CTX_new_id(NID_ED25519, nullptr);
	if (!context) {
		return {};
	}
	const auto guardContext = gsl::finally([&] {
		EVP_PKEY_CTX_free(context);
	});

	if (EVP_PKEY_keygen_init(context) <= 0) {
		return {};
	}

	auto key = (EVP_PKEY*)nullptr;
	if (EVP_PKEY_keygen(context, &key) <= 0) {
		return {};
	}
	const auto guardKey = gsl::finally([&] {
		EVP_PKEY_free(key);
	});

	auto length = size_t(0);
	if (!EVP_PKEY_get_raw_public_key(key, nullptr, &length)) {
		return {};
	}
	Assert(length == 32);

	auto result = bytes::vector(length);
	const auto code = EVP_PKEY_get_raw_public_key(
		key,
		reinterpret_cast<unsigned char *>(result.data()),
		&length);
	if (!code) {
		return {};
	}
	return result;
}

struct ClientHello {
	QByteArray data;
	QByteArray digest;
};

class Generator {
public:
	Generator(
		const MTPTlsClientHello &rules,
		bytes::const_span domain,
		bytes::const_span key);
	[[nodiscard]] ClientHello take();

private:
	class Part final {
	public:
		explicit Part(
			bytes::const_span domain,
			const bytes::vector &greases);

		[[nodiscard]] bytes::span grow(int size);
		void writeBlocks(const QVector<MTPTlsBlock> &blocks);
		void writeBlock(const MTPTlsBlock &data);
		void writeBlock(const MTPDtlsBlockString &data);
		void writeBlock(const MTPDtlsBlockZero &data);
		void writeBlock(const MTPDtlsBlockGrease &data);
		void writeBlock(const MTPDtlsBlockRandom &data);
		void writeBlock(const MTPDtlsBlockDomain &data);
		void writeBlock(const MTPDtlsBlockPublicKey &data);
		void writeBlock(const MTPDtlsBlockScope &data);
		void writeBlock(const MTPDtlsBlockPermutation &data);
		void writeBlock(const MTPDtlsBlockM &data);
		void writeBlock(const MTPDtlsBlockE &data);
		void writeBlock(const MTPDtlsBlockPadding &data);
		void finalize(bytes::const_span key);
		[[nodiscard]] QByteArray extractDigest() const;

		[[nodiscard]] bool error() const;
		[[nodiscard]] QByteArray take();

	private:
		void writeDigest(bytes::const_span key);
		void injectTimestamp();

		bytes::const_span _domain;
		const bytes::vector &_greases;
		QByteArray _result;
		const char *_data = nullptr;
		int _digestPosition = -1;
		bool _error = false;

	};

	bytes::vector _greases;
	Part _result;
	QByteArray _digest;

};

Generator::Part::Part(
	bytes::const_span domain,
	const bytes::vector &greases)
: _domain(domain)
, _greases(greases) {
	_result.reserve(kClientHelloLimit);
	_data = _result.constData();
}

bool Generator::Part::error() const {
	return _error;
}

QByteArray Generator::Part::take() {
	Expects(_error || _result.constData() == _data);

	return _error ? QByteArray() : std::move(_result);
}

bytes::span Generator::Part::grow(int size) {
	if (_error
		|| size <= 0
		|| _result.size() + size > kClientHelloLimit) {
		_error = true;
		return bytes::span();
	}

	const auto offset = _result.size();
	_result.resize(offset + size);
	return bytes::make_detached_span(_result).subspan(offset);
}

void Generator::Part::writeBlocks(const QVector<MTPTlsBlock> &blocks) {
	for (const auto &block : blocks) {
		writeBlock(block);
	}
}

void Generator::Part::writeBlock(const MTPTlsBlock &data) {
	data.match([&](const auto &data) {
		writeBlock(data);
	});
}

void Generator::Part::writeBlock(const MTPDtlsBlockString &data) {
	const auto &bytes = data.vdata().v;
	const auto storage = grow(bytes.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, bytes::make_span(bytes));
}

void Generator::Part::writeBlock(const MTPDtlsBlockZero &data) {
	const auto length = data.vlength().v;
	const auto already = _result.size();
	const auto storage = grow(length);
	if (storage.empty()) {
		return;
	}
	if (length == kHelloDigestLength && _digestPosition < 0) {
		_digestPosition = already;
	}
	bytes::set_with_const(storage, bytes::type(0));
}

void Generator::Part::writeBlock(const MTPDtlsBlockGrease &data) {
	const auto seed = data.vseed().v;
	if (seed < 0 || seed >= _greases.size()) {
		_error = true;
		return;
	}
	const auto storage = grow(2);
	if (storage.empty()) {
		return;
	}
	bytes::set_with_const(storage, _greases[seed]);
}

void Generator::Part::writeBlock(const MTPDtlsBlockRandom &data) {
	const auto length = data.vlength().v;
	const auto storage = grow(length);
	if (storage.empty()) {
		return;
	}
	bytes::set_random(storage);
}

void Generator::Part::writeBlock(const MTPDtlsBlockDomain &data) {
	const auto storage = grow(_domain.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, _domain);
}

void Generator::Part::writeBlock(const MTPDtlsBlockPublicKey &data) {
	const auto key = GeneratePublicKey();
	const auto storage = grow(key.size());
	if (storage.empty()) {
		return;
	}
	bytes::copy(storage, key);
}

void Generator::Part::writeBlock(const MTPDtlsBlockScope &data) {
	const auto storage = grow(kLengthSize);
	if (storage.empty()) {
		return;
	}
	const auto already = _result.size();
	writeBlocks(data.ventries().v);
	const auto length = qToBigEndian(uint16(_result.size() - already));
	bytes::copy(storage, bytes::object_as_span(&length));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPermutation &data) {
	auto list = std::vector<QByteArray>();
	list.reserve(data.ventries().v.size());
	for (const auto &inner : data.ventries().v) {
		auto part = Part(_domain, _greases);
		part.writeBlocks(inner.v);
		if (part.error()) {
			_error = true;
			return;
		}
		list.push_back(part.take());
	}
	ranges::shuffle(list);
	for (const auto &element : list) {
		const auto storage = grow(element.size());
		if (storage.empty()) {
			return;
		}
		bytes::copy(storage, bytes::make_span(element));
	}
}

void Generator::Part::writeBlock(const MTPDtlsBlockM &data) {
	constexpr auto kElements = 384;
	constexpr auto kAdded = 32;

	const auto storage = grow(kElements * 3 + kAdded);
	if (storage.empty()) {
		return;
	}

	auto random = bytes::vector(kElements * 8 + kAdded);
	bytes::set_random(random);

	auto chars = reinterpret_cast<char*>(storage.data());
	const auto ints = reinterpret_cast<const uint32*>(random.data());
	for (auto i = 0; i < kElements; ++i) {
		const auto a = int(ints[i * 2] % 3329);
		const auto b = int(ints[i * 2 + 1] % 3329);
		*chars++ = (char)(a & 255);
		*chars++ = (char)((a >> 8) + ((b & 15) << 4));
		*chars++ = (char)(b >> 4);
	}
	bytes::set_random(storage.subspan(kElements * 3));
}

void Generator::Part::writeBlock(const MTPDtlsBlockE &data) {
	const auto lengths = std::array{ 144, 176, 208, 240 };
	const auto length = lengths[base::RandomIndex(lengths.size())];
	writeBlock(MTP_tlsBlockRandom(MTP_int(length)));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPadding &data) {
	const auto length = int(_result.size());
	if (length < 513) {
		const auto zero = MTP_tlsBlockZero(MTP_int(513 - length));
		writeBlock(MTP_tlsBlockString(MTP_bytes("\x00\x15"_q)));
		writeBlock(MTP_tlsBlockScope(MTP_vector<MTPTlsBlock>(1, zero)));
	}
}

void Generator::Part::finalize(bytes::const_span key) {
	if (_error) {
		return;
	} else if (_digestPosition < 0) {
		_error = true;
		return;
	}
	writeDigest(key);
	injectTimestamp();
}

QByteArray Generator::Part::extractDigest() const {
	if (_digestPosition < 0) {
		return {};
	}
	return _result.mid(_digestPosition, kHelloDigestLength);
}

void Generator::Part::writeDigest(bytes::const_span key) {
	Expects(_digestPosition >= 0);

	bytes::copy(
		bytes::make_detached_span(_result).subspan(_digestPosition),
		openssl::HmacSha256(key, bytes::make_span(_result)));
}

void Generator::Part::injectTimestamp() {
	Expects(_digestPosition >= 0);

	const auto storage = bytes::make_detached_span(_result).subspan(
		_digestPosition + kHelloDigestLength - sizeof(int32),
		sizeof(int32));
	auto already = int32();
	bytes::copy(bytes::object_as_span(&already), storage);
	already ^= qToLittleEndian(int32(base::unixtime::http_now()));
	bytes::copy(storage, bytes::object_as_span(&already));
}

Generator::Generator(
	const MTPTlsClientHello &rules,
	bytes::const_span domain,
	bytes::const_span key)
: _greases(PrepareGreases())
, _result(domain, _greases) {
	_result.writeBlocks(rules.data().vblocks().v);
	_result.finalize(key);
}

ClientHello Generator::take() {
	auto digest = _result.extractDigest();
	return { _result.take(), std::move(digest) };
}

[[nodiscard]] ClientHello PrepareClientHello(
		const MTPTlsClientHello &rules,
		bytes::const_span domain,
		bytes::const_span key) {
	return Generator(rules, domain, key).take();
}

[[nodiscard]] ClientHello PrepareBoringSSLClientHello(
		bytes::const_span domain,
		bytes::const_span key,
		const std::optional<TlsSocket::PskData> &psk) {
	// Mimics Chrome 149 / BoringSSL ClientHello (mtproxy_tls2.py build_client_hello)
	// Returns { record (full TLS record), digest (32-byte HMAC for server hello verification) }

	const auto u16be = [&](uint16 v) {
		const auto b = qToBigEndian(v);
		return QByteArray(reinterpret_cast<const char*>(&b), 2);
	};
	const auto with16 = [&](const QByteArray &d) {
		return u16be(d.size()).append(d);
	};
	const auto ext = [&](uint16 t, const QByteArray &p) {
		return u16be(t).append(with16(p));
	};

	// GREASE seed: 6 bytes, each forced to 0x?A pattern
	auto seed = bytes::vector(6);
	base::RandomFill(seed.data(), seed.size());
	for (int i = 0; i < 6; ++i) {
		seed[i] = static_cast<bytes::type>(
			(static_cast<uint8_t>(seed[i]) & 0xF0) | 0x0A);
	}
	const auto gv = [&](int i) -> char {
		return char((static_cast<uint8_t>(seed[i]) & 0xF0) | 0x0A);
	};
	const auto g = [&](int i) { char c = gv(i); return QByteArray(2, c); };

	// === Cipher Suites (Chrome 149 no-AES-HW order) ===
	// GREASE + 15 suites: 1303, 1301, 1302, cca9, cca8, c02b, c02f, c02c, c030, c013, c014, 009c, 009d, 002f, 0035
	const auto ciphers = g(0).append(
		"\x13\x03\x13\x01\x13\x02\xcc\xa9\xcc\xa8"
		"\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xc0\x13\xc0\x14"
		"\x00\x9c\x00\x9d\x00\x2f\x00\x35", 30);  // 2 + 28 = 30 bytes (15 suites)

	// === Extensions ===

	// SNI (always first, not permuted)
	const auto domainStr = QByteArray(
		reinterpret_cast<const char*>(domain.data()), domain.size());
	const auto sniExt = ext(0x0000,
		with16(QByteArray(1, char(0)).append(with16(domainStr))));  // server_name_list + type=host_name

	// Mandatory TLS 1.3 extensions (added to permutable list)
	// supported_versions: [GREASE, TLS1.3, TLS1.2]
	const auto svExt = ext(0x002b,
		QByteArray(1, char(0x06)).append(g(1)).append("\x03\x04\x03\x03", 4));

	// supported_groups: [GREASE, X25519MLKEM768, x25519, secp256r1, secp384r1]
	const auto sgExt = ext(0x000a, with16(
		g(3).append("\x11\xec\x00\x1d\x00\x17\x00\x18", 8)));

	// key_share: GREASE(0-len key) + X25519MLKEM768(1216B random) + x25519(32B random)
	auto x25519Pub = bytes::vector(32);
	base::RandomFill(x25519Pub.data(), x25519Pub.size());
	auto pqKey = bytes::vector(1216);
	base::RandomFill(pqKey.data(), pqKey.size());
	const auto ksExt = ext(0x0033, with16(
		g(3)                                           // GREASE group
		+ with16(QByteArray(1, char(0)))               // 1 zero byte key data
		+ QByteArray("\x11\xec", 2)                    // X25519MLKEM768
		+ with16(QByteArray(reinterpret_cast<const char*>(pqKey.data()), pqKey.size()))
		+ QByteArray("\x00\x1d", 2)                    // x25519
		+ with16(QByteArray(reinterpret_cast<const char*>(x25519Pub.data()), x25519Pub.size()))
	));

	// ALPN: h2, http/1.1
	const auto alpnExt = ext(0x0010, with16(
		QByteArray("\x02h2\x08http/1.1", 12)));

	// signature_algorithms: 8 algorithms as Chrome 149
	const auto sigAlgsPayload = with16(QByteArray(
		"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01", 16));

	// GREASE extension collision avoidance
	char gv2[2] = { gv(2), gv(2) };
	char gv4[2] = { gv(4), gv(4) };
	if (gv4[0] == gv2[0] && gv4[1] == gv2[1]) {
		gv4[0] ^= 0x10;
		gv4[1] ^= 0x10;
	}

	// GREASE ECH extension (0xfe0d) — outer_type=0, kdf=HKDF-SHA256, aead=ChaCha20Poly1305
	QByteArray echExt;
	{
		auto echPriv = bytes::vector(32);
		base::RandomFill(echPriv.data(), 32);
		// Clamp X25519 private key per RFC 7748
		auto *p = reinterpret_cast<uint8_t*>(echPriv.data());
		p[0] &= 248;
		p[31] &= 127;
		p[31] |= 64;
		// Derive X25519 public key from clamped private key (matches Python _x25519_keypair)
		const auto echKey = EVP_PKEY_new_raw_private_key(
			NID_X25519,
			nullptr,
			reinterpret_cast<const unsigned char*>(echPriv.data()),
			32);
		auto echPub = bytes::vector(32);
		if (echKey) {
			size_t pubLen = 32;
			EVP_PKEY_get_raw_public_key(
				echKey,
				reinterpret_cast<unsigned char*>(echPub.data()),
				&pubLen);
			EVP_PKEY_free(echKey);
		}
		const uint8 kInnerLen = 128 + (static_cast<uint8>(seed[0]) & 0x03) * 32; // 128/160/192/224
		auto echInner = bytes::vector(kInnerLen + 16); // +16 for ChaCha20Poly1305 tag
		base::RandomFill(echInner.data(), echInner.size());
		const auto configId = QByteArray(1, static_cast<char>(seed[5]));
		QByteArray echPayload;
		echPayload.append('\x00');                          // outer_type
		echPayload.append("\x00\x01\x00\x03", 4);           // kdf=HKDF-SHA256, aead=ChaCha20Poly1305
		echPayload.append(configId);                        // config_id from seed[5]
		echPayload.append("\x00\x20", 2);                   // enc_len=32
		echPayload.append(reinterpret_cast<const char*>(echPub.data()), 32);
		const auto payloadLen = qToBigEndian(quint16(echInner.size()));
		echPayload.append(reinterpret_cast<const char*>(&payloadLen), 2);
		echPayload.append(reinterpret_cast<const char*>(echInner.data()), echInner.size());
		echExt = ext(0xfe0d, echPayload);
	}

	// Permutable extensions (shuffled) — stored as full encoded ext (type+len+payload)
	QVector<QByteArray> perm;
	perm.append(ext(0x0017, QByteArray()));                              // extended_master_secret
	perm.append(ext(0xff01, QByteArray(1, char(0))));                    // renegotiation_info
	perm.append(ext(0x000b, QByteArray("\x01\x00", 2)));                // ec_point_formats
	perm.append(ext(0x0023, QByteArray()));                              // session_ticket
	perm.append(ext(0x0005, QByteArray("\x01\x00\x00\x00\x00", 5)));   // status_request
	perm.append(ext(0x000d, sigAlgsPayload));                            // signature_algorithms
	perm.append(ext(0x0012, QByteArray()));                              // signed_cert_timestamp
	perm.append(ext(0x002d, QByteArray("\x01\x01", 2)));                // psk_key_exchange_modes
	perm.append(ext(0x001b, QByteArray("\x02\x00\x02", 3)));            // compress_certificate
	perm.append(ext(0x44cd, QByteArray("\x00\x03\x02h2", 5)));          // application_settings
	perm.append(svExt);                                                  // supported_versions
	perm.append(sgExt);                                                  // supported_groups
	perm.append(ksExt);                                                  // key_share
	perm.append(alpnExt);                                                // ALPN
	perm.append(ext(uint16(uint8_t(gv2[0]) << 8 | uint8_t(gv2[1])), QByteArray("\x00\x00", 2)));  // GREASE ext1
	perm.append(ext(uint16(uint8_t(gv4[0]) << 8 | uint8_t(gv4[1])), QByteArray("\x00\x01\x00", 3))); // GREASE ext2
	perm.append(echExt);                                                 // GREASE ECH

	// === PSK extension (if we have a ticket from previous session) ===
	QByteArray pskExt;
	if (psk.has_value()) {
		const auto &pskData = psk.value();
		const auto ticketBytes = QByteArray(
			reinterpret_cast<const char*>(pskData.ticket.data()),
			pskData.ticket.size());
		const auto ageMs = uint32_t(
			(base::unixtime::http_now() - pskData.timestamp) * 1000
			+ pskData.ticketAgeAdd);
		const auto obfuscatedAge = qToBigEndian(ageMs);
	
		QByteArray pskIdentity;
		pskIdentity.append(with16(ticketBytes));
		pskIdentity.append(reinterpret_cast<const char*>(&obfuscatedAge), 4);
	
		QByteArray identities;
		identities.append(pskIdentity);
	
		// Placeholder binder: 1 byte length (32) + 32 zero bytes
		QByteArray binderPlaceholder;
		binderPlaceholder.append(static_cast<char>(32));
		binderPlaceholder.append(QByteArray(32, char(0)));
	
		QByteArray binders;
		binders.append(with16(binderPlaceholder));
	
		QByteArray pskContents;
		pskContents.append(with16(identities));
		pskContents.append(with16(binders));
	
		pskExt = ext(kPskExtensionType, pskContents);
	}


	std::random_device rd;
	std::mt19937 gen(rd());
	std::shuffle(perm.begin(), perm.end(), gen);

	QByteArray extBody = sniExt;
	for (const auto &e : perm) {
		extBody.append(e);
	}
	if (psk.has_value()) {
		extBody.append(pskExt);
	}
	const auto extensions = with16(extBody);

	// === Session ID ===
	auto sid = bytes::vector(32);
	base::RandomFill(sid.data(), 32);
	const auto sessionID = QByteArray(1, char(32)).append(
		reinterpret_cast<const char*>(sid.data()), 32);

	// === Assemble ClientHello body (version + random + session_id + ciphers + compression + extensions) ===
	auto body = QByteArray();
	body.append("\x03\x03", 2);               // legacy_version = TLS 1.2
	[[maybe_unused]] const auto digestPosition = body.size();
	body.append(QByteArray(32, char(0)));      // random placeholder for HMAC
	body.append(sessionID);
	body.append(with16(ciphers));
	body.append("\x01\x00", 2);                // compression_methods: [null]
	body.append(extensions);

	// === Wrap in handshake header first (python computes HMAC over full record) ===
	QByteArray handshake;
	handshake.append(char(1));  // ClientHello
	const auto hsLen = qToBigEndian(quint32(body.size()));
	handshake.append(reinterpret_cast<const char*>(&hsLen) + 1, 3);
	handshake.append(body);

	// === Wrap in TLS record ===
	QByteArray record;
	record.append("\x16\x03\x01", 3);
	record.append(u16be(handshake.size()));
	record.append(handshake);

	// === HMAC-SHA256 over full record, inject into random field (bytes 11..43) ===
	auto recordSpan = bytes::make_detached_span(record);
	auto digestSpan = recordSpan.subspan(11, kHelloDigestLength);
	auto keySpan = bytes::make_span(key);
	bytes::copy(digestSpan, openssl::HmacSha256(keySpan, recordSpan));

	// === PSK binder computation (RFC 8446 4.2.11.2) ===
	if (psk.has_value()) {
		const auto recData = reinterpret_cast<uint8_t*>(record.data());
		const auto recLen = record.size();
		constexpr uint16_t kPskExtType = 0x0029;
		int psk_type_pos = -1;
		const int kExtensionsStart = 114;
		int pos = kExtensionsStart;
		while (pos + 4 <= recLen) {
			const uint16_t ext_type = (recData[pos] << 8) | recData[pos + 1];
			const uint16_t ext_len = (recData[pos + 2] << 8) | recData[pos + 3];
			if (ext_type == kPskExtType) {
				psk_type_pos = pos;
				break;
			}
			pos += 4 + ext_len;
		}
		if (psk_type_pos >= 0) {
			const auto ticketLen = psk.value().ticket.size();
			const int binder_offset = psk_type_pos + 9 + ticketLen + 6;
			const uint8_t binder_len = recData[psk_type_pos + 8 + ticketLen + 6];
			const int ch_offset = 5;
			const int ch_hs_len = 1 + 3 +
				((recData[6] << 16) | (recData[7] << 8) | recData[8]);
			const int ch_len = ch_offset + ch_hs_len;
			QByteArray truncatedCH = record.mid(ch_offset, ch_len);
			auto truncData = reinterpret_cast<uint8_t*>(truncatedCH.data());
			const int binder_in_ch = binder_offset - ch_offset;
			std::memset(truncData + binder_in_ch, 0, binder_len);
			const auto &pskTicket = psk.value().ticket;
			auto pskSecret = bytes::make_span(
				reinterpret_cast<const bytes::type*>(pskTicket.data()),
				pskTicket.size());
			const auto truncatedSpan = bytes::make_span(
				reinterpret_cast<const bytes::type*>(truncatedCH.constData()),
				truncatedCH.size());
			auto binder = ComputePskBinder(pskSecret, truncatedSpan);
			std::memcpy(recData + binder_offset, binder.data(), binder_len);
		} else {
		}
	}

	// XOR timestamp into digest[28..32] (last 4 bytes of random field = record bytes 39..43)
	// In the HMAC output (digestSpan), offset 28..32
	const auto ts = qToLittleEndian(int32(base::unixtime::http_now()));
	const auto tsSpan = recordSpan.subspan(11 + kHelloDigestLength - sizeof(int32), sizeof(int32));
	auto tsVal = int32();
	bytes::copy(bytes::object_as_span(&tsVal), tsSpan);
	tsVal ^= ts;
	bytes::copy(tsSpan, bytes::object_as_span(&tsVal));

	// Extract digest for server hello verification
	auto helloDigest = record.mid(11, kHelloDigestLength);

	return { record, helloDigest };
}
[[nodiscard]] bool CheckPart(bytes::const_span data, QLatin1String check) {
	if (data.size() < check.size()) {
		return false;
	}
	return !bytes::compare(
		data.subspan(0, check.size()),
		bytes::make_span(check.data(), check.size()));
}

[[nodiscard]] int ReadPartLength(bytes::const_span data, int offset) {
	const auto storage = data.subspan(offset, kLengthSize);
	return qFromBigEndian(
		*reinterpret_cast<const uint16*>(storage.data()));
}

} // namespace

TlsSocket::TlsSocket(
	not_null<QThread*> thread,
	const bytes::vector &secret,
	const QNetworkProxy &proxy,
	bool protocolForFiles,
		MTP::ProxyData::ClientHello clientHello)
: AbstractSocket(thread)
, _secret(secret)
, _clientHello(clientHello) {
	Expects(_secret.size() >= 21 && _secret[0] == bytes::type(0xEE));

	_socket.moveToThread(thread);
	_socket.setProxy(proxy);
	if (protocolForFiles) {
		_socket.setSocketOption(
			QAbstractSocket::SendBufferSizeSocketOption,
			kFilesSendBufferSize);
		_socket.setSocketOption(
			QAbstractSocket::ReceiveBufferSizeSocketOption,
			kFilesReceiveBufferSize);
	}
	const auto wrap = [&](auto handler) {
		return [=](auto &&...args) {
			InvokeQueued(this, [=] { handler(args...); });
		};
	};
	using Error = QAbstractSocket::SocketError;
	connect(
		&_socket,
		&QTcpSocket::connected,
		wrap([=] { plainConnected(); }));
	connect(
		&_socket,
		&QTcpSocket::disconnected,
		wrap([=] { plainDisconnected(); }));
	connect(
		&_socket,
		&QTcpSocket::readyRead,
		wrap([=] { plainReadyRead(); }));
	connect(
		&_socket,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) { handleError(e); }));
}

bytes::const_span TlsSocket::domainFromSecret() const {
	return bytes::make_span(_secret).subspan(17);
}

bytes::const_span TlsSocket::keyFromSecret() const {
	return bytes::make_span(_secret).subspan(1, 16);
}

void TlsSocket::plainConnected() {
	if (_state != State::Connecting) {
		return;
	}

	static const auto kClientHelloRules = PrepareClientHelloRules();
	const auto hello = (_clientHello == MTP::ProxyData::ClientHello::BoringSSL)
		? PrepareBoringSSLClientHello(domainFromSecret(), keyFromSecret(), _psk)
		: PrepareClientHello(kClientHelloRules, domainFromSecret(), keyFromSecret());
	if (hello.data.isEmpty()) {
		logError(888, "Could not generate Client Hello.");
		_state = State::Error;
		_error.fire({});
	} else {
		_state = State::WaitingHello;
		_incoming = hello.digest;
		_socket.write(hello.data);
	}
}

void TlsSocket::plainDisconnected() {
	_state = State::NotConnected;
	_incoming = QByteArray();
	_serverHelloLength = 0;
	_incomingGoodDataOffset = 0;
	_incomingGoodDataLimit = 0;
	_disconnected.fire({});
}

void TlsSocket::plainReadyRead() {
	switch (_state) {
	case State::WaitingHello: return readHello();
	case State::Connected: return readData();
	}
}

bool TlsSocket::requiredHelloPartReady() const {
	return _incoming.size() >= kHelloDigestLength + _serverHelloLength;
}

void TlsSocket::readHello() {
	const auto parts1Size = kServerHelloPart1.size() + kLengthSize;
	if (!_serverHelloLength) {
		_serverHelloLength = parts1Size;
	}
	while (!requiredHelloPartReady()) {
		if (!_socket.bytesAvailable()) {
			return;
		}
		_incoming.append(_socket.readAll());
	}
	// All needed bytes are present — compute full length including tickets.
	// Start scanning from the beginning of the server response (after digest).
	// SkipTlsRecords will walk through ServerHello, CCS, AppData, tickets.
	const auto fullSpan = bytes::make_span(_incoming);
	const auto afterHello = fullSpan.subspan(kHelloDigestLength);
	_serverHelloLength = SkipTlsRecords(afterHello);
	// If tickets haven't fully arrived yet — wait for more.
	if (!requiredHelloPartReady()) {
		return;
	}
	checkHelloParts12();
}

void TlsSocket::checkHelloParts12() {
	// Validate ServerHello header (first 5 bytes after digest).
	const auto headerSize = kServerHelloPart1.size() + kLengthSize;
	const auto data = bytes::make_span(_incoming).subspan(
		kHelloDigestLength,
		headerSize);
	const auto part1Offset = headerSize
		- kLengthSize
		- kServerHelloPart1.size();
	if (!CheckPart(data.subspan(part1Offset), kServerHelloPart1)) {
		logError(888, "Bad Server Hello part1.");
		handleError();
		return;
	}
	// _serverHelloLength already computed correctly in readHello().
	checkHelloDigest();
}

int TlsSocket::SkipTlsRecords(bytes::const_span data) const {
	auto offset = int(0);
	while (offset + 5 <= data.size()) {
		const auto recordLen = ReadPartLength(data, offset + 3);
		const auto totalLen = 5 + recordLen;
		if (offset + totalLen > data.size()) {
			break;
		}
		offset += totalLen;
	}
	return offset;
}

void TlsSocket::checkHelloDigest() {
	// HMAC is computed over client_digest + entire server response
	// (ServerHello + CCS + app_data + any trailing ticket-mimic records).
	// Some proxies (e.g. telemt) append fake NewSessionTicket ApplicationData
	// records after the handshake and include them in the HMAC input.
	const auto fulldata = bytes::make_detached_span(_incoming).subspan(
		0,
		_incoming.size());
	const auto digest = fulldata.subspan(
		kHelloDigestLength + kServerHelloDigestPosition,
		kHelloDigestLength);
	const auto digestCopy = bytes::make_vector(digest);
	bytes::set_with_const(digest, bytes::type(0));
	const auto check = openssl::HmacSha256(keyFromSecret(), fulldata);
	if (bytes::compare(digestCopy, check) != 0) {
		logError(888, "Bad Server Hello digest.");
		handleError();
		return;
	}
	// Parse NewSessionTicket mimics before shifting them out.
	// Tickets live between ServerHello end and real MTProto data.
	parseNewSessionTickets();
	// Shift past the entire TLS response (ServerHello + CCS + app_data + tickets).
	shiftIncomingBy(kHelloDigestLength + _serverHelloLength);
	if (!_incoming.isEmpty()) {
		InvokeQueued(this, [=] {
			if (!checkNextPacket()) {
				handleError();
			}
		});
	}
	_incomingGoodDataOffset = _incomingGoodDataLimit = 0;
	_state = State::Connected;
	_connected.fire({});
}

void TlsSocket::readData() {
	if (!isConnected()) {
		return;
	}
	_incoming.append(_socket.readAll());
	if (!checkNextPacket()) {
		handleError();
	} else if (hasBytesAvailable()) {
		_readyRead.fire({});
	}
}

void TlsSocket::parseNewSessionTickets() {
    auto data = bytes::make_span(_incoming);
    auto offset = size_t(0);
    while (offset + 5 <= data.size()) {
        uint8_t record_type = static_cast<uint8_t>(data[offset]);
        uint16_t record_len = (uint16_t(static_cast<uint8_t>(data[offset+3])) << 8)
            | uint16_t(static_cast<uint8_t>(data[offset+4]));
        if (offset + 5 + record_len > data.size()) {
            break;
        }
        const auto record_data = data.subspan(offset + 5, record_len);
        bool parsed = false;
        if (record_type == 0x16 && record_data.size() >= 4) {
            uint8_t hs_type = static_cast<uint8_t>(record_data[0]);
            uint32_t hs_len = (uint32_t(static_cast<uint8_t>(record_data[1])) << 16)
                | (uint32_t(static_cast<uint8_t>(record_data[2])) << 8)
                | uint32_t(static_cast<uint8_t>(record_data[3]));
            if (hs_type == 0x04 && record_data.size() >= 4 + hs_len) {
                parsed = parseNewSessionTicketData(
                    record_data.subspan(4, hs_len));
            }
        } else if (record_type == 0x17 && record_data.size() >= 4) {
            uint8_t hs_type = static_cast<uint8_t>(record_data[0]);
            if (hs_type == 0x04) {
                uint32_t hs_len = (uint32_t(static_cast<uint8_t>(record_data[1])) << 16)
                    | (uint32_t(static_cast<uint8_t>(record_data[2])) << 8)
                    | uint32_t(static_cast<uint8_t>(record_data[3]));
                if (record_data.size() >= 4 + hs_len) {
                    parsed = parseNewSessionTicketData(
                        record_data.subspan(4, hs_len));
                }
            }
        }
        if (parsed) {
        }
        offset += 5 + record_len;
    }
}

bool TlsSocket::parseNewSessionTicketData(bytes::const_span data) {
    size_t pos = 0;
    uint32_t ticket_lifetime = 0, ticket_age_add = 0;
    uint16_t ticket_len = 0;
    uint8_t nonce_len = 0;
    if (pos + 4 > data.size()) return false;
    auto b0 = static_cast<uint8_t>(data[pos]);
    auto b1 = static_cast<uint8_t>(data[pos+1]);
    auto b2 = static_cast<uint8_t>(data[pos+2]);
    auto b3 = static_cast<uint8_t>(data[pos+3]);
    ticket_lifetime = (uint32_t(b0) << 24) | (uint32_t(b1) << 16)
        | (uint32_t(b2) << 8) | uint32_t(b3);
    pos += 4;
    if (pos + 4 > data.size()) return false;
    b0 = static_cast<uint8_t>(data[pos]);
    b1 = static_cast<uint8_t>(data[pos+1]);
    b2 = static_cast<uint8_t>(data[pos+2]);
    b3 = static_cast<uint8_t>(data[pos+3]);
    ticket_age_add = (uint32_t(b0) << 24) | (uint32_t(b1) << 16)
        | (uint32_t(b2) << 8) | uint32_t(b3);
    pos += 4;
    if (pos + 1 > data.size()) return false;
    nonce_len = static_cast<uint8_t>(data[pos]);
    pos += 1;
    if (pos + nonce_len > data.size()) return false;
    pos += nonce_len;
    if (pos + 2 > data.size()) return false;
    ticket_len = (uint16_t(static_cast<uint8_t>(data[pos])) << 8)
        | uint16_t(static_cast<uint8_t>(data[pos+1]));
    pos += 2;
    if (pos + ticket_len > data.size()) return false;
    PskData psk;
    psk.ticket = bytes::vector(ticket_len);
    std::memcpy(psk.ticket.data(), data.data() + pos, ticket_len);
    psk.ticketAgeAdd = ticket_age_add;
    psk.timestamp = base::unixtime::http_now();
    _psk = std::move(psk);
    return true;
}

bool TlsSocket::checkNextPacket() {
	auto offset = 0;
	const auto incoming = bytes::make_span(_incoming);
	while (!_incomingGoodDataLimit) {
		const auto fullHeader = kServerHeader.size() + kLengthSize;
		if (incoming.size() <= offset + fullHeader) {
			return true;
		}
		if (!CheckPart(incoming.subspan(offset), kServerHeader)) {
			logError(888, "Bad packet header.");
			return false;
		}
		const auto length = ReadPartLength(
			incoming,
			offset + kServerHeader.size());
		if (length > 0) {
			if (offset > 0) {
				shiftIncomingBy(offset);
			}
			_incomingGoodDataOffset = fullHeader;
			_incomingGoodDataLimit = length;
		} else {
			offset += kServerHeader.size() + kLengthSize + length;
		}
	}
	return true;
}

void TlsSocket::shiftIncomingBy(int amount) {
	Expects(_incomingGoodDataOffset == 0);
	Expects(_incomingGoodDataLimit == 0);

	const auto incoming = bytes::make_detached_span(_incoming);
	if (incoming.size() > amount) {
		bytes::move(incoming, incoming.subspan(amount));
		_incoming.chop(amount);
	} else {
		_incoming.clear();
	}
}

void TlsSocket::connectToHost(const QString &address, int port) {
	Expects(_state == State::NotConnected);

	_state = State::Connecting;
	_socket.connectToHost(address, port);
}

bool TlsSocket::isGoodStartNonce(bytes::const_span nonce) {
	return true;
}

void TlsSocket::timedOut() {
	_syncTimeRequests.fire({});
}

bool TlsSocket::isConnected() {
	return (_state == State::Connected);
}

bool TlsSocket::hasBytesAvailable() {
	return (_incomingGoodDataLimit > 0)
		&& (_incomingGoodDataOffset < _incoming.size());
}

int64 TlsSocket::read(bytes::span buffer) {
	auto written = int64(0);
	while (_incomingGoodDataLimit) {
		const auto available = std::min(
			_incomingGoodDataLimit,
			int(_incoming.size()) - _incomingGoodDataOffset);
		if (available <= 0) {
			return written;
		}
		const auto write = std::min(std::size_t(available), buffer.size());
		if (write <= 0) {
			return written;
		}
		bytes::copy(
			buffer,
			bytes::make_span(_incoming).subspan(
				_incomingGoodDataOffset,
				write));
		written += write;
		buffer = buffer.subspan(write);
		_incomingGoodDataLimit -= write;
		_incomingGoodDataOffset += write;
		if (_incomingGoodDataLimit) {
			return written;
		}
		shiftIncomingBy(base::take(_incomingGoodDataOffset));
		if (!checkNextPacket()) {
			_state = State::Error;
			InvokeQueued(this, [=] { handleError(); });
			return written;
		}
	}
	return written;
}

void TlsSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (!isConnected()) {
		return;
	}
	if (!prefix.empty()) {
		_socket.write(kClientPrefix.data(), kClientPrefix.size());
	}
	while (!buffer.empty()) {
		const auto write = std::min(
			kClientPartSize - prefix.size(),
			buffer.size());
		_socket.write(kClientHeader.data(), kClientHeader.size());
		const auto size = qToBigEndian(uint16(prefix.size() + write));
		_socket.write(reinterpret_cast<const char*>(&size), sizeof(size));
		if (!prefix.empty()) {
			_socket.write(
				reinterpret_cast<const char*>(prefix.data()),
				prefix.size());
			prefix = bytes::const_span();
		}
		_socket.write(
			reinterpret_cast<const char*>(buffer.data()),
			write);
		buffer = buffer.subspan(write);
	}
}

int32 TlsSocket::debugState() {
	return _socket.state();
}

QString TlsSocket::debugPostfix() const {
	return u"_ee"_q;
}

void TlsSocket::handleError(int errorCode) {
	if (_state != State::Connected) {
		_syncTimeRequests.fire({});
	}
	if (errorCode) {
		logError(errorCode, _socket.errorString());
	}
	_state = State::Error;
	_error.fire({});
}

} // namespace MTP::details
