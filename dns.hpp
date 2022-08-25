#ifndef _LIB_DNS_PACKET_H_
#define _LIB_DNS_PACKET_H_

#include <array>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <list>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
#define __WINDOWS__
#endif

#ifdef __WINDOWS__
#include <cstdlib>
//
// May I assume that all windows are installed on little-endian hardware?
// AFAIK:
//	Windows for x86
//	Windows for AMD64
//	Windows for AArch32
//	Windows for AArch64
// They all execute in little-endian mode
//
#ifndef htonl
#define htonl _byteswap_ulong
#endif

#ifndef ntohl
#define ntohl _byteswap_ulong
#endif

#ifndef ntohs
#define ntohs _byteswap_ushort
#endif

#ifndef htons
#define htons _byteswap_ushort
#endif

#define strncasecmp _strnicmp
#else
#include <arpa/inet.h>
#endif //__WINDOWS__

namespace dns {

enum DnsOpCode : uint16_t {
	RCODE_OKAY = 0, /* RFC-1035 */
	RCODE_FORMAT_ERROR = 1, /* RFC-1035 */
	RCODE_SERVER_FAILURE = 2, /* RFC-1035 */
	RCODE_NAME_ERROR = 3, /* RFC-1035 */
	RCODE_NOT_IMPLEMENTED = 4, /* RFC-1035 */
	RCODE_REFUSED = 5, /* RFC-1035 */
	RCODE_YXDOMAIN = 6, /* RFC-2136 */
	RCODE_YXRRSET = 7, /* RFC-2136 */
	RCODE_NXRRSET = 8, /* RFC-2136 */
	RCODE_NOTAUTH = 9, /* RFC-2136 */
	RCODE_NOTZONE = 10, /* RFC-2136 */
	RCODE_BADVERS = 16, /* RFC-2671 */
	RCODE_BADSIG = 16, /* RFC-2845 */
	RCODE_BADKEY = 17, /* RFC-2845 */
	RCODE_BADTIME = 18, /* RFC-2845 */
	RCODE_BADMODE = 19, /* RFC-2845 */
	RCODE_BADNAME = 20, /* RFC-2930 */
	RCODE_BADALG = 21, /* RFC-2930 */
	RCODE_BADTRUC = 22, /* RFC-4635 */
	RCODE_PRIVATE = 3841, /* RFC-2929 */
};

enum RecordType : uint16_t {
	A = 1,
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15,
	TXT = 16,
	AAAA = 28,
	SPF = 99,
	UknownType = 65280
};

enum RecordClass : uint16_t {
	INTERNET = 1, /* Internet	    	RFC-1035 */
	CSNET = 2, /* CSNET (obsolete)    	RFC-1035 */
	CHAOS = 3, /* CHAOS		RFC-1035 */
	HESIOD = 4, /* Hesiod		RFC-1035 */
	NONE = 254, /* 			RFC-2136 */
	ANY = 255, /* All classes		RFC-1035 */
	UknownClass = 65280 /* Unknown class 	RFC-2929 */
};

//
// DNS answer
//
using OctectStreamData = std::vector<std::byte>;

using AData = uint32_t;

using AAAAData = std::array<std::byte, 16>;

using PTRData = std::string;

struct MXData {
	uint16_t preference = 0;
	std::string exchange;
};

struct TXTData {
	uint8_t size = 0;
	std::string txt;
};

struct SOAData {
	std::string primaryServer;
	std::string administrator;
	uint32_t serialNo = 0;
	uint32_t refresh = 0;
	uint32_t retry = 0;
	uint32_t expire = 0;
	uint32_t defaultTtl = 0;
};

// generic dns record data
using DnsRecordData = std::variant<
		OctectStreamData,
		AData,
		AAAAData,
		PTRData,
		MXData,
		TXTData,
		SOAData>;

struct DnsAnswer {
	std::string name;
	uint16_t type = RecordType::UknownType;
	uint16_t cls = RecordClass::UknownClass;
	uint32_t ttl = 0;
	DnsRecordData value;
};

//
// DNS question
//
struct DnsQuestion {
	std::string name;
	uint16_t type = RecordType::UknownType;
	uint16_t cls = RecordClass::UknownClass;
};

//
// DNS header variables
//
#pragma pack(1)
struct DnsHeaderVars {
	uint16_t xid = 0;
	uint8_t recursionDesired : 1;
	uint8_t truncation : 1;
	uint8_t authoritative : 1;
	uint8_t opcode : 4;
	uint8_t isResponse : 1;
	uint8_t responseCode : 4;
	uint8_t checkingDisabled : 1;
	uint8_t authenticatedData : 1;
	uint8_t reserved : 1;
	uint8_t recursionAvailable : 1;
};
#pragma pack()

struct DnsMessage {
	DnsHeaderVars dnsHead = { 0 };
	std::vector<DnsQuestion> questions;
	std::vector<DnsAnswer> answers;
	std::vector<DnsAnswer> authorityAnwsers;
	std::vector<DnsAnswer> additionalAnwsers;
};

namespace impl {
template <typename T, typename U>
struct decay_equiv : std::is_same<typename std::decay_t<T>, U>::type {};

struct NameCompressResult {
	std::string labelizedPrefix;
	size_t compressedLabelCount = 0;
	size_t compressedTargetOffset = 0;
	void *parent = nullptr;
};

using LabelNameParts = std::vector<const uint8_t *>;

constexpr auto MAX_UDP_DNS_PACKET_SIZE = 512;

//
// convert a plain domain name to a sequence of [[len][text]]
//
static std::tuple<size_t, std::string> LablizeName(const char *name) {
	// prepare buffer
	std::string r;
	auto nameLen = strlen(name);
	//
	// #TODO
	// it's compatible to domain name with/without dot tail.
	// I think according to the rfc1035, the domain name should be fully qualified
	//
	r.resize(nameLen + (name[nameLen - 1] == '.' ? 1 : 2));
	memset(&r[0], 0, r.size());
	memcpy(&r[1], name, r.size() - 1);

	//
	size_t labelCount = 0;
	size_t prevPos = 0;
	size_t pos = 0;
	while ((pos = r.find_first_of('.', prevPos + 1)) != std::string::npos) {
		r[prevPos] = (char)(pos - prevPos - 1);
		prevPos = pos;
		++labelCount;
	}

	// last potion
	r[prevPos] = (char)(r.size() - prevPos - 2);
	++labelCount;

	//
	// #TODO
	// as same as the previous section, compatible oriented code
	//
	if (name[nameLen - 1] == '.') {
		// remove the last empty label
		--labelCount;
		r[r.size() - 1] = 0;
	}

	// done
	return { labelCount, std::move(r) };
}

//
// collect all the parts of this domain name from the dns message
// return: <data_size, name parts>
//
static int CollectLableNames(const uint8_t *head, const uint8_t *ptr, const uint8_t *tail, std::vector<const uint8_t *> &parts, bool recursively = true) {
	assert(head != nullptr && ptr != nullptr && tail != nullptr);
	assert(head < tail);
	if (ptr < head) {
		return 0;
	}
	if (ptr >= tail) {
		return 0;
	}

	bool countTerminal = true;
	int consumed = 0;
	while (*ptr && ptr < tail) {
		if (((uint8_t)*ptr & 0xc0) != 0) {
			// compress pointer
			uint16_t offset = htons(*(uint16_t *)ptr) & (uint16_t)(~0xc000);
			if (head + offset >= tail) {
				// illegal
				return 0;
			}
			if (recursively) {
				// recursive collect
				if (!CollectLableNames(head, head + offset, tail, parts)) {
					// illegal
					return 0;
				}
			}

			// consumed += sizeof(uint16_t)
			consumed += 2;
			countTerminal = false;
			ptr += 2;

			// the compressed part should be the last part of a host name
			break;
		} else if (*ptr >= 64 || ptr + *ptr > tail) {
			// illegal
			return 0;
		} else {
			// plain text
			parts.emplace_back(ptr);

			// consumed += [len] [text]
			consumed += *ptr + 1;

			// move ptr
			ptr += (*ptr) + 1;
		}
	}
	if (countTerminal) {
		++consumed;
	}

	// we should count the last null terminator in
	return consumed;
}

//
// read out a fully qualified domain name
//
static std::tuple<size_t, std::string> ReadDomainName(const uint8_t *head, const uint8_t *ptr, const uint8_t *tail) {
	// is ROOT name?
	if (*ptr == 0) {
		return { 1, {} };
	}

	// collect them
	std::vector<const uint8_t *> labels;
	auto dataLen = CollectLableNames(head, ptr, tail, labels);
	if (!dataLen) {
		return {};
	}

	// concatenate each part
	std::string result;
	for (auto p : labels) {
		result += std::string((char *)p + 1, *p);
		result += ".";
	}

	// done
	return { dataLen, std::move(result) };
}

//
// compress DNS host names within the given DNS message
//
class DnsNameCompressionContext {
private:
	struct PureName {
		const uint8_t *ptr = nullptr;
		size_t compressedLabelCount = 0;
		std::list<PureName> compressedChildren;
	};

	struct CompressResult {
		size_t msgOffset = 0;
		size_t compressedCount = 0;
		const PureName *targetNode = nullptr;
	};

public:
	DnsNameCompressionContext(const uint8_t *startPtr, const uint8_t *endPtr) :
			head_(startPtr), tail_(endPtr) {
		assert(head_ < tail_);
	}

	//
	// compress a domain name
	//
	NameCompressResult TryCompressName(const char *name) {
		// lablize
		auto [srcLabelCount, srcLabelString] = LablizeName(name);
		if (srcLabelCount < 2) {
			// we assume a domain should have 1 dot in the middle of string at least
			return {};
		}

		auto srcParts = CollectPartsFromLabelizedString(srcLabelString);
		if (srcParts.size() != srcLabelCount) {
			// should not reach here
			return {};
		}

		// match recursively
		CompressResult matched;
		RecursivelyProbeAndCompressOnNode(srcParts, root_, matched);
		if (!matched.compressedCount) {
			// no compression
			return { std::move(srcLabelString) };
		}

		// compressed
		size_t compressedSize = 0;
		for (size_t idx = 0; idx < matched.compressedCount; idx++) {
			compressedSize += srcParts[srcLabelCount - idx - 1].size() + 1;
		}
		assert(compressedSize <= srcLabelString.size() - 1);

		auto prefixSize = srcLabelString.size() - compressedSize;
		if (compressedSize) {
			// we have a compressed suffix, so we gonna remove terminator
			assert(prefixSize > 0);
			--prefixSize;
		}

		// build result
		NameCompressResult result;
		result.labelizedPrefix = srcLabelString.substr(0, prefixSize);
		result.compressedLabelCount = matched.compressedCount;
		result.compressedTargetOffset = matched.msgOffset;
		result.parent = (void *)matched.targetNode;
		return result;
	}

	//
	// save the written name to compression context
	//	parent: the source string compressed from
	//	pos: written pointer in dns message
	//  compressedLabelCount: compressed label count
	//
	void PutPureName(void *parent, const uint8_t *ptr, size_t compressedLabelCount) {
		if (parent == nullptr) {
			// top level
			root_.compressedChildren.emplace_back(PureName{ ptr });
		} else {
			// child level
			((PureName *)parent)->compressedChildren.emplace_back(PureName{ ptr, compressedLabelCount });
		}
	}

private:
	std::vector<std::string_view> CollectPartsFromLabelizedString(const std::string &labelizedS) {
		std::vector<std::string_view> result;
		auto ptr = &labelizedS[0];
		while (ptr < &labelizedS[0] + labelizedS.size() - 1) {
			result.emplace_back(std::string_view{ ptr + 1, (size_t)ptr[0] });
			ptr += (uint8_t)ptr[0] + 1;
		}
		return result;
	}

	//
	// example.mail.google.co.jp  [TOP]
	//
	//     foo.mail.ablook......  [NODE]
	//
	//     bar.mail.ablook......  [TARGET]
	//
	//     bar..................  [RESULT]
	//
	void RecursivelyProbeAndCompressOnNode(const std::vector<std::string_view> &targetNameParts, const PureName &root, CompressResult &resultContext) {
		for (const auto &node : root.compressedChildren) {
			if (node.compressedLabelCount != resultContext.compressedCount) {
				// if and only if they have same compressed label count, then the matching process keep going
				continue;
			}

			// match this node
			std::vector<const uint8_t *> dstLabels;
			auto segLen = CollectLableNames(head_, node.ptr, tail_, dstLabels, false);
			if (!segLen) {
				// invalid, why this could happen?
				break;
			}

			if (dstLabels.empty()) {
				assert(segLen == sizeof(uint16_t));
				// fully compressed
				continue;
			}

			// match on this node
			bool errorOccurred = false;
			size_t matched = 0;
			for (; matched < dstLabels.size() && matched < targetNameParts.size() - node.compressedLabelCount; matched++) {
				// get source and destination label
				auto &src = targetNameParts[targetNameParts.size() - matched - node.compressedLabelCount - 1];
				auto dst = dstLabels[dstLabels.size() - matched - 1];
				if (src.empty() || !dst) {
					errorOccurred = true;
					break;
				}

				// compare source and destination label
				if (src.size() != dst[0] ||
						strncasecmp(src.data(), (const char *)&dst[1], src.size()) != 0) {
					break;
				}
			}
			if (errorOccurred) {
				// something goes wrong
				break;
			}

			if (!matched) {
				// cannot compress more label with this node
				continue;
			}

			// update result
			auto dst = dstLabels[dstLabels.size() - matched];
			resultContext.compressedCount += matched;
			resultContext.msgOffset = (uint16_t)(dst - (const uint8_t *)head_);
			resultContext.targetNode = &node;

			// go deeper
			RecursivelyProbeAndCompressOnNode(targetNameParts, node, resultContext);
			break;
		}
	}

private:
	const uint8_t *head_ = nullptr, *tail_ = nullptr;
	PureName root_;
};

//
// extract DNS question/answers from the given DNS message
//
class DnsRecordExtractor {
public:
	DnsRecordExtractor(const uint8_t *startPtr, const uint8_t *endPtr) :
			head_(startPtr), tail_(endPtr) {
		assert(head_ < tail_);
	}

	std::tuple<size_t, DnsQuestion> ExtractQuestion(size_t offset) {
		//
		// +0x00 Name (VARIANT size, at least 2 bytes)
		//	...
		// +0x02 Type
		// +0x04 Class
		//
		if (head_ + offset + 6 >= tail_) {
			return { 0, {} };
		}
		auto [rsize, name] = ReadDomainName(head_, head_ + offset, tail_);
		if (!rsize) {
			return { 0, {} };
		}
		if (head_ + offset + rsize + 4 > tail_) {
			return { 0, {} };
		}

		DnsQuestion r;
		// name
		r.name = std::move(name);
		// type
		r.type = ntohs(*(uint16_t *)(head_ + offset + rsize));
		rsize += sizeof(uint16_t);
		// class
		r.cls = ntohs(*(uint16_t *)(head_ + offset + rsize));
		rsize += sizeof(uint16_t);

		// done
		return { rsize, std::move(r) };
	}

	std::tuple<size_t, DnsAnswer> ExtractAnwser(size_t offset) {
		//
		// +0x00 Name (VARIANT size, at least 2 bytes)
		//	...
		// +0x02 Type
		// +0x04 Class
		// +0x06 TTL
		// +0x0A Data length
		// +0x0C Data (VARIANT)
		//
		if (head_ + offset + 12 >= tail_) {
			return { 0, {} };
		}
		auto [rsize, name] = ReadDomainName(head_, head_ + offset, tail_);
		if (!rsize) {
			return { 0, {} };
		}
		if (head_ + offset + rsize + 11 > tail_) {
			return { 0, {} };
		}

		DnsAnswer r;
		// name
		r.name = std::move(name);
		// type
		r.type = ntohs(*(uint16_t *)(head_ + offset + rsize));
		rsize += sizeof(uint16_t);
		// class
		r.cls = ntohs(*(uint16_t *)(head_ + offset + rsize));
		rsize += sizeof(uint16_t);
		// ttl
		r.ttl = ntohl(*(uint32_t *)(head_ + offset + rsize));
		rsize += sizeof(uint32_t);
		// data size
		auto dataSize = ntohs(*(uint16_t *)(head_ + offset + rsize));
		rsize += sizeof(uint16_t);
		if (head_ + offset + rsize + dataSize > tail_) {
			return { 0, {} };
		}
		// resolve data
		auto [ok, data] = BuildDnsData(r.type, head_ + offset + rsize, dataSize);
		if (!ok) {
			return { 0, {} };
		}
		r.value = std::move(data);
		rsize += dataSize;

		// done
		return { rsize, std::move(r) };
	}

private:
	std::tuple<bool, DnsRecordData> BuildDnsData(uint16_t type, const uint8_t *dataPtr, uint16_t dataLength) {
		switch (type) {
			case RecordType::A: {
				//
				// +0x00 IPv4 (4 bytes)
				//
				if (dataLength != sizeof(AData)) {
					break;
				}
				return { true, *(AData *)dataPtr };
			} break;
			case RecordType::AAAA: {
				//
				// +0x00 IPv6 (16 bytes)
				//
				AAAAData data;
				if (dataLength != data.size()) {
					break;
				}
				memcpy(&data[0], dataPtr, data.size());
				return { true, std::move(data) };
			} break;
			case RecordType::SOA: {
				//
				// +0x00 Primary name server (VARIANT, 2 bytes at least)
				//	...
				// +0x02 Responsible authority's mailbox (VARIANT, 2 bytes at least)
				//  ...
				// +0x04 Serial number
				// +0x08 Refresh interval
				// +0x0C Retry interval
				// +0x10 Expire limit
				// +0x14 Minimum TTL
				//
				if (dataLength < 0x18) {
					return { 0, {} };
				}
				size_t offset = 0;

				auto [primaySvrLen, primarySvr] = ReadDomainName(head_, dataPtr + offset, tail_);
				if (!primaySvrLen || dataLength < 0x16 + primaySvrLen) {
					return { 0, {} };
				}
				offset += primaySvrLen;

				auto [mailboxLen, mailbox] = ReadDomainName(head_, dataPtr + offset, tail_);
				if (!mailboxLen || dataLength != 0x14 + primaySvrLen + mailboxLen) {
					return { 0, {} };
				}
				offset += mailboxLen;

				// read other fields
				SOAData r;
				r.primaryServer = std::move(primarySvr);
				r.administrator = std::move(mailbox);
				r.serialNo = ntohl(*(uint16_t *)(dataPtr + offset));
				r.refresh = ntohl(*(uint16_t *)(dataPtr + offset + sizeof(uint32_t)));
				r.retry = ntohl(*(uint16_t *)(dataPtr + offset + sizeof(uint32_t) * 2));
				r.expire = ntohl(*(uint16_t *)(dataPtr + offset + sizeof(uint32_t) * 3));
				r.defaultTtl = ntohl(*(uint16_t *)(dataPtr + offset + sizeof(uint32_t) * 4));
				return { true, std::move(r) };
			} break;
			case RecordType::MX: {
				//
				// +0x00 Preference
				// +0x02 Exchange Server Name
				//
				MXData data;
				if (dataLength < sizeof(uint16_t) * 2) {
					return { false, {} };
				}
				data.preference = ntohs(*(uint16_t *)dataPtr);
				auto [nameSize, name] = ReadDomainName(head_, dataPtr + sizeof(uint16_t), tail_);
				if (nameSize + sizeof(uint16_t) != dataLength) {
					return { false, {} };
				}
				data.exchange = std::move(name);
				return { true, std::move(data) };
			} break;
			case RecordType::NS:
			case RecordType::CNAME:
			case RecordType::PTR: {
				//
				// +0x00 Host name
				//
				auto [nameSize, name] = ReadDomainName(head_, dataPtr, tail_);
				if (nameSize != dataLength) {
					return { false, {} };
				}
				return { true, std::move(name) };
			} break;
			case RecordType::TXT:
			case RecordType::SPF: {
				//
				// +0x00 Text length
				// +0x01 Text (VARIANT length)
				//
				if (dataLength <= 1 || dataLength != *(uint8_t *)dataPtr + 1) {
					return { false, {} };
				}
				TXTData data;
				data.size = *(uint8_t *)dataPtr;
				data.txt = std::string((char *)dataPtr + 1, dataLength - 1);
				return { true, std::move(data) };
			} break;
			default: {
				// Unsupported record type (for now)
				OctectStreamData payload;
				payload.resize(dataLength);
				if (payload.empty()) {
					return {};
				}
				memcpy(&payload[0], dataPtr, dataLength);
				return { true, std::move(payload) };
			} break;
		}
		return {};
	}

private:
	const uint8_t *head_ = nullptr, *tail_ = nullptr;
};

template <class T>
static uint8_t *WriteMetaToPacket(uint8_t *pch, uint8_t *pchEnd, T v, DnsNameCompressionContext *nameCompressionCtx = nullptr) {
	assert(pch < pchEnd);
	if constexpr (decay_equiv<T, std::string>::value) {
		if (v.empty()) {
			return nullptr;
		}
		if (nameCompressionCtx) {
			// try to compress and write
			auto result = nameCompressionCtx->TryCompressName(v.c_str());
			if (result.labelizedPrefix.empty() && !result.compressedTargetOffset) {
				// something goes wrong
				return nullptr;
			}
			if ((size_t)(pchEnd - pch) < result.labelizedPrefix.size() +
							(result.compressedTargetOffset ? sizeof(uint16_t) : 0)) {
				return nullptr;
			}

			auto nameFinalPtr = pch;
			if (!result.labelizedPrefix.empty()) {
				memcpy(pch, result.labelizedPrefix.data(), result.labelizedPrefix.size());
				pch += result.labelizedPrefix.size();
			}
			if (result.compressedTargetOffset) {
				*(uint16_t *)pch = htons((0xc000 | (uint16_t)result.compressedTargetOffset));
				pch += sizeof(uint16_t);
			}
			// save it
			nameCompressionCtx->PutPureName(result.parent, nameFinalPtr, result.compressedLabelCount);

			return pch;
		} else {
			// write pure text
			if (v.size() > 0xff || (size_t)(pchEnd - pch) < v.size()) {
				return nullptr;
			}
			// write text
			memcpy(pch, v.data(), v.size());
			pch += v.size();
			return pch;
		}
	} else if constexpr (decay_equiv<T, RecordClass>::value) {
		// write dns class
		if ((size_t)(pchEnd - pch) < sizeof(uint16_t) || v == RecordClass::UNKNOWN) {
			return nullptr;
		}
		*(uint16_t *)pch = htons((uint16_t)v);
		return pch + 2;
	} else if constexpr (decay_equiv<T, RecordType>::value) {
		// write dns record type
		if ((size_t)(pchEnd - pch) < sizeof(uint16_t) || v == RecordType::UNKNOWN) {
			return nullptr;
		}
		*(uint16_t *)pch = htons((uint16_t)v);
		return pch + 2;
	} else if constexpr (decay_equiv<T, uint8_t>::value) {
		// write uint8_t value
		if ((size_t)(pchEnd - pch) < sizeof(uint8_t)) {
			return nullptr;
		}
		*(uint8_t *)pch = v;
		return pch + 1;
	} else if constexpr (decay_equiv<T, uint16_t>::value) {
		// write uint16_t value
		if ((size_t)(pchEnd - pch) < sizeof(uint16_t)) {
			return nullptr;
		}
		*(uint16_t *)pch = htons((uint16_t)v);
		return pch + 2;
	} else if constexpr (decay_equiv<T, uint32_t>::value) {
		// write uint32_t value
		if ((size_t)(pchEnd - pch) < sizeof(uint32_t)) {
			return nullptr;
		}
		*(uint32_t *)pch = htonl((uint32_t)v);
		return pch + 4;
	}

	assert(false);
	return nullptr;
}

static uint8_t *WriteRecordToPacket(uint8_t *pch, uint8_t *pchEnd, const DnsAnswer &record, DnsNameCompressionContext *compressCtx) {
#define RR_CHECK_WRITE(_v_)                    \
	pch = WriteMetaToPacket(pch, pchEnd, _v_); \
	if (!pch)                                  \
		return {}
#define RR_CHECK_WRITE_DOMAIN(_v_)                          \
	pch = WriteMetaToPacket(pch, pchEnd, _v_, compressCtx); \
	if (!pch)                                               \
		return {}

	RR_CHECK_WRITE_DOMAIN(record.name);
	RR_CHECK_WRITE(record.type);
	RR_CHECK_WRITE(record.cls);
	RR_CHECK_WRITE(record.ttl);

	uint16_t dataLen = 0;
	uint8_t *dataPtr = nullptr;
	if (auto a = std::get_if<AData>(&record.value)) {
		if (record.type != RecordType::A) {
			// illegal
			return nullptr;
		}

		// we can predict that data size is sizeof(uint32_t)
		dataLen = sizeof(uint32_t);
		RR_CHECK_WRITE(dataLen);

		// write data
		uint32_t hostOrderIP = htonl(*a);
		RR_CHECK_WRITE(hostOrderIP);

		// done
		return pch;
	} else if (auto aaaa = std::get_if<AAAAData>(&record.value)) {
		if (record.type != RecordType::AAAA) {
			// illegal
			return nullptr;
		}

		// we can predict that data size is 16
		dataLen = 16;
		RR_CHECK_WRITE(dataLen);

		// write data
		if (pchEnd - pch < 16) {
			return nullptr;
		}
		memcpy(pch, aaaa->data(), 16);

		// done
		return pch;
	} else if (auto mx = std::get_if<MXData>(&record.value)) {
		if (record.type != RecordType::MX ||
				mx->exchange.empty()) {
			// illegal
			return nullptr;
		}

		// save the data-size ptr
		dataPtr = pch;
		RR_CHECK_WRITE(dataLen);

		// write preference number & exchange name
		RR_CHECK_WRITE(mx->preference);
		RR_CHECK_WRITE_DOMAIN(mx->exchange);

		// reset the data-size
		dataLen = (uint16_t)(pch - dataPtr - 2);
		*(uint16_t *)dataPtr = htons(dataLen);

		// done
		return pch;
	} else if (auto ptr = std::get_if<PTRData>(&record.value)) {
		if ((record.type != RecordType::CNAME && record.type != RecordType::PTR) ||
				ptr->empty()) {
			// illegal
			return nullptr;
		}

		// save the data-size ptr
		dataPtr = pch;
		RR_CHECK_WRITE(dataLen);

		// write preference name
		RR_CHECK_WRITE_DOMAIN(*ptr);

		// reset the data-size
		dataLen = (uint16_t)(pch - dataPtr - 2);
		*(uint16_t *)dataPtr = htons(dataLen);

		// done
		return pch;
	} else if (auto t = std::get_if<TXTData>(&record.value)) {
		if ((record.type != RecordType::TXT && record.type != RecordType::SPF) ||
				t->txt.empty() ||
				t->size != t->txt.size()) {
			// illegal
			return nullptr;
		}

		// save the data-size ptr
		dataPtr = pch;
		RR_CHECK_WRITE(dataLen);

		// write text
		RR_CHECK_WRITE(t->size);
		RR_CHECK_WRITE(t->txt);

		// reset the data-size
		dataLen = (uint16_t)(pch - dataPtr - 2);
		*(uint16_t *)dataPtr = htons(dataLen);

		// done
		return pch;
	}
	return nullptr;
}

static uint8_t *WriteQuestionToPacket(uint8_t *pch, uint8_t *pchEnd, const DnsQuestion &question, DnsNameCompressionContext *compressCtx) {
#define RR_CHECK_WRITE(_v_)                    \
	pch = WriteMetaToPacket(pch, pchEnd, _v_); \
	if (!pch)                                  \
		return {}
#define RR_CHECK_WRITE_DOMAIN(_v_)                          \
	pch = WriteMetaToPacket(pch, pchEnd, _v_, compressCtx); \
	if (!pch)                                               \
		return {}

	RR_CHECK_WRITE_DOMAIN(question.name);
	RR_CHECK_WRITE(question.type);
	RR_CHECK_WRITE(question.cls);
	return pch;
}

}; // namespace impl

//
// parse a sequence of bytes into a structured DNS message
//
static std::tuple<bool, DnsMessage> Parse(const uint8_t *buf, size_t bufSize) {
	static_assert(sizeof(DnsMessage::dnsHead) == 4);
	//
	// +0x00 Xid
	// +0x02 Flags1
	// +0x03 Flags2
	// +0x04 Question count
	// +0x06 Answer record count
	// +0x08 Authority record count
	// +0x0A Additional record count
	//
	if (bufSize < 0x0c) {
		return { false, {} };
	}
	auto headerVars = (const DnsHeaderVars *)buf;

	size_t offset = sizeof(DnsHeaderVars);
	auto questionCount = ntohs(*(uint16_t *)(buf + offset));
	auto anwserCount = ntohs(*(uint16_t *)(buf + offset + sizeof(uint16_t)));
	auto authoriyCount = ntohs(*(uint16_t *)(buf + offset + sizeof(uint16_t) * 2));
	auto additonalCount = ntohs(*(uint16_t *)(buf + offset + sizeof(uint16_t) * 3));
	offset += sizeof(uint16_t) * 4;
	assert(offset == 0x0c);

	// extract records
	impl::DnsRecordExtractor extractor(buf, buf + bufSize);
	DnsMessage result;
	for (auto idx = 0; idx < questionCount; idx++) {
		auto [qsize, question] = extractor.ExtractQuestion(offset);
		if (!qsize) {
			return {};
		}
		result.questions.emplace_back(std::move(question));
		offset += qsize;
	}

	if (headerVars->isResponse) {
		for (auto idx = 0; idx < anwserCount; idx++) {
			auto [rsize, record] = extractor.ExtractAnwser(offset);
			if (!rsize) {
				return {};
			}
			offset += rsize;
			result.answers.emplace_back(std::move(record));
		}

		for (auto idx = 0; idx < authoriyCount; idx++) {
			auto [rsize, record] = extractor.ExtractAnwser(offset);
			if (!rsize) {
				return {};
			}
			offset += rsize;
			result.authorityAnwsers.emplace_back(std::move(record));
		}

		for (auto idx = 0; idx < additonalCount; idx++) {
			auto [rsize, record] = extractor.ExtractAnwser(offset);
			if (!rsize) {
				return {};
			}
			offset += rsize;
			result.additionalAnwsers.emplace_back(std::move(record));
		}
	}

	// copy headers
	memcpy(&result.dnsHead, headerVars, sizeof(DnsHeaderVars));
	result.dnsHead.xid = ntohs(headerVars->xid);

	// done
	return { true, std::move(result) };
}

//
// build structured DNS message into raw bytes buffer
//
static std::vector<std::byte> Build(const DnsMessage &message) {
	static_assert(sizeof(DnsHeaderVars) == 4);

	if (!message.dnsHead.xid ||
			message.questions.size() != 1) {
		return {};
	}

	if (message.dnsHead.isResponse &&
			message.answers.empty()) {
		return {};
	}

	std::vector<std::byte> result;
	result.resize(impl::MAX_UDP_DNS_PACKET_SIZE);
	if (result.empty()) {
		return {};
	}

	//
	// +0x00 Xid
	// +0x02 Flags1
	// +0x03 Flags2
	// +0x04 Question count
	// +0x06 Answer record count
	// +0x08 Authority record count
	// +0x0A Additional record count
	//

	// prepare to write
	auto pchBegin = (uint8_t *)&result[0];
	auto pchEnd = pchBegin + result.size();
	auto pch = pchBegin;
#define CHECK_WRITE(_v_)                             \
	pch = impl::WriteMetaToPacket(pch, pchEnd, _v_); \
	if (!pch)                                        \
		return {}

	// write headers
	memcpy(pchBegin, &message.dnsHead, sizeof(DnsHeaderVars));
	CHECK_WRITE(message.dnsHead.xid);
	pch += 2;
	CHECK_WRITE((uint16_t)message.questions.size());
	CHECK_WRITE((uint16_t)message.answers.size());
	CHECK_WRITE((uint16_t)message.authorityAnwsers.size());
	CHECK_WRITE((uint16_t)message.additionalAnwsers.size());

	impl::DnsNameCompressionContext compressCtx(pchBegin, pchEnd);
	auto bodyPtr = pch;

	// write questions
	pch = impl::WriteQuestionToPacket(pch, pchEnd, message.questions[0], &compressCtx);
	if (!pch) {
		return {};
	}

	// write answers
	for (const auto &answer : message.answers) {
		pch = impl::WriteRecordToPacket(pch, pchEnd, answer, &compressCtx);
		if (!pch)
			return {};
	}
	for (const auto &authority : message.authorityAnwsers) {
		pch = impl::WriteRecordToPacket(pch, pchEnd, authority, &compressCtx);
		if (!pch)
			return {};
	}
	for (const auto &additional : message.additionalAnwsers) {
		pch = impl::WriteRecordToPacket(pch, pchEnd, additional, &compressCtx);
		if (!pch)
			return {};
	}
	if (pch == bodyPtr) {
		// nothing written
		return {};
	}

	// done
	result.resize(pch - pchBegin);
	return result;
}
}; // namespace dns

#endif //_LIB_DNS_PACKET_H_