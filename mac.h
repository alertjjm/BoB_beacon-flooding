#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>

struct Mac final {
	static const int SIZE = 6;

	//
	// constructor
	//
	Mac() {}
	Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
	Mac(const std::string r);
	Mac(const struct sockaddr s);
	//
	// casting operator
	//
	operator uint8_t*() const { return const_cast<uint8_t*>(mac_); } // default
	explicit operator std::string() const;

	//
	// comparison operator
	//
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) < 0; }
	bool operator > (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) > 0; }
public:
	uint8_t mac_[SIZE];
};

namespace std {
	template<>
	struct hash<Mac> {
		size_t operator() (const Mac & rhs) const {
			size_t h1 = std::hash<std::uint32_t>{}(rhs.mac_[0]);
            for(int i=1; i<Mac::SIZE; i++)
				h1=h1^(rhs.mac_[i]<<1);
            return h1;
		}
	};
}
