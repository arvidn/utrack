
#include <array>

struct packet_socket
{
	explicit packet_socket(bool receive = false);
	~packet_socket();
	packet_socket(packet_socket&& s);
	packet_socket(packet_socket const&) = delete;

	void close();

	bool send(iovec const* v, int num, sockaddr const* to, socklen_t tolen);

	// fills in the in_packets array with incoming packets. Returns the number filled in
	int receive(incoming_packet_t* in_packets, int num);
private:
	int m_socket;
	// this buffer needs to be aligned, because we
	// overlay structs to parse out packets
	std::array<uint64_t, 1500/8> m_buffer;
	bool m_receive;
};

