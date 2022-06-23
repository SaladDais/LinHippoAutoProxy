// Very bad thing I didn't want to write. Assumes little-endian.

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#ifdef MSG_WAITFORONE
#  define RECVMMSG_SUPPORTED
#endif

#define SOCK_BUFLEN 8096
#define LOCALHOST 0x0100007f

static int sProxySock = 0;
static uint16_t sProxyUDPPort = 0;
static bool sProxyEnabled = false;

#define SENDTO_SIG int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen
typedef ssize_t (*sendtoptr)(SENDTO_SIG);

#define SENDMSG_SIG int sockfd, const struct msghdr *msg, int flags
typedef ssize_t (*sendmsgptr)(SENDMSG_SIG);

#define RECVFROM_SIG int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen
typedef ssize_t (*recvfromptr)(RECVFROM_SIG);

#define RECVMSG_SIG int sockfd, struct msghdr *msg, int flags
typedef ssize_t (*recvmsgptr)(RECVMSG_SIG);

#define RECVMMSG_SIG int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout
typedef int (*recvmmsgptr)(RECVMMSG_SIG);

static sendtoptr sRealSendTo = nullptr;
static sendmsgptr sRealSendMsg = nullptr;
static recvfromptr sRealRecvFrom = nullptr;
static recvmsgptr sRealRecvMsg = nullptr;
#ifdef RECVMMSG_SUPPORTED
static recvmmsgptr sRealRecvMmsg = nullptr;
#endif

// Old pcaps make it seem like sizeof() sometimes includes alignment
// padding at the end of struct. Maybe not.
#define SOCKS_DATAGRAM_HEADER_SIZE 10

#pragma pack(push, 1)
struct socks5_datagram_header_t {
    uint16_t reserved;
    uint8_t fragment;
    uint8_t address_type;
    uint32_t address;
    uint16_t port;
};
#pragma pack(pop)


static bool is_proxied_datagram(int s, const struct sockaddr* addr) {
    int sock_type;
    socklen_t length = sizeof(int);

    if (!sProxyEnabled) {
        return false;
    }

    // Fail if we can't get socket option
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &length)) {
        return false;
    }

    // UDP only
    if (sock_type != SOCK_DGRAM) {
        return false;
    }

    // Addr has to be provided
    if (addr == nullptr) {
        return false;
    }

    // IPv4 only.
    if (addr->sa_family != AF_INET) {
        return false;
    }

    auto addr_in = (sockaddr_in*)addr;
    // Pass DNS through as-is no matter what.
    if (ntohs(addr_in->sin_port) == 53)
        return false;

    return true;
}

static ssize_t deproxify_inbound_msg(void *buf, ssize_t data_len, sockaddr* src_addr) {
    auto from_in = (sockaddr_in*)src_addr;
    // Didn't actually come from the proxy, pass it through
    if (from_in->sin_addr.s_addr != LOCALHOST) {
        return data_len;
    }

    // Not long enough to even have a header
    if (data_len < SOCKS_DATAGRAM_HEADER_SIZE) {
        return -1;
    }

    const socks5_datagram_header_t socks_header = *((socks5_datagram_header_t *)buf);

    // We don't know how to handle either of these cases.
    if (socks_header.reserved || socks_header.fragment) {
        return -1;
    }

    // lie about who we got the packet from using the SOCKS5 header
    from_in->sin_addr.s_addr = socks_header.address;
    from_in->sin_port = socks_header.port;

    // Remove the SOCKS 5 datagram header from the start of the buffer
    memmove(buf, (char*)buf + SOCKS_DATAGRAM_HEADER_SIZE, data_len - SOCKS_DATAGRAM_HEADER_SIZE);
    data_len -= SOCKS_DATAGRAM_HEADER_SIZE;
    return data_len;
}

ssize_t recvfrom(RECVFROM_SIG) {
    // Pass errors through as-is
    ssize_t data_len = sRealRecvFrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (data_len < 0) {
        return data_len;
    }

    // This isn't something that could even potentially be proxied.
    if (!is_proxied_datagram(sockfd, src_addr)) {
        return data_len;
    }

    return deproxify_inbound_msg(buf, data_len, src_addr);
}

static ssize_t deproxify_recvmsg_struct(int sockfd, struct msghdr *msg, ssize_t data_len) {
    // Don't know what to do about this case, sparse output buffer chunks.
    if (msg->msg_iovlen != 1) {
        return data_len;
    }
    if (msg->msg_namelen != sizeof (sockaddr)) {
        return data_len;
    }

    auto src_addr = (sockaddr*)msg->msg_name;
    // This isn't something that could even potentially be proxied.
    if (!is_proxied_datagram(sockfd, src_addr)) {
        return data_len;
    }

    return deproxify_inbound_msg(msg->msg_iov[0].iov_base, data_len, src_addr);
}

ssize_t recvmsg(RECVMSG_SIG) {
    ssize_t data_len = sRealRecvMsg(sockfd, msg, flags);
    if (data_len < 0) {
        return data_len;
    }
    return deproxify_recvmsg_struct(sockfd, msg, data_len);
}

#ifdef RECVMMSG_SUPPORTED
int recvmmsg(RECVMMSG_SIG) {
    int ret = sRealRecvMmsg(sockfd, msgvec, vlen, flags, timeout);
    if (ret > 0) {
        for(int i=0; i<ret; ++i) {
            ssize_t new_size = deproxify_recvmsg_struct(sockfd, &msgvec[i].msg_hdr, msgvec[i].msg_len);
            // Ugh, we have to pass invalid SOCKS messages through unused for now because I can't figure
            // out how to pretend we failed to receive them.
            if (new_size >= 0) {
                msgvec[i].msg_len = (unsigned int)new_size;
            }
        }
    }
    return ret;
}
#endif

ssize_t proxify_outbound_msg(sockaddr_in *proxy_to, const void *buf, ssize_t len, char *send_buf) {
    // Too large, can't send this at all.
    if (len + SOCKS_DATAGRAM_HEADER_SIZE >= SOCK_BUFLEN) {
        return -1;
    }

    // Write the SOCKS5 header at the start of the new packet
    auto socks_header = (socks5_datagram_header_t*)send_buf;
    socks_header->address = proxy_to->sin_addr.s_addr;
    socks_header->port = proxy_to->sin_port;
    socks_header->reserved = 0;
    socks_header->fragment = 0;
    socks_header->address_type = 1;

    // rewrite the to address to point to the proxy
    proxy_to->sin_port = sProxyUDPPort;
    proxy_to->sin_addr.s_addr = LOCALHOST;

    // Copy the original data over to the new packet
    memcpy(send_buf + SOCKS_DATAGRAM_HEADER_SIZE, buf, len);
    len += SOCKS_DATAGRAM_HEADER_SIZE;
    return len;
}

ssize_t sendto(SENDTO_SIG) {
    if (!is_proxied_datagram(sockfd, dest_addr)) {
        return sRealSendTo(sockfd, buf, len, flags, dest_addr, addrlen);
    }
    struct sockaddr_in proxy_to = *(sockaddr_in*)dest_addr;
    char send_buf[SOCK_BUFLEN] = { 0 };

    len = proxify_outbound_msg(&proxy_to, buf, (ssize_t)len, (char*)&send_buf);
    return sRealSendTo(sockfd, send_buf, len, flags, (sockaddr*)&proxy_to, addrlen);
}

ssize_t sendmsg(SENDMSG_SIG) {
    if (msg->msg_iovlen != 1 || msg->msg_namelen != sizeof (sockaddr)) {
        return sRealSendMsg(sockfd, msg, flags);
    }

    auto dest_addr = (sockaddr*)msg->msg_name;
    if(!is_proxied_datagram(sockfd, dest_addr)) {
        return sRealSendMsg(sockfd, msg, flags);
    }
    // msg is const, so we need to make a local copy
    auto new_msg = *msg;
    struct sockaddr_in proxy_to = *(sockaddr_in*)dest_addr;
    char send_buf[SOCK_BUFLEN] = { 0 };

    auto old_len = (ssize_t)msg->msg_iov[0].iov_len;
    ssize_t new_len = proxify_outbound_msg(&proxy_to, msg->msg_iov[0].iov_base, old_len, (char*)&send_buf);
    if(new_len >= 0) {
        new_msg.msg_iov[0].iov_len = new_len;
        new_msg.msg_iov[0].iov_base = send_buf;
        new_msg.msg_name = (void*)&proxy_to;
    }
    ssize_t ret = sRealSendMsg(sockfd, &new_msg, flags);
    if (ret > 0)
        ret -= (ssize_t)(new_len - old_len);
    return ret;
}

static bool blocking_socks5_handshake() {
    char recvbuf[SOCK_BUFLEN] = {0};
    int timeout = 1000;
    sockaddr_in proxy_addr = { 0 };

    sProxySock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sProxySock == -1) {
        fprintf(stderr, "Couldn't create a socket\n");
        return false;
    }
    setsockopt(sProxySock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sProxySock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = LOCALHOST;
    proxy_addr.sin_port = htons(9061);
    if (connect(sProxySock, (const sockaddr*)&proxy_addr, sizeof(sockaddr_in))) {
        fprintf(stderr, "Couldn't connect to SOCKS proxy, closing!\n");
        return false;
    }
    // SOCKS 5 handshake, no auth
    if (send(sProxySock, "\x05\x01\x00", 3, 0) != 3) {
        goto handshake_failed;
    }

    // failed to send
    if (recv(sProxySock, recvbuf, 2, 0) != 2) {
        goto handshake_failed;
    }
    // not SOCKS or unauthed not allowed.
    if (memcmp(recvbuf, "\x05\x00", 2) != 0) {
        goto handshake_failed;
    }

    // ask for a UDP association
    if (send(sProxySock, "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0) != 10) {
        fprintf(stderr, "Failed to ask for UDP association!\n");
        goto handshake_failed;
    }

    if (recv(sProxySock, recvbuf, 10, 0) != 10) {
        goto handshake_failed;
    }

    // Did we fail to get an IPv4 association
    if (memcmp(recvbuf, "\x05\x00\x00\x01", 4) != 0) {
        fprintf(stderr, "Didn't get a UDP association");
        goto handshake_failed;
    }

    // Don't care about the host. We assume it's localhost. Only get the port, network-endian.
    sProxyUDPPort = (*((uint16_t*)&recvbuf[8]));
    sProxyEnabled = true;
    return true;

handshake_failed:
    shutdown(sProxySock, SHUT_RDWR);
    close(sProxySock);
    fprintf(stderr, "SOCKS Proxy handshake failed!\n");
    return false;
}

__attribute__((constructor))
static void custom_init() {
    sRealSendTo = (sendtoptr)dlsym(RTLD_NEXT, "sendto");
    sRealSendMsg = (sendmsgptr)dlsym(RTLD_NEXT, "sendmsg");
    sRealRecvFrom = (recvfromptr)dlsym(RTLD_NEXT, "recvfrom");
    sRealRecvMsg = (recvmsgptr)dlsym(RTLD_NEXT, "recvmsg");
#ifdef RECVMMSG_SUPPORTED
    sRealRecvMmsg = (recvmmsgptr)dlsym(RTLD_NEXT, "recvmmsg");
#endif

    if (!blocking_socks5_handshake()) {
        exit(1);
    }
}


__attribute__((destructor))
static void custom_fini() {
    if (sProxyEnabled) {
        shutdown(sProxySock, SHUT_RDWR);
        close(sProxySock);
    }
}
