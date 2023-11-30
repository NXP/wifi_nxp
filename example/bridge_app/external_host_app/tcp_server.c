#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/times.h>

typedef struct _iperf_set_t
{
    uint32_t iperf_type;
    uint32_t iperf_count;
    uint32_t iperf_udp_rate;
    uint32_t iperf_udp_time;
} iperf_set_t;

typedef struct _iperf_thead_data
{
    iperf_set_t iperf_set;
    int sockfd;
    long long pkt_size;
    int per_pkt_size;
    struct sockaddr_in *clientaddr;
    socklen_t addrlen;
} iperf_thead_data;

enum ncp_iperf_item
{
    NCP_IPERF_TCP_TX,
    NCP_IPERF_TCP_RX,
    NCP_IPERF_UDP_TX,
    NCP_IPERF_UDP_RX,
};

#ifndef NCP_IPERF_TCP_SERVER_PORT_DEFAULT
#define NCP_IPERF_TCP_SERVER_PORT_DEFAULT 5001
#define NCP_IPERF_UDP_SERVER_PORT_DEFAULT NCP_IPERF_TCP_SERVER_PORT_DEFAULT + 2
#endif
#define NCP_IPERF_PKG_COUNT        100000
#define NCP_IPERF_TCP_PER_PKG_SIZE 1448
#define NCP_IPERF_UDP_PER_PKG_SIZE 1472
#define NCP_IPERF_END_TOKEN_SIZE   11
char buf[NCP_IPERF_UDP_PER_PKG_SIZE]      = {0};
char send_buf[NCP_IPERF_UDP_PER_PKG_SIZE] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
};
char lwiperf_end_token[NCP_IPERF_END_TOKEN_SIZE] = {'N', 'C', 'P', 'I', 'P', 'E', 'R', 'P', 'E', 'N', 'D'};

extern int gettimeofday();

#define DUMP_WRAPAROUND 16
void dump_hex(const void *data, unsigned len)
{
    (void)printf("**** Dump @ %p Len: %d ****\n\r", data, len);

    unsigned int i;
    const char *data8 = (const char *)data;
    for (i = 0; i < len;)
    {
        (void)printf("%02x ", data8[i++]);
        if (!(i % DUMP_WRAPAROUND))
            (void)printf("\n\r");
    }

    (void)printf("\n\r******** End Dump *******\n\r");
}

void *send_data(void *arg);
void *recv_data(void *arg);

void start_thread(iperf_thead_data *td)
{
    td->pkt_size = td->iperf_set.iperf_count * td->per_pkt_size;
    printf("type = %d, size = %lld\n", td->iperf_set.iperf_type, td->pkt_size);
    pthread_t tx_thread, rx_thread;
    switch (td->iperf_set.iperf_type)
    {
        case NCP_IPERF_TCP_RX:
        case NCP_IPERF_UDP_RX:
            /*send data thread*/
            printf("tx_thread start\n");
            pthread_create(&tx_thread, NULL, send_data, (void *)td);
            pthread_join(tx_thread, NULL);
            printf("tx_thread finish\n");
            break;
        case NCP_IPERF_TCP_TX:
        case NCP_IPERF_UDP_TX:
            printf("rx_thread start\n");
            pthread_create(&rx_thread, NULL, recv_data, (void *)td);
            pthread_join(rx_thread, NULL);
            printf("rx_thread finish\n");
            break;
        default:
            printf("setting direction is error\n");
            break;
    }
}

int start_tcp(void)
{
    int ret = 0;
    iperf_thead_data td;
    /*create socket*/
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return sockfd;
    }

    /*port multi use*/
    int on = 1;
    ret    = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0)
    {
        perror("setsockopt");
        return -1;
    }

    /*bind ip addr and port*/
    struct sockaddr_in serveraddr = {0};
    serveraddr.sin_family         = AF_INET;
    serveraddr.sin_port           = htons(NCP_IPERF_TCP_SERVER_PORT_DEFAULT);
    serveraddr.sin_addr.s_addr    = htonl(INADDR_ANY);

    int addr_len = sizeof(serveraddr);

    ret = bind(sockfd, (struct sockaddr *)&serveraddr, addr_len);
    if (ret < 0)
    {
        perror("bind");
        return ret;
    }

    /*listen*/
    ret = listen(sockfd, 10);
    if (ret < 0)
    {
        perror("listen");
        return ret;
    }

    printf("tcp server start....\n");

    struct sockaddr_in clientaddr = {0};
    int ncp_bridge_fd             = -1;

    addr_len = sizeof(clientaddr);
    while (1)
    {
        printf("wait a client....\n");
        /*wait client connect*/
        ncp_bridge_fd = accept(sockfd, (struct sockaddr *)&clientaddr, &addr_len);
        if (ncp_bridge_fd < 0)
        {
            perror("ncp bridge server accept");
            return -1;
        }

        printf("client ip:%s client port:%d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

        printf("wait setting\n");
        if (0 > recv(ncp_bridge_fd, (char *)(&td.iperf_set), sizeof(iperf_set_t), 0))
        {
            printf("get setting fail\n");
            close(ncp_bridge_fd);
            continue;
        }

        td.sockfd       = ncp_bridge_fd;
        td.per_pkt_size = NCP_IPERF_TCP_PER_PKG_SIZE;
        start_thread(&td);
        close(ncp_bridge_fd);
    }
    close(sockfd);
}

int start_udp(void)
{
    int ret;
    struct sockaddr_in serveraddr, clientaddr;
    socklen_t addr_len;
    int sockfd;
    iperf_thead_data td;

    /*create udp socket*/
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return sockfd;
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family      = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port        = htons(NCP_IPERF_UDP_SERVER_PORT_DEFAULT);

    ret = bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (0 > ret)
    {
        perror("bind");
        return ret;
    }

    printf("udp server start\n");

    addr_len = sizeof(clientaddr);
    while (1)
    {
        printf("wait setting\n");
        /*wait client connect*/
        ret = recvfrom(sockfd, (char *)(&td.iperf_set), sizeof(iperf_set_t), 0, (struct sockaddr *)&clientaddr,
                       &addr_len);
        if (ret <= 0)
        {
            perror("ncp bridge udp server recvfrom fail");
            continue;
        }
        printf("client ip:%s client port:%d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
        td.sockfd       = sockfd;
        td.per_pkt_size = NCP_IPERF_UDP_PER_PKG_SIZE;
        td.clientaddr   = &clientaddr;
        td.addrlen      = addr_len;
        start_thread(&td);
    }
    close(sockfd);
}

int main(int argc, const char *argv[])
{
    int ret = 0;
    /*fork two process, one is for tcp server, and two is for udp server*/
    pid_t pid = fork();
    if (pid < 0)
        perror("fork");
    else if (pid > 0) /*parent for tcp*/
    {
        if (0 > start_tcp())
            printf("start tcp fail\n");
    }
    else if (pid == 0) /*child for udp*/
    {
        if (0 > start_udp())
            printf("start tcp fail\n");
    }
    return 0;
}

/*send data thread*/
void *send_data(void *arg)
{
    int fd                = -1;
    int i                 = 0;
    int ret               = 0;
    long long send_sum    = 0;
    iperf_thead_data *td  = (iperf_thead_data *)arg;
    fd                    = td->sockfd;
    iperf_set_t iperf_set = td->iperf_set;
    long long pkt_size    = td->pkt_size;
    int per_pkt_size      = td->per_pkt_size;
    printf("ncp bridge iperf start tx\n");
    struct sockaddr_in *clientaddr = td->clientaddr;
    socklen_t *addrlen             = &td->addrlen;
    long long udp_rate             = iperf_set.iperf_udp_rate;
    int pkt_num_per_xms            = 0;

    long long start_time_us = 0, prev_time_us = 0, cur_time_us = 0;
    int rate = 0;
    struct timeval prev_time, cur_time;
    int send_interval = 1;
    if (udp_rate <= 30)
        send_interval = 4;
    else if (udp_rate <= 60)
        send_interval = 2;
    else
        send_interval = 1;
    pkt_num_per_xms =
        ((udp_rate * 1024 * 1024 / 8) / per_pkt_size / (1000 / send_interval)); /*num pkt per send_interval(ms)*/

    gettimeofday(&prev_time, NULL);
    prev_time_us  = prev_time.tv_sec * 1000 * 1000 + prev_time.tv_usec;
    start_time_us = prev_time_us;
    while (send_sum < pkt_size)
    {
        if (iperf_set.iperf_type == NCP_IPERF_TCP_RX)
            ret = send(fd, send_buf, per_pkt_size, 0);
        else if (iperf_set.iperf_type == NCP_IPERF_UDP_RX)
        {
            ret = sendto(fd, send_buf, per_pkt_size, 0, (struct sockaddr *)clientaddr, *addrlen);
            gettimeofday(&cur_time, NULL);
            cur_time_us = cur_time.tv_sec * 1000 * 1000 + cur_time.tv_usec;
            if (!(i % pkt_num_per_xms))
            {
                long long delta = prev_time_us + (1000 * send_interval) - cur_time_us;
                printf("prev_time_us = %lld, cur_time_us = %lld, delta = %lld, pkt_num_per1ms = %d, i = %d\n",
                       prev_time_us, cur_time_us, delta, pkt_num_per_xms, i);
                if (delta > 0)
                    usleep(delta);
                prev_time_us += (1000 * send_interval);
            }
        }
        else
            printf("socket type is error\n");
        if (ret == -EAGAIN)
        {
            printf("ncp bridge iperf send buffer is full\n");
            usleep(1);
        }
        else if (ret < 0)
        {
            printf("ncp bridge iperf send data fail\n");
            printf("ncp bridge iperf end tx\n");
            break;
        }
        else
            send_sum += ret;
        i++;
        if (!(i % 1000))
            printf("ncp bridge iperf send data pkg = %d, send_sum = %lld\n", i, send_sum);
    }
    gettimeofday(&cur_time, NULL);
    cur_time_us = cur_time.tv_sec * 1000 * 1000 + cur_time.tv_usec;
    rate        = send_sum * 1000000 * 8 / (cur_time_us - start_time_us) / (1024);
    printf("ncp bridge iperf end tx\n");
    printf("tcp rx rate = %dkbit\n", rate);
}

/*recv data thread*/
void *recv_data(void *arg)
{
    char buf[NCP_IPERF_UDP_PER_PKG_SIZE] = {0};
    int fd                               = 0;
    int ret                              = 0;
    static int iperf_running_flag        = 0;
    unsigned long recv_len_sum           = 0;
    long long rate                       = 0;
    long long total_time_ms              = 0;
    struct timeval iperf_timer_start;
    struct timeval iperf_timer_end;
    iperf_thead_data *td           = (iperf_thead_data *)arg;
    fd                             = td->sockfd;
    iperf_set_t iperf_set          = td->iperf_set;
    long long pkt_size             = td->pkt_size;
    int per_pkt_size               = td->per_pkt_size;
    struct sockaddr_in *clientaddr = td->clientaddr;
    socklen_t *addrlen             = &td->addrlen;

    printf("ncp bridge iperf start rx\n");

    while (recv_len_sum < pkt_size)
    {
        if (iperf_set.iperf_type == NCP_IPERF_TCP_TX)
            ret = recv(fd, buf, per_pkt_size, 0);
        else if (iperf_set.iperf_type == NCP_IPERF_UDP_TX)
            ret = recvfrom(fd, buf, per_pkt_size, 0, (struct sockaddr *)clientaddr, addrlen);
        else
            printf("socket type is error\n");

        if (0 == iperf_running_flag)
        {
            gettimeofday(&iperf_timer_start, NULL);
        }

        if (ret <= 0)
        {
            perror("ncp bridge server recv");
            printf("ncp bridge iperf end rx\n");

            gettimeofday(&iperf_timer_end, NULL);
            total_time_ms = (iperf_timer_end.tv_sec - iperf_timer_start.tv_sec) * 1000 +
                            (iperf_timer_end.tv_usec - iperf_timer_start.tv_usec) / 1000;
            rate = ((long long)recv_len_sum) / total_time_ms;
            rate = rate * 8 / 1024;

            (void)printf("total_time_ms :%lld , iperf rate = %lld kbit/s\r\n", total_time_ms, rate);
            iperf_running_flag = 0;
            return NULL;
        }

        iperf_running_flag = 1;
        /*Update timer*/
        recv_len_sum += ret;

        /*Client data transfer finished*/
        if (0 == memcmp(buf, lwiperf_end_token, NCP_IPERF_END_TOKEN_SIZE))
        {
            printf("iperf finished\n\r");
            iperf_running_flag = 0;
            break;
        }
        else
        {
            gettimeofday(&iperf_timer_end, NULL);
        }
    }
    printf("ncp bridge iperf end rx\n");

    total_time_ms = (iperf_timer_end.tv_sec - iperf_timer_start.tv_sec) * 1000 +
                    (iperf_timer_end.tv_usec - iperf_timer_start.tv_usec) / 1000;
    rate = ((long long)recv_len_sum * 1000) / total_time_ms;
    rate = rate * 8 / 1024;

    iperf_running_flag = 0;
    (void)printf("start secs:%ld , usecs:%ld \r\n", iperf_timer_start.tv_sec, iperf_timer_start.tv_usec);
    (void)printf("end   secs:%ld , usecs:%ld \r\n", iperf_timer_end.tv_sec, iperf_timer_end.tv_usec);
    (void)printf("total_time_ms :%lld , iperf rate = %lld kbit/s\r\n", total_time_ms, rate);
}
