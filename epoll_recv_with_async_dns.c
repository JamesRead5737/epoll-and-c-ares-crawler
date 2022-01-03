#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <ares.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#define MAXWAITING 1000 /* Max. number of parallel DNS queries */
#define MAXTRIES      3 /* Max. number of tries per domain */
#define DNSTIMEOUT    3000 /* Max. number of ms for first try */
#define SERVERS    "1.0.0.1,8.8.8.8" /* DNS server to use (Cloudflare & Google) */
#define MAXDOMAINS 8192
#define PORT 80
#define MAXBUF 1024
#define MAX_EPOLL_EVENTS 8192
#define MAX_CONNECTIONS 8192
#define TIMEOUT 10000
int epfd;
int sockfd[MAX_CONNECTIONS];
struct epoll_event event[MAX_CONNECTIONS];
struct sockaddr_in dest[MAX_CONNECTIONS];
char resolved[MAXDOMAINS][254];
char ips[MAXDOMAINS][128];
int current = 0, active = 0, next = 0;
char servers[MAX_CONNECTIONS][128];
char domains[MAX_CONNECTIONS][254];
char get_buffer[MAX_CONNECTIONS][1024];
char buffer[MAX_CONNECTIONS][MAXBUF];
int buffer_used[MAX_CONNECTIONS];
struct timespec startTime, stopTime;
int i, num_ready, connections = 0, done = 0, total_bytes = 0, total_domains = 0, iterations = 0, count = 0;
FILE * fp;
struct epoll_event events[MAX_EPOLL_EVENTS];
static int nwaiting;

static void state_cb(void *data, int s, int read, int write)
{
	//printf("Change state fd %d read:%d write:%d\n", s, read, write);
}

static void callback(void *arg, int status, int timeouts, struct hostent *host)
{
	nwaiting--;

	if(!host || status != ARES_SUCCESS){
		//fprintf(stderr, "Failed to lookup %s\n", ares_strerror(status));
		return;
	}

	char ip[INET6_ADDRSTRLEN];

	if (host->h_addr_list[0] != NULL){
		inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, sizeof(ip));
		strcpy(resolved[current], host->h_name);
		strcpy(ips[current], ip);
		if (current < MAXDOMAINS - 1) current++; else current = 0;
		active++;
		printf("active %d\r", active);
	}
}

static void wait_ares(ares_channel channel)
{
	struct timeval *tvp, tv;
	fd_set read_fds, write_fds;
	int nfds;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	nfds = ares_fds(channel, &read_fds, &write_fds);

	if (nfds > 0) {
		tvp = ares_timeout(channel, NULL, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}
}

void make_socket_and_connect (int sock)
{
    if ( (sockfd[sock] = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0 ) {
        perror("Socket");
        exit(errno);
    }
    count++;
    event[sock].events = EPOLLIN|EPOLLOUT;
    event[sock].data.fd = sockfd[sock];
    epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd[sock], &event[sock]);
    bzero(&dest[sock], sizeof(dest[sock]));
    dest[sock].sin_family = AF_INET;
    dest[sock].sin_port = htons(PORT);
    if ( inet_pton(AF_INET, servers[sock], &dest[sock].sin_addr.s_addr) == 0 ) {
        printf("\n");
        perror(servers[sock]);
        exit(errno);
    }
    if ( connect(sockfd[sock], (struct sockaddr*)&dest[sock], sizeof(dest[sock])) != 0 ) {
        if(errno != EINPROGRESS) {
            printf("%s\n", servers[sock]);
            perror("Connect again ");
            //exit(errno);
        }
        buffer_used[sock] = 0;
    }
}

int is_valid_ip(char *domain)
{
    if (!strcmp(domain, "255.255.255.255"))
        return 0;
    if (!strcmp(domain, "192.168.1.0"))
        return 0;
    if (!strcmp(domain, "127.0.0.0"))
        return 0;
        
    return 1;
}

void close_socket (int socket)
{
    close(sockfd[socket]);
    count--;
    epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd[socket], &event[socket]);
}

void get_domain_and_ip(int id)
{
    close_socket(id);
    active--;
get_domain_name:
    strcpy(servers[id], ips[next]);
    strcpy(domains[id], resolved[next]);
    if (next < (MAXDOMAINS - 1)) next++; else next = 0;
    if (is_valid_ip(servers[id]))
    {
        make_socket_and_connect(id);
        total_domains++;
    }
    else
        goto get_domain_name;                
}

void get_domain_and_ip_without_connect(int id)
{
get_domain_name2:
    strcpy(servers[id], ips[next]);
    strcpy(domains[id], resolved[next]);
    if (next < (MAXDOMAINS - 1)) next++; else next = 0;
    if (!is_valid_ip(servers[id]))
        goto get_domain_name2;                
}

void get_time()
{
    clock_gettime(CLOCK_MONOTONIC, &stopTime);
    uint64_t msElapsed = (stopTime.tv_nsec - startTime.tv_nsec) / 1000000 + (stopTime.tv_sec - startTime.tv_sec) * 1000;
    double seconds = (double)msElapsed / 1000.0;
    iterations++;
    fprintf(stderr, "iterations=%d total domains=%d elapsed=%2.2fs domains/s=%2.2f KB=%d Mbit/s=%2.2f num_ready=%d count=%d active=%d end\r"
            , iterations, total_domains, seconds, total_domains/seconds, total_bytes/1024, 8*total_bytes/seconds/1024/1204, num_ready, count, active);
}

ssize_t send_data(int id)
{
    ssize_t nByte = send(sockfd[id], get_buffer[id] + buffer_used[id], strlen(get_buffer[id]) - buffer_used[id], 0);
    return nByte;
}

ssize_t recv_data(int id)
{
    ssize_t nByte = recv(sockfd[id], buffer[id], sizeof(buffer[id]), 0);
    return nByte;
}

int wait()
{
    int ret = epoll_wait(epfd, events, MAX_EPOLL_EVENTS, TIMEOUT/*timeout*/);
    return ret;
}
                
int main(int argc, char *argv[]) {
        
    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
    FILE * fp;
    char domain[254];
    size_t len = 0;
    ssize_t read;
    ares_channel channel;
    int status, dns_done = 0;
    int optmask;
	
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }

    struct ares_options options = {
        .timeout = DNSTIMEOUT,     /* set first query timeout */
        .tries = MAXTRIES       /* set max. number of tries */
    };
    optmask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;

    status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
        return 1;
    }

    status = ares_set_servers_csv(channel, SERVERS);
    if (status != ARES_SUCCESS) {
        printf("ares_set_servers_csv: %s\n", ares_strerror(status));
        return 1;
    }
	
    fp = fopen(argv[1], "r");
    if (!fp)
        exit(EXIT_FAILURE);

    do{
        if (nwaiting >= MAXWAITING || dns_done) {
            do {
                wait_ares(channel);
                
            } while (nwaiting > MAXWAITING);
        }
        if (!dns_done) {
            if (fscanf(fp, "%253s", domain) == 1) {
                ares_gethostbyname(channel, domain, AF_INET, callback, NULL);
                nwaiting++;
            } else {
                //fprintf(stderr, "done sending\n");
                dns_done = 1;
            }
        }
    } while (active < MAX_CONNECTIONS);
    
    /*---Open sockets for streaming---*/
    for (i = 0; i < MAX_CONNECTIONS; i++)
    { 
        if ( (sockfd[i] = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0 ) {
            perror("Socket");
            exit(errno);
        }
        count++;
    }

    /*---Add sockets to epoll---*/
    epfd = epoll_create1(0);
    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        event[i].events = EPOLLIN|EPOLLOUT; 
        event[i].data.fd = sockfd[i];
        epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd[i], &event[i]);
    }
    
    /*---Initialize server address/port structs---*/
    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        get_domain_and_ip_without_connect(i);
        //printf("%s %s\n", servers[i], domains[i]);
        bzero(&dest[i], sizeof(dest[i]));
        dest[i].sin_family = AF_INET;
        dest[i].sin_port = htons(PORT);
        if ( inet_pton(AF_INET, servers[i], &dest[i].sin_addr.s_addr) == 0 ) {
           perror(servers[i]);
           exit(errno);
        }
    }
    
    /*---Connect to servers---*/
    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        if ( connect(sockfd[i], (struct sockaddr*)&dest[i], sizeof(dest[i])) != 0 ) {
            if(errno != EINPROGRESS) {
                perror("Connect ");
                //exit(errno);
            }
            buffer_used[i] = 0;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &startTime);
    while (1)
    {
        /*---Do async DNS---*/
        do {
            if (nwaiting >= MAXWAITING || dns_done) {
                do {
                    wait_ares(channel);
                } while (nwaiting > MAXWAITING);
            }
            if (!dns_done) {
                if (fscanf(fp, "%253s", domain) == 1) {
                    ares_gethostbyname(channel, domain, AF_INET, callback, NULL);
                    nwaiting++;
                } else {
                    //fprintf(stderr, "done sending\n");
                    dns_done = 1;
                }
            }
        } while (active < MAXDOMAINS);
        /*---Wait to be able to send---*/
        num_ready = wait();
        get_time();
        if (!num_ready) break;
        for(i = 0; i < num_ready; i++) {
            int index;
            if(events[i].events & EPOLLOUT) {
                for (int j = 0; j < MAX_CONNECTIONS; j++)
                {
                    if (events[i].data.fd == sockfd[j])
                    {
                        index = j;
                        break;
                    }
                }
                snprintf(get_buffer[index], sizeof(get_buffer[index]), 
                "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\r\n\r\n", "/", domains[i]);
                ssize_t nByte = 0;
                if (buffer_used[index] < strlen(get_buffer[index]))
                    nByte = send_data(index);
                if (nByte > 0)
                {
                    buffer_used[index] += nByte;
                    total_bytes += nByte;
                }
                if (nByte == -1 && errno == EPIPE)
                {
                    get_domain_and_ip(index);
                }
            }
            if(events[i].events & EPOLLIN) {
                for (int j = 0; j < MAX_CONNECTIONS; j++)
                {
                    if (events[i].data.fd == sockfd[j])
                    {
                        index = j;
                        break;
                    }
                }
                bzero(buffer[index], MAXBUF);
                ssize_t nByte = recv_data(index);
                //if (nByte > 0) printf("Received: %s from %s at %s \n", buffer[index], domains[index], servers[index]);
                if (nByte > 0) total_bytes += nByte;
                if (nByte == 0)
                {
                    close_socket(index);
                    if (!done)
                    {
                        get_domain_and_ip(index);
                    }
                }
            }
        }
        get_time();
        if (done && count == 0) break;
    }
    ares_destroy(channel);
    ares_library_cleanup();
    fclose(fp);
    printf("\nFinished without errors\n");
    return 0;
}
