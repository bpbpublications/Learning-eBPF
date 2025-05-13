#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define SERVER_PORT 10000
int redir_key = 0;

static int setup_listening_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket (listen)");
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (listen(sock, 10) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    return sock;
}

static int setup_client_socket(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket (client)");
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

int main() {
    struct bpf_object *obj = bpf_object__open_file("sk_skb.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "sock_store");
    int redir_fd = bpf_object__find_map_fd_by_name(obj, "sock_redir");

    if (map_fd < 0 || redir_fd < 0) {
        fprintf(stderr, "Failed to find map FDs\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "bpf_prog_verdict"));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_prog_attach(prog_fd, map_fd, BPF_SK_SKB_STREAM_VERDICT, 0) < 0 ||
        bpf_prog_attach(prog_fd, redir_fd, BPF_SK_SKB_STREAM_VERDICT, 0) < 0) {
        fprintf(stderr, "Failed to attach BPF prog: %s\n", strerror(errno));
        return 1;
    }

    int listen_sock = setup_listening_socket(SERVER_PORT);
    if (listen_sock < 0) return 1;

    // Spawn client socket (in a real deployment this would be external)
    int client_sock = setup_client_socket("127.0.0.1", SERVER_PORT);
    if (client_sock < 0) return 1;

    int accepted_sock = accept(listen_sock, NULL, NULL);
    if (accepted_sock < 0) {
        perror("accept");
        return 1;
    }

    // Update sockmaps
    if (bpf_map_update_elem(map_fd, &redir_key, &accepted_sock, BPF_ANY) < 0) {
        perror("map_store update failed");
        return 1;
    }
    if (bpf_map_update_elem(redir_fd, &redir_key, &client_sock, BPF_ANY) < 0) {
        perror("map_redir update failed");
        return 1;
    }

    printf("Inserted sockets into sockmaps\n");

    // Try to trigger BPF logic
    char msg[] = "hello server!";
    char buf[128] = {};

    send(client_sock, msg, sizeof(msg), 0);
    recv(accepted_sock, buf, sizeof(buf), 0);

    printf("Received at server: %s\n", buf);

    // Now try reverse
    char reply[] = "hello client!";
    send(accepted_sock, reply, sizeof(reply), 0);
    recv(client_sock, buf, sizeof(buf), 0);

    printf("Received at client: %s\n", buf);

    printf("Test complete. Check dmesg or trace_pipe for BPF output.\n");

    close(listen_sock);
    close(client_sock);
    close(accepted_sock);
    return 0;
}
