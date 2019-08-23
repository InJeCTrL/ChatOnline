#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define BUFFSIZE        8192
#define MAXCONN         20
#define PORT            12345
#define S_OK            0
#define S_FAIL          1

int fds_client[MAXCONN] = { 0 };

char *base64(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buff;
}

int procResponse(int fd_cliesock, unsigned char buf[], int len)
{
    unsigned char key_recv[BUFFSIZE] = { 0 }, key_sha1[BUFFSIZE] = { 0 };
    const unsigned char magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char *ptr_buf = NULL, *key_base64 = NULL;
    unsigned char handshake[BUFFSIZE] = "HTTP/1.1 101 Switching Protocols\r\n"
                                        "Upgrade: websocket\r\n"
                                        "Connection: Upgrade\r\n"
                                        "Sec-WebSocket-Accept: ";

    if (ptr_buf = strstr(buf, "Sec-WebSocket-Key: "))
    {
        sscanf(ptr_buf, "Sec-WebSocket-Key: %s\r\n", key_recv);
        strcat(key_recv, magic);
        SHA1(key_recv, strlen(key_recv), key_sha1);
        key_base64 = base64(key_sha1, strlen(key_sha1));
        strcat(handshake, key_base64);
        strcat(handshake, "\r\n\r\n");
        send(fd_cliesock, handshake, strlen(handshake), 0);
        free(key_base64);
    }
    else
    {
        char opcode = buf[0] & 15;
        if (opcode != 8)
        {
            for (int i = 0; i < MAXCONN; i++)
            {
                if (fd_cliesock)
                    send(fds_client[i], buf, len, 0);
            }
        }
        else
        {
            send(fd_cliesock, buf, len, 0);
        }
    }

    return S_OK;
}
void* procRequest(void *data)
{
    unsigned char buf[BUFFSIZE] = { 0 };
    int fd_cliesock = *(int*)data;
    int len_recv;

    while((len_recv = recv(fd_cliesock, buf, BUFFSIZE, 0)) > 0)
    {
        buf[len_recv] = 0;
        procResponse(fd_cliesock, buf, len_recv);
        memset(buf, 0, BUFFSIZE);
    }
    close(fd_cliesock);
    for (int i = 0; i < MAXCONN; i++)
    {
        if (fds_client[i] == fd_cliesock)
        {
            fds_client[i] = 0;
            break;
        }
    }

    return S_OK;
}

int procConn(int fd_servsock)
{
    struct sockaddr_in sca;     // record addr(client)
    socklen_t len_cfd = sizeof(struct sockaddr);
    int fd_cliesock;     // file descriptor of client socket
    pthread_t tid;
    int index_fd;

    while (1)
    {
        if ((fd_cliesock = accept(fd_servsock, (struct sockaddr*)&sca, &len_cfd)) < 0)
        {
            perror("log >> fail to connect");
        }
        else
        {
            for (index_fd = 0; index_fd < MAXCONN; index_fd++)
            {
                if (!fds_client[index_fd])
                {
                    fds_client[index_fd] = fd_cliesock;
                    pthread_create(&tid, NULL, procRequest, (void*)&fd_cliesock);
                    break;
                }
            }
        }
    }

    return S_OK;
}

int initSocket(int *fd_servsock)
{
    struct sockaddr_in ssa; // record addr(server)
    int nOptval;
    int _fd;

    if ((_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("log >> fail to create socket");
        return S_FAIL;
    }
    setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&nOptval, sizeof(int));
    memset(&ssa,0,sizeof(struct sockaddr_in));
    ssa.sin_addr.s_addr = htonl(INADDR_ANY);
    ssa.sin_family = AF_INET;
    ssa.sin_port = htons(PORT);
    if (bind(_fd, (struct sockaddr*)&ssa,sizeof(struct sockaddr)) < 0)
    {
        perror("log >> fail to bind address");
        return S_FAIL;
    }
    if (listen(_fd, MAXCONN) < 0)
    {
        perror("log >> fail to set listen");
        return S_FAIL;
    }
    printf("Establishing...\n");
    *fd_servsock = _fd;

    return S_OK;
}

int main(int argc, char *argv[])
{
    int fd_servsock = 0;    // file descriptor of server socket

    if (initSocket(&fd_servsock) == S_FAIL)
        return S_FAIL;
    procConn(fd_servsock);
    
    return S_OK;
}