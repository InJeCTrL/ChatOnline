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

char *base64(const unsigned char *input, int length)
{
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

int disConnect(int fd_client)
{
    close(fd_client);
    for (int i = 0; i < MAXCONN; i++)
    {
        if (fds_client[i] == fd_client)
        {
            fds_client[i] = 0;
            break;
        }
    }
    
    return S_OK;
}

unsigned char* maskPayload(unsigned char *payload, long long len_payload, unsigned char *mask)
{
    unsigned char *Data = (unsigned char*)malloc(len_payload * sizeof(unsigned char));

    for (long long i = 0; i < len_payload; i++)
    {
        Data[i] = payload[i] ^ mask[i % 4];
    }

    return Data;
}

void* procRequest(void *data)
{
    unsigned char first, opcode, mask_len_payload, ex1_len_payload[2], ex2_len_payload[8], MaskingKey[4], payload[64];
    long long len_payload;
    unsigned char buf[BUFFSIZE] = { 0 };
    int len_recv;
    long long len_buf = 0;
    int fd_client = *(int*)data;

    while (1)
    {
        if ((len_recv = recv(fd_client, &first, 1, 0)) > 0)
        {
            memcpy(buf + len_buf, &first, 1);
            opcode = first & 0B00001111;
            len_buf++;
        }
        if (len_recv <= 0 || opcode == 8)
        {
            disConnect(fd_client);
            break;
        }
        if ((len_recv = recv(fd_client, &mask_len_payload, 1, 0)) > 0)
        {
            memcpy(buf + len_buf, &mask_len_payload, 1);
            len_buf++;
            if ((mask_len_payload & 0B01111111) == 126)
            {
                if ((len_recv = recv(fd_client, ex1_len_payload, 2, 0)) > 0)
                {
                    memcpy(buf + len_buf, ex1_len_payload, 2);
                    len_buf += 2;
                    len_payload = ex1_len_payload[0];
                    len_payload <<= 8;
                    len_payload |= ex2_len_payload[1];
                }
            }
            else if ((mask_len_payload & 0B01111111) == 127)
            {
                if ((len_recv = recv(fd_client, ex2_len_payload, 8, 0)) > 0)
                {
                    memcpy(buf + len_buf, ex2_len_payload, 8);
                    len_buf += 8;
                    for (int i = 0; i < 8; i++)
                    {
                        len_payload |= ex2_len_payload[i];
                        len_payload <<= 8;
                    }
                }
            }
            else
            {
                len_payload = mask_len_payload & 0B01111111;
            }
            if (len_recv <= 0)
            {
                disConnect(fd_client);
                break;
            }
        }
        else
        {
            disConnect(fd_client);
            break;
        }
        if ((len_recv = recv(fd_client, MaskingKey, 4, 0)) > 0)
        {
            memcpy(buf + len_buf, MaskingKey, 4);
            len_buf += 4;
        }
        else
        {
            disConnect(fd_client);
            break;
        }
        if ((len_recv = recv(fd_client, payload, len_payload, 0)) > 0)
        {
            unsigned char *p = maskPayload(payload, len_payload, MaskingKey);
            //memcpy(buf + len_buf, p, len_payload);
            memcpy(buf + len_buf, payload, len_payload);
            len_buf += len_payload;
            free(p);
        }
        else
        {
            disConnect(fd_client);
            break;
        }
        for (int i = 0; i < MAXCONN; i++)
        {
            if (fds_client[i])
                send(fds_client[i], buf, len_buf, 0);
        }
        // clean
        len_buf = 0;
        len_payload = 0;
        memset(buf, 0, BUFFSIZE);
    }

    return S_OK;
}

int handshake(int fd_client)
{
    const unsigned char magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char handshake[BUFFSIZE] = "HTTP/1.1 101 Switching Protocols\r\n"
                                        "Upgrade: websocket\r\n"
                                        "Connection: Upgrade\r\n"
                                        "Sec-WebSocket-Accept: ";
    unsigned char key_recv[BUFFSIZE] = { 0 }, key_sha1[BUFFSIZE] = { 0 };
    unsigned char *ptr_buf = NULL, *key_base64 = NULL;
    unsigned char buf[BUFFSIZE] = { 0 };
    ssize_t len_recv;

    if ((len_recv = recv(fd_client, buf, BUFFSIZE, 0)) > 0)
    {
        buf[len_recv] = 0;
        ptr_buf = strstr(buf, "Sec-WebSocket-Key: ");
        sscanf(ptr_buf, "Sec-WebSocket-Key: %s\r\n", key_recv);
        strcat(key_recv, magic);
        SHA1(key_recv, strlen(key_recv), key_sha1);
        key_base64 = base64(key_sha1, strlen(key_sha1));
        strcat(handshake, key_base64);
        strcat(handshake, "\r\n\r\n");
        send(fd_client, handshake, strlen(handshake), 0);
        free(key_base64);
        return S_OK;
    }
    else
    {
        return S_FAIL;
    }
}

int procConn(int fd_servsock)
{
    struct sockaddr_in sca;     // record addr(client)
    socklen_t len_cfd = sizeof(struct sockaddr);
    int fd_client;     // file descriptor of client socket
    pthread_t tid;
    int index_fd;

    while (1)
    {
        if ((fd_client = accept(fd_servsock, (struct sockaddr*)&sca, &len_cfd)) < 0)
        {
            perror("log >> fail to connect");
        }
        else
        {
            if (handshake(fd_client) == S_OK)
            {
                for (index_fd = 0; index_fd < MAXCONN; index_fd++)
                {
                    if (!fds_client[index_fd])
                    {
                        fds_client[index_fd] = fd_client;
                        pthread_create(&tid, NULL, procRequest, (void*)&fd_client);
                        break;
                    }
                }
            }
        }
    }

    return S_OK;
}

int initSocket(int *fd_server)
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
    *fd_server = _fd;

    return S_OK;
}

int main(int argc, char *argv[])
{
    int fd_server = 0;    // file descriptor of server socket

    if (initSocket(&fd_server) == S_FAIL)
        return S_FAIL;
    procConn(fd_server);
    
    return S_OK;
}