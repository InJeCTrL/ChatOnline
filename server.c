#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define BUFFSIZE        8192
#define MAXPLSIZE       8000
#define PORT            12345
#define MAXEVENT        100
#define S_OK            0
#define S_FAIL          1
#define S_MEM           2
#define MAGIC           "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// head of websocket frame
typedef struct
{
    int FIN;
    int RSV;
    int Opcode;
    int isMasked;
    int len_ch;
    long long len_Payload;
    unsigned char MaskingKey[4];
    unsigned char ch_len_Payload[9];
}info_webFramehead;
// save pointer of fd_server and fd_epoll
typedef struct
{
    int *pfd_server;
    int *pfd_epoll;
}fds;
// node of Queue
typedef struct QueueNode
{
    struct epoll_event *pEvt;
    struct QueueNode *next;
}QNode;
typedef struct
{
    QNode *head;
    QNode *tail;
}Queue;
typedef struct ListNode
{
    int fd;
    struct ListNode *next;
}LNode, List;

// semaphore and mutex
sem_t empty;
pthread_mutex_t mutex_Queue, mutex_List;

// eventQueue
Queue evtQueue;
// list of fd_client
List fdList = {0, NULL};

// encrypto input string by base64
int base64(const unsigned char *input, unsigned char **output, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    *output = (unsigned char *)malloc(bptr->length);
    if (!*output)
        return S_MEM;
    memcpy(*output, bptr->data, bptr->length-1);
    (*output)[bptr->length-1] = 0;

    BIO_free_all(b64);

    return S_OK;
}
// mask(unmask) payload
int maskPayload(unsigned char *payload, int len_payload, unsigned char *MaskingKey)
{
    for (int i = 0; i < len_payload; i++)
    {
        payload[i] ^= MaskingKey[i % 4];
    }

    return S_OK;
}
// analyse head of websocket frame
int analyseHead(int fd_client, info_webFramehead *headInfo)
{
    unsigned char tch, tbuf[8] = { 0 };
    int len_recv;

    // FIN(1 bit), RSV(3 bits) and Opcode(4 bits)
    if ((len_recv = recv(fd_client, &tch, 1, 0)) > 0)
    {
        headInfo->FIN = tch & 0B10000000;
        headInfo->RSV = tch & 0B01110000;
        headInfo->Opcode = tch & 0B00001111;
    }
    else if (len_recv == -1 && errno == EAGAIN)
    {
        free(headInfo);
        return S_FAIL;
    }
    // MASK(1 bit) and Payload len(7bs / 7bs+2Bs / 7bs+8Bs)
    if ((len_recv = recv(fd_client, &tch, 1, 0)) > 0)
    {
        headInfo->isMasked = tch & 0B10000000;
        int tlen = tch & 0B01111111;
        // Payload len is between 0 and 125 Bytes
        if (tlen < 126)
        {
            headInfo->len_Payload = tlen;
            headInfo->ch_len_Payload[0] = tlen;
            headInfo->len_ch = 1;
        }
        // Payload len is the value of next 2 Bytes
        else if (tlen == 126)
        {
            if ((len_recv = recv(fd_client, tbuf, 2, 0)) > 0)
            {
                headInfo->len_Payload = 0;
                for (int i = 0; i < 2; i++)
                {
                    headInfo->len_Payload |= tbuf[i];
                    headInfo->len_Payload <<= 8;
                }
                headInfo->ch_len_Payload[0] = 126;
                memcpy(headInfo->ch_len_Payload + 1, tbuf, 2);
                headInfo->len_ch = 3;
            }
            else if (len_recv == -1 && errno == EAGAIN)
            {
                free(headInfo);
                return S_FAIL;
            }
        }
        // Payload len is the value of next 8 Bytes
        else if (tlen == 127)
        {
            if ((len_recv = recv(fd_client, tbuf, 8, 0)) > 0)
            {
                headInfo->len_Payload = 0;
                for (int i = 0; i < 8; i++)
                {
                    headInfo->len_Payload |= tbuf[i];
                    headInfo->len_Payload <<= 8;
                }
                headInfo->ch_len_Payload[0] = 127;
                memcpy(headInfo->ch_len_Payload + 1, tbuf, 8);
                headInfo->len_ch = 9;
            }
            else if (len_recv == -1 && errno == EAGAIN)
            {
                free(headInfo);
                return S_FAIL;
            }
        }
        // protocol error
        else
        {
            free(headInfo);
            return S_FAIL;
        }
        
    }
    // Masking-Key(4 Bytes)
    if ((len_recv = recv(fd_client, tbuf, 4, 0)) > 0)
    {
        memcpy(headInfo->MaskingKey, tbuf, 4);
    }
    else if (len_recv == -1 && errno == EAGAIN)
    {
        free(headInfo);
        return S_FAIL;
    }

    return S_OK;
}
// read payload and unmask
int getPayload(int fd_client, unsigned char *Payload, unsigned char *MaskingKey, int num_toRead, int *num_hasRead)
{
    unsigned char tPayload[BUFFSIZE] = { 0 };
    int len_recv;

    if ((len_recv = recv(fd_client, tPayload, num_toRead, 0)) > 0)
    {
        maskPayload(tPayload, len_recv, MaskingKey);
        memcpy(Payload, tPayload, len_recv);
        *num_hasRead = len_recv;
    }
    else if (len_recv == -1 && errno == EAGAIN)
    {
        return S_FAIL;
    }

    return S_OK;
}
// send payload to client
int sendPayload(int fd_client, info_webFramehead *headInfo, unsigned char *Payload, int num_toSend, int *num_hasSent)
{
    unsigned char buf[BUFFSIZE] = { 0 };
    int len_snd = 1 + num_toSend;
    int len_s = 0;

    buf[0] = headInfo->FIN | headInfo->RSV | headInfo->Opcode;
    memcpy(buf + 1, headInfo->ch_len_Payload, headInfo->len_ch);
    memcpy(buf + 1 + headInfo->len_ch, Payload, num_toSend);
    len_snd += headInfo->len_ch;
    if ((len_s = send(fd_client, buf, len_snd, 0)) > 0)
    {
        *num_hasSent = num_toSend;
    }
    else if (len_s == -1 && errno == EAGAIN)
    {
        return S_FAIL;
    }

    return S_OK;
}
// receive and send handshake frame
int handshake(int fd_client)
{
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
        if (!ptr_buf)
            return S_FAIL;
        sscanf(ptr_buf, "Sec-WebSocket-Key: %s\r\n", key_recv);
        strcat(key_recv, MAGIC);
        SHA1(key_recv, strlen(key_recv), key_sha1);
        if (base64(key_sha1, &key_base64, strlen(key_sha1)) == S_MEM)
            return S_FAIL;
        strcat(handshake, key_base64);
        strcat(handshake, "\r\n\r\n");
        send(fd_client, handshake, strlen(handshake), 0);
        free(key_base64);
        return S_OK;
    }
    else if (len_recv == -1 && errno == EAGAIN)
    {
        return S_FAIL;
    }
}
// init eventQ
int initQueue()
{
    evtQueue.head = NULL;
    evtQueue.tail = NULL;
    return S_OK;
}
// add event to the queue
int addEvtQ(struct epoll_event *pEvt)
{
    QNode *p = (QNode*)malloc(sizeof(QNode));

    if (!p)
        return S_MEM;
    p->pEvt = pEvt;
    p->next = NULL;
    // Queue is null
    if (!evtQueue.head)
    {
        evtQueue.head = p;
        evtQueue.tail = p;
    }
    else
    {
        evtQueue.tail->next = p;
    }
    return S_OK;
}
// remove queuehead and return ptr_event
struct epoll_event* remEvtQ()
{
    QNode *pNode = evtQueue.head;
    struct epoll_event *pEvt = pNode->pEvt;

    evtQueue.head = pNode->next;
    free(evtQueue.head);
    
    return pEvt;
}
// add event listener to epoll
int addEvent(int fd_epoll, int fd, uint32_t flag)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.data.fd = fd;
    ev.events = flag;
    epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd, &ev);

    return S_OK;
}
// insert new fd to list
int addfdlist(int fd)
{
    LNode *pNode = (LNode*)malloc(sizeof(LNode));

    if (!pNode)
        return S_FAIL;
    pNode->fd = fd;
    pNode->next = fdList.next;
    fdList.next = pNode;

    return S_OK;
}
// remove fd from list
int remfdlist(int fd)
{
    LNode *ptr = &fdList;

    while (ptr->next)
    {
        if (ptr->next->fd == fd)
        {
            LNode *pt = ptr->next;
            ptr->next = pt->next;
            free(pt);
            break;
        }
        ptr = ptr->next;
    }

    return S_OK;
}
// receive request and send response
int procReq(int fd_client)
{
    unsigned char payload[MAXPLSIZE] = { 0 };
    info_webFramehead inf_head;

    do
    {
        if (analyseHead(fd_client, &inf_head) != S_OK)
        {
            return S_FAIL;
        }
        long long t_len = inf_head.len_Payload; 
        int num_hasRead = 0, num_hasSent = 0;
        while (t_len > 0)
        {
            int num_toRead = (t_len > MAXPLSIZE) ? MAXPLSIZE : t_len;
            if (getPayload(fd_client, payload, inf_head.MaskingKey, num_toRead, &num_hasRead) != S_OK)
            {
                return S_FAIL;
            }
            LNode *p_Node = &fdList;
            while (p_Node->next)
            {
                if (inf_head.Opcode != 8)
                {
                    if (sendPayload(p_Node->next->fd, &inf_head, payload, num_hasRead, &num_hasSent) != S_OK)
                    {
                        return S_FAIL;
                    }
                }
                else
                {
                    if (sendPayload(fd_client, &inf_head, payload, num_hasRead, &num_hasSent) != S_OK)
                    {
                        return S_FAIL;
                    }
                    break;
                }
                p_Node = p_Node->next;
            }
            t_len -= num_hasRead;
        }
    } while (!inf_head.FIN);
    if (inf_head.Opcode == 8)
    {
        close(fd_client);
        pthread_mutex_lock(&mutex_List);
        remfdlist(fd_client);
        pthread_mutex_unlock(&mutex_List);
    }

    return S_OK;
}
// accept connection, handshake and add clientfd to epoll
int procConn(int fd_servsock, int fd_epoll)
{
    struct sockaddr_in sca;     // record addr(client)
    socklen_t len_cfd = sizeof(struct sockaddr);
    int fd_client;     // file descriptor of client socket

    if ((fd_client = accept(fd_servsock, (struct sockaddr*)&sca, &len_cfd)) < 0)
    {
        return S_FAIL;
    }
    else
    {
        if (handshake(fd_client) == S_OK)
        {
            pthread_mutex_lock(&mutex_List);
            addfdlist(fd_client);
            pthread_mutex_unlock(&mutex_List);
            addEvent(fd_epoll, fd_client, EPOLLIN | EPOLLET);
        }
        else
        {
            return S_FAIL;
        }
    }

    return S_OK;
}
// function called by threads
void* procEvent(void *data)
{
    struct epoll_event *pEvt = NULL;
    int fd_server = *(((fds*)data)->pfd_server);
    int fd_epoll = *(((fds*)data)->pfd_epoll);
    while (1)
    {
        // wait if the queue is empty
        sem_wait(&empty);
        // remove one event from the queue
        pthread_mutex_lock(&mutex_Queue);
        pEvt = remEvtQ();
        pthread_mutex_unlock(&mutex_Queue);
        // client is connecting
        if (pEvt->data.fd == fd_server)
        {
            procConn(fd_server, fd_epoll);
        }
        else
        {
            // data in
            if (pEvt->events & EPOLLIN)
            {
                if (procReq(pEvt->data.fd) == S_FAIL)
                {
                    close(pEvt->data.fd);
                    pthread_mutex_lock(&mutex_List);
                    remfdlist(pEvt->data.fd);
                    pthread_mutex_unlock(&mutex_List);
                }
            }
        }
    }
}
// init serverfd
int initSocket(int *fd_server)
{
    struct sockaddr_in ssa; // record addr(server)
    int nOptval;
    int _fd;
    int flag;

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
    flag = fcntl(_fd, F_GETFL, NULL);
    fcntl(_fd, F_SETFL, flag | O_NONBLOCK);
    if (bind(_fd, (struct sockaddr*)&ssa,sizeof(struct sockaddr)) < 0)
    {
        perror("log >> fail to bind address");
        return S_FAIL;
    }
    if (listen(_fd, 5) < 0)
    {
        perror("log >> fail to set listen");
        return S_FAIL;
    }
    *fd_server = _fd;

    return S_OK;
}
int main(int argc, char *argv[])
{
    int fd_server = 0;
    int fd_epoll = 0;
    int num_evt = 0;
    int num_th = 0;
    pthread_t list_th[512] = { 0 };
    fds fd = {&fd_server, &fd_epoll};
    struct epoll_event evts[MAXEVENT];

    // init mutex, semaphore and queue
    pthread_mutex_init(&mutex_Queue, NULL);
    pthread_mutex_init(&mutex_List, NULL);
    sem_init(&empty, 0, 0);
    initQueue();
    // init socket and epoll
    fd_epoll = epoll_create(5);
    if (initSocket(&fd_server) == S_FAIL)
    {
        return S_FAIL;
    }
    addEvent(fd_epoll, fd_server, EPOLLIN | EPOLLET);
    // create threads
    num_th = sysconf(_SC_NPROCESSORS_ONLN);
    for (int i_th = 0; i_th <= num_th; i_th++)
    {
        pthread_create(&list_th[i_th], NULL, procEvent, (void*)&fd);
    }
    // loop and get event
    while(1)
    {
        num_evt = epoll_wait(fd_epoll, evts, MAXEVENT, -1);
        for (int i_evt = 0; i_evt < num_evt; i_evt++)
        {
            pthread_mutex_lock(&mutex_Queue);
            if (addEvtQ(&evts[i_evt]) == S_OK)
            {
                pthread_mutex_unlock(&mutex_Queue);
                sem_post(&empty);
            }
        }
    }
    
    return S_OK;
}