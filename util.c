/*
 * Copyright (C) 2010-2011, Andreas Sandberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>

#include <unistd.h>
#include <assert.h>

#include "expect.h"
#include "util.h"

size_t
read_all(int fd, void *buf, size_t size)
{
    char *_buf = (char *)buf;
    size_t _size = size;
    do {
        ssize_t ret;
        ret = read(fd, _buf, _size);
        switch (ret) {
        case -1:
            EXPECT_ERRNO(errno == EAGAIN);
            break;

        case 0:
            return 0;
            
        default:
            _size -= ret;
            _buf += ret;
            break;
        }
    } while(_size);

    return size;
}

size_t
write_all(int fd, const void *buf, size_t size)
{
    char *_buf = (char *)buf;
    size_t _size = size;
    do {
        ssize_t ret;
        ret = write(fd, _buf, _size);
        if (ret == -1)
            EXPECT_ERRNO(errno == EAGAIN);
        else {
            _size -= ret;
            _buf += ret;
        }
    } while(_size);

    return size;
}

void
send_fd(int sockfd, int fd)
{
    char buf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_control = buf,
        .msg_controllen = sizeof(buf)
    };
    struct cmsghdr *cmsg;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    *(int *)CMSG_DATA(cmsg) = fd;

    msg.msg_controllen = cmsg->cmsg_len;

    EXPECT_ERRNO(sendmsg(sockfd, &msg, 0) != -1);
}

int
recv_fd(int sockfd)
{
    char buf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_control = buf,
        .msg_controllen = sizeof(buf)
    };
    struct cmsghdr *cmsg;
    
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    EXPECT_ERRNO(recvmsg(sockfd, &msg, 0) != -1);

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) {
        fprintf(stderr, "Failed to receive fds, aborting.\n");
        exit(EXIT_FAILURE);
    }

    assert(cmsg->cmsg_type == SCM_RIGHTS);
    return *(int *)CMSG_DATA(cmsg);
}

void
fredirect(FILE *new, int fd)
{
    int fd_new;

    fd_new = fileno(new);
    EXPECT_ERRNO(fd_new != -1);
    EXPECT_ERRNO(dup2(fd_new, fd) != -1);
}


/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
