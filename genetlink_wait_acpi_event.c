#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#define PAGE_SIZE 4096


/**
 * The following informations are get from ACPI driver source code
 * files - "drivers/acpi/event.c" and "include/acpi/battery.h"
 */

/* event types */
#define ACPI_BATTERY_NOTIFY_STATUS 0x80
#define ACPI_BATTERY_NOTIFY_INFO 0x81
#define ACPI_BATTERY_NOTIFY_THRESHOLD 0x82

typedef char acpi_device_class[20];

struct acpi_genl_event {
        acpi_device_class device_class;
        char bus_id[15];
        __u32 type;
        __u32 data;
};

#define ACPI_GENL_FAMILY_NAME "acpi_event"
#define ACPI_GENL_VERSION 0x01
#define ACPI_GENL_MCAST_GROUP_NAME "acpi_mc_group"

enum {
        ACPI_GENL_ATTR_EVENT = 1, /* nlattr.type */
};

enum {
        ACPI_GENL_CMD_EVENT = 1, /* genlmsghdr.cmd */
};


/**
 * NETLINK GENERIC
 */

#define NL_HDRLEN NLMSG_ALIGN(sizeof(struct nlmsghdr))

const size_t nlmsghdr_size_aligned = NL_HDRLEN;
const size_t genlmsghdr_size_aligned = GENL_HDRLEN;
const size_t nlattrhdr_size_aligned = NLA_HDRLEN;

static __u32 nlmsg_seqn = 0;

struct genlmsghdr *get_genlhdr(struct nlmsghdr *hdr)
{
        void *genlhdr = NULL;
        genlhdr = NLMSG_DATA(hdr);
        return genlhdr;
}

struct nlattr *get_nlahdr(struct genlmsghdr *hdr)
{
        void *nlahdr = NULL;
        nlahdr = (void *)hdr + genlmsghdr_size_aligned;
        return nlahdr;
}

struct acpi_genl_event *get_acpi_attr(struct nlattr *hdr)
{
        void *ptr = NULL;
        ptr = (void *)hdr + nlattrhdr_size_aligned;
        return ptr;
}

#define GENL_DEF_VERSION 0x01

struct nlmsghdr *makeup_genl_get_msg(void *buf, __u8 cmd, __u16 nla_type, 
                                     void *val, size_t val_size)
{
        void *ret_ptr = buf;

        struct genlmsghdr genlhdr = {
                .cmd = cmd,
                .version = GENL_DEF_VERSION,
                .reserved = 0,
        };

        struct nlattr nlahdr = {
                .nla_type = nla_type,
        };
        size_t nla_payload_size = 0;

        if (!val_size) {
                /* attribute value is string */
                char *attr_str = (char *)val;
                nla_payload_size = NLA_ALIGN(strlen(attr_str));
        } else
                nla_payload_size = NLA_ALIGN(val_size);
        nlahdr.nla_len = nlattrhdr_size_aligned + nla_payload_size;

        struct nlmsghdr hdr = {
                .nlmsg_len = nlmsghdr_size_aligned + genlmsghdr_size_aligned
                             + nlahdr.nla_len,
                .nlmsg_type = GENL_ID_CTRL,
                .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
                .nlmsg_seq = ++nlmsg_seqn,
                .nlmsg_pid = getpid(),
        };

        /* construct message */
        memcpy(buf, &hdr, sizeof(struct nlmsghdr));
        buf += nlmsghdr_size_aligned;
        memcpy(buf, &genlhdr, sizeof(struct genlmsghdr));
        buf += genlmsghdr_size_aligned;
        memcpy(buf, &nlahdr, sizeof(struct nlattr));
        buf += nlattrhdr_size_aligned;
        
        /* copy value */
        if (!val_size)
                memcpy(buf, val, strlen((char *)val));
        else
                memcpy(buf, val, val_size);

        return (struct nlmsghdr *)ret_ptr;
}

struct nlmsghdr *makeup_getfamily_msg(void *buf, char *famname);
inline struct nlmsghdr *makeup_getfamily_msg(void *buf, char *famname)
{
        return makeup_genl_get_msg(buf, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME,
                                   famname, 0);
}

bool is_nlmsg_error(struct nlmsghdr *hdr)
{
        bool ret = hdr->nlmsg_type == NLMSG_ERROR;
        if (ret && *((int *)((void *)hdr + nlmsghdr_size_aligned)) == 0)
                ret = false;
        return ret;
}

__s32 extract_nlmsg_errcode(struct nlmsghdr *hdr);
inline __s32 extract_nlmsg_errcode(struct nlmsghdr *hdr)
{
        return *((__s32 *)((void *)hdr + nlmsghdr_size_aligned));
}

void print_nlmsghdr(const struct nlmsghdr *hdr, void *stream_id)
{
        fprintf(stream_id, "nlmsghdr length : %u\n"
                           "nlmsghdr type   : %hu\n"
                           "nlmsghdr flags  : %hu\n"
                           "nlmsghdr seq    : %u\n"
                           "nlmsghdr pid    : %u\n",
                hdr->nlmsg_len, hdr->nlmsg_type, hdr->nlmsg_flags,
                hdr->nlmsg_seq, hdr->nlmsg_pid);
}

void perror_nlmsghdr(const struct nlmsghdr *hdr);
inline void perror_nlmsghdr(const struct nlmsghdr *hdr)
{
        print_nlmsghdr(hdr, stderr);
}

void printf_nlmsghdr(const struct nlmsghdr *hdr);
inline void printf_nlmsghdr(const struct nlmsghdr *hdr)
{
        print_nlmsghdr(hdr, stdout);
}

/**
 * attr_struct - generic netlink attributes collection
 * @ctrl_attr_family_id:
 *               family ID
 * @ctrl_attr_version:
 *               attribute version
 * @ctrl_attr_maxattr:
 *               maximum attributes
 * @ctrl_attr_ops:
 *               operations
 *               # I'm not sure the type of this field 
 *                 whether is integral data,maybe it is
 *                 string type,but we actually do not
 *                 send CTRL_CMD_**OPS** command to
 *                 kernel,thus the respone message do
 *                 not contain this field
 * @ctrl_attr_hdrsize:
 *               header size
 * @ctrl_attr_mcast_group_id:
 *               multicast group ID
 * @ctrl_attr_family_name:
 *               family name
 * @ctrl_attr_mcast_group_name:
 *               multicast group NAME
 */
struct genl_attr_struct {
        struct genlmsghdr genlhdr;
        __u16 ctrl_attr_family_id;
        __u8 ctrl_attr_version;
        __u8 ctrl_attr_maxattr;
        __u16 ctrl_attr_ops;
        __u16 ctrl_attr_hdrsize;
        __u16 ctrl_attr_mcast_group_id;
        char ctrl_attr_family_name[32];
        char ctrl_attr_mcast_group_name[32];
};

/* only parse respone message for GENL_ID_CTRL */
void parse_genl_id_ctrl_attrs(struct nlmsghdr *hdr, ssize_t datum_len, struct genl_attr_struct *attr)
{
        /* parse */
        struct nlmsghdr *nlm_iter = hdr;
        ssize_t rem = datum_len;

        for ( ; NLMSG_OK(nlm_iter, rem);
             nlm_iter = NLMSG_NEXT(nlm_iter, rem)) {
                ssize_t nlmsg_payload_size = nlm_iter->nlmsg_len - nlmsghdr_size_aligned;
                struct genlmsghdr *genlhdr = get_genlhdr(nlm_iter);
                attr->genlhdr = *genlhdr;

                nlmsg_payload_size -= GENL_HDRLEN;
                struct nlattr *nlahdr = get_nlahdr(genlhdr);

                while (nlmsg_payload_size > 0) {
                        const char *str_attr = NULL;
                        __u32 uint_attr = 0;

#ifdef DEBUG
                        fprintf(stdout, "is nla nested - %u\n", nlahdr->nla_type & NLA_F_NESTED);
                        fprintf(stdout, "nla_len : %u | nla_type : %u | align : %u\n",
                                nlahdr->nla_len, nlahdr->nla_type,
                                NLA_ALIGN(nlahdr->nla_len));
#endif
                        
                        switch (nlahdr->nla_type) {
                        case CTRL_ATTR_FAMILY_ID:
                                uint_attr = *((__u16 *)((void *)nlahdr + nlattrhdr_size_aligned));
                                if (nlahdr->nla_type & NLA_F_NET_BYTEORDER)
                                        uint_attr = ntohs(uint_attr);
                                attr->ctrl_attr_family_id = uint_attr;
                                break;

                        case CTRL_ATTR_FAMILY_NAME:
                                str_attr = (char *)((void *)nlahdr + nlattrhdr_size_aligned);
                                strncpy(attr->ctrl_attr_family_name, str_attr, 32);
                                break;

                        case CTRL_ATTR_VERSION:
                                uint_attr = *((__u8 *)((void *)nlahdr + nlattrhdr_size_aligned));
                                if (nlahdr->nla_type & NLA_F_NET_BYTEORDER)
                                        uint_attr = ntohs(uint_attr);
                                attr->ctrl_attr_version = uint_attr;
                                break;

                        case CTRL_ATTR_HDRSIZE:
                                uint_attr = *((__u16 *)((void *)nlahdr + nlattrhdr_size_aligned));
                                if (nlahdr->nla_type & NLA_F_NET_BYTEORDER)
                                        uint_attr = ntohs(uint_attr);
                                attr->ctrl_attr_hdrsize = uint_attr;
                                break;
                                
                        case CTRL_ATTR_MAXATTR:
                                uint_attr = *((__u8 *)((void *)nlahdr + nlattrhdr_size_aligned));
                                if (nlahdr->nla_type & NLA_F_NET_BYTEORDER)
                                        uint_attr = ntohs(uint_attr);
                                attr->ctrl_attr_maxattr = uint_attr;
                                break;

                        case CTRL_ATTR_OPS:
                                uint_attr = *((__u16 *)((void *)nlahdr + nlattrhdr_size_aligned));
                                if (nlahdr->nla_type & NLA_F_NET_BYTEORDER)
                                        uint_attr = ntohs(uint_attr);
                                attr->ctrl_attr_ops = uint_attr;
                                break;

                        case CTRL_ATTR_MCAST_GROUPS:
                        /**
                         * CTRL_ATTR_MCAST_GROUPS contained nested attributes about
                         * mcast group name and mcast groups id -
                         *
                         * +--> nlahdr
                         * |           +--> nlahdr + NLA_HDRLEN
                         * |           |           +--> nlahdr + 2 * NLD_HDRLEN 
                         * |           |           |                    +--> nlahdr + 3 * NLA_HDRLEN
                         | |           |           |                    |
                         * +---------------------------------------------------------------------------+
                         * |   |   |   |   |   |   |   |   |   |    |   |   |   |   |      |   |   |   |
                         * | L | T | P | L | T | P | L | T | P | ID | P | L | T | P | NAME | P | P | P |
                         * |   |   |   |   |   |   |   |   |   |    |   |   |   |   |      |   |   |   |
                         * +---------------------------------------------------------------------------+
                         *       7           1       8   2     __u16          1
                         *                           |
                         *                           +--> 4 + 2 => aligned to 8
                         */
                        {
                                struct nlattr *nested_nla = (void *)nlahdr + nlattrhdr_size_aligned;
                                struct nlattr *grpid_nla = (void *)nested_nla + nlattrhdr_size_aligned;
                                struct nlattr *grpnam_nla = (void *)grpid_nla + grpid_nla->nla_len;

                                uint_attr = *((__u16 *)((void *)grpid_nla + nlattrhdr_size_aligned));
                                str_attr  = (char *)((void *)grpnam_nla + nlattrhdr_size_aligned);

                                if (grpid_nla->nla_type & NLA_F_NET_BYTEORDER)
                                        uint_attr = ntohs(uint_attr);
                                attr->ctrl_attr_mcast_group_id = uint_attr;
                                strncpy(attr->ctrl_attr_mcast_group_name, str_attr, 32);
                        }
                        break;
                        }
                        nlmsg_payload_size -= NLA_ALIGN(nlahdr->nla_len);
                        nlahdr = (void *)nlahdr + NLA_ALIGN(nlahdr->nla_len);
                }
        }        
}

int main(void)
{
        /**
         * |<--------------------------------- msghdr.msg_iov.iov_len -------------------------------------->|
         * [netlink msg hdr | ... | generic netlink msg hdr | nlattr hdr | ... | acpi_genl_event | ... | ... ]
         * ^
         * |
         * +-- msghdr.msg_iov.iov_base
         */

        int netlink_fd = -1;
        errno = 0;
        netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
        if (netlink_fd < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
                return -1;
        }

        void *iov_buf = malloc(PAGE_SIZE);
        if (!iov_buf) {
                fprintf(stderr, "error: ENOMEM\n");
                shutdown(netlink_fd, SHUT_RDWR);
                return -1;
        }
        memset(iov_buf, 0, PAGE_SIZE);

        /* @nlmsghdr - mark the head of iov buffer */
        struct nlmsghdr *nlmsghdr =
                makeup_getfamily_msg(iov_buf, ACPI_GENL_FAMILY_NAME);

        struct sockaddr_nl addr = {0};
        addr.nl_family = AF_NETLINK;
        socklen_t addr_len = sizeof(struct sockaddr_nl);

        struct iovec iov = {
                .iov_base = iov_buf,
                .iov_len = nlmsghdr->nlmsg_len,
        };

        struct msghdr msghdr = {0};
        msghdr.msg_name = &addr;
        msghdr.msg_namelen = addr_len;
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;

        errno = 0;
        ssize_t ret = sendmsg(netlink_fd, &msghdr, 0);
        if (ret < 0) {
                fprintf(stderr, "error: sendmsg: %s\n", strerror(errno));
                goto exit_free;
        }

        memset(iov_buf, 0, PAGE_SIZE);
        msghdr.msg_iov->iov_len = PAGE_SIZE;
        errno = 0;
        ret = recvmsg(netlink_fd, &msghdr, 0);
        if (ret < 0) {
                fprintf(stderr, "error: recvmsg: %s\n", strerror(errno));
                goto exit_free;
        }

        /* check respone */
        if (is_nlmsg_error(nlmsghdr)) {
                fprintf(stderr, "error: nlmsg: err - %d\n", extract_nlmsg_errcode(nlmsghdr));
                goto exit_free;
        } else if (ret != nlmsghdr->nlmsg_len) {
                fprintf(stderr, "error: recvmsg: netlink generic message have truncated\n");
                fprintf(stderr, "readed - %d , nlmsg length - %u\n", ret, nlmsghdr->nlmsg_len);
                goto exit_free;
        }

        struct genl_attr_struct attr = {0};

        if (nlmsghdr->nlmsg_type == GENL_ID_CTRL)
                parse_genl_id_ctrl_attrs(nlmsghdr, ret, &attr);
        else {
                fprintf(stderr, "error: nlmsg: type is not GENL_ID_CTRL\n");
                goto exit_free;
        }

#ifdef DEBUG
        fprintf(stdout, "attributes - \n");

        fprintf(stdout, "genl cmd - %u\n", attr.genlhdr.cmd);
        fprintf(stdout, "genl version - %u\n", attr.genlhdr.version);
        fprintf(stdout, "genl reserved - %u\n", attr.genlhdr.reserved);

        fprintf(stdout, "CTRL_ATTR_FAMILY_ID - %u\n", attr.ctrl_attr_family_id);
        fprintf(stdout, "CTRL_ATTR_VERSION - %u\n", attr.ctrl_attr_version);
        fprintf(stdout, "CTRL_ATTR_MAXATTR - %u\n", attr.ctrl_attr_maxattr);
        fprintf(stdout, "CTRL_ATTR_OPS - %u\n", attr.ctrl_attr_ops);
        fprintf(stdout, "CTRL_ATTR_HDRSIZE - %u\n", attr.ctrl_attr_hdrsize);
        fprintf(stdout, "CTRL_ATTR_MCAST_GROUP_ID - %u\n", attr.ctrl_attr_mcast_group_id);
        fprintf(stdout, "CTRL_ATTR_FAMILY_NAME - %s\n", attr.ctrl_attr_family_name);
        fprintf(stdout, "CTRL_ATTR_MCAST_GROUP_NAME - %s\n", attr.ctrl_attr_mcast_group_name);
#endif


        /* subscribe mcast group */

        /**
         * I have tried pass arguments "&attr.ctrl_attr_mcast_group_id" and "sizeof(__u16)" == 2
         * to function setsockopt(),but it returned EINVAL.
         * the type of @__optlen of setsockopt() is uint32_t == unsigned int,if
         * there is a restrict on the parameter,that might cause this error.
         */
        unsigned int group_id = attr.ctrl_attr_mcast_group_id;

        errno = 0;
        if (setsockopt(netlink_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                       &group_id, sizeof(group_id)) < 0) {
                fprintf(stderr, "error: setsockopt: failed to subscribe mcast group - ID : %u - "
                                "NAME : %s - Reason : %s\n",
                        attr.ctrl_attr_mcast_group_id, attr.ctrl_attr_mcast_group_name,
                        strerror(errno));
                goto exit_free;
        }

        /* wait event */
        while (1) {
                memset(iov_buf, 0, PAGE_SIZE);
                msghdr.msg_iov->iov_len = PAGE_SIZE;
                errno = 0;

                ret = recvmsg(netlink_fd, &msghdr, 0);
                if (ret < 0) {
                        fprintf(stderr, "error: recvmsg: failed to receive message - %s\n",
                                strerror(errno));
                        goto exit_free;
                }

                if (is_nlmsg_error(nlmsghdr)) {
                        perror_nlmsghdr(nlmsghdr);
                        fprintf(stderr, "error: nlmsg: err - %d\n", extract_nlmsg_errcode(nlmsghdr));
                        fprintf(stderr, "skip...\n");
                        continue;
                } else if (ret != nlmsghdr->nlmsg_len) {
                        fprintf(stderr, "error: recvmsg: netlink generic message have truncated\n");
                        fprintf(stderr, "readed - %d , nlmsg length - %u\n", ret, nlmsghdr->nlmsg_len);
                        fprintf(stderr, "skip...\n");
                        continue;
                }

                struct genlmsghdr *genlhdr = get_genlhdr(nlmsghdr);
                if (genlhdr->cmd != ACPI_GENL_CMD_EVENT) {
                        fprintf(stderr, "info: it is not ACPI_GENL_CMD_EVENT,skip...\n");
                        continue;
                }

                struct nlattr *nlahdr = get_nlahdr(genlhdr);
                if (nlahdr->nla_type != ACPI_GENL_ATTR_EVENT) {
                        fprintf(stderr, "info: it is not ACPI_GENL_ATTR_EVENT,skip...\n");
                        continue;
                }

                struct acpi_genl_event *event = get_acpi_attr(nlahdr);
                fprintf(stdout, "device class : %s\n", event->device_class);
                fprintf(stdout, "bus id : %s \n", event->bus_id);
                const char *event_type_info = NULL;
                switch (event->type) {
                case ACPI_BATTERY_NOTIFY_STATUS:
                        event_type_info = "type : ACPI_BATTERY_NOTIFY_STATUS";
                        break;
                case ACPI_BATTERY_NOTIFY_INFO:
                        event_type_info = "type : ACPI_BATTERY_NOTIFY_INFO";
                        break;
                case ACPI_BATTERY_NOTIFY_THRESHOLD:
                        event_type_info = "type : ACPI_BATTERY_NOTIFY_THRESHOLD";
                        break;
                }
                fprintf(stdout, "%s\n", event_type_info);
                fprintf(stdout, "data : %u\n", event->data);
        }


exit_free:
        free(iov_buf);

        shutdown(netlink_fd, SHUT_RDWR);
        return 0;
}
