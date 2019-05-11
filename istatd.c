#include "btree.h"
#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <signal.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/file.h>
#include <syslog.h>
#include <fcntl.h>

#define SERVER_KEY_PATHNAME "/tmp/istatd_server_key"
#define PROJECT_ID 'A'
#define QUEUE_PERMISSIONS 0660

struct msg_command{
  int qid;
  char command;
};

struct msgcommand {
  long message_type;
  struct msg_command message;
};

struct msg_string {
  int qid;
  char string [15]; 
};

struct msgstring {
  long message_type;
  struct msg_string message;
};


struct msg_stat{
  int qid;
	COUNT_TYPE count;
	IP_TYPE ip;
};

struct msgstat{
	long message_type;
  struct msg_stat message;
};

struct packet_struct {
	u_int8_t	ip_vhl;		// header length, version 
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		// type of service 
	u_int16_t	ip_len;		// total length 
	u_int16_t	ip_id;		// identification 
	u_int16_t	ip_off;		// fragment offset field 
#define	IP_DF 0x4000			// dont fragment flag 
#define	IP_MF 0x2000			// more fragments flag 
#define	IP_OFFMASK 0x1fff		// mask for fragmenting bits 
	u_int8_t	ip_ttl;		// time to live 
	u_int8_t	ip_p;		// protocol 
	u_int16_t	ip_sum;		// checksum 
	struct	in_addr ip_src,ip_dst;	// source and dest address 
};

typedef struct packet_struct *hdrstr;

int sigcommand = 0;
pcap_t* descr = NULL;

struct settings{
	char *dev; //current
	char *lastdev; //last success
	char mode; // 0 stop 1 start 2 ip stat 3 set iface  4 iface stat 5 status
};

int init_daemon()
{
    pid_t pid;
		int lfp;
		FILE *f;
		char str[10];
    // Fork off the parent process
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // On success: The child process becomes session leader
    if (setsid() < 0)
        exit(EXIT_FAILURE);
		
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // Fork off for the second time
    pid = fork();

    // An error occurred 
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate 
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // Set new file permissions 
    umask(0);

    // Changing the working directory
    chdir("/etc/istatd/");
		lfp=open(".lock",O_RDWR|O_CREAT,0666);
		if (lfp<0) 
			return -1;
		if (lockf(lfp,F_TLOCK,0)<0) 
			return -2;
		//sprintf(str,"%d\n",getpid());
		//write(lfp,str,strlen(str)); // record pid to lockfile 
		// only first instance continues
		f = fopen(".pid", "w+");
		if (f == NULL)
			return -1;
		fprintf(f, "%d", getpid());
		fclose(f);
		return 0;
}

int saveConfig(char *pathToFile, char *dev){
	FILE *f;
	f = fopen(pathToFile, "w+");
	if(f == NULL)
		return -1;
	fprintf(f, "%s", dev);
	fclose(f);
  return 0;
}

int loadConfig(char *pathToFile, char *dev){
	FILE *f;
	f = fopen(pathToFile, "r+");
	if(f == NULL)
		return -1;
	if (fscanf(f, "%s", dev) != 1);
		dev == NULL;
	fclose(f);
	return 0;
}

COUNT_TYPE getStatIP(IP_TYPE addr){
	char errbuf[PCAP_ERRBUF_SIZE];
	struct in_addr tmp;
	//inet_aton(addr, &tmp);
	BTREE treev4 = createTree();
	pcap_if_t *alldevs;
	char *devset;

	if(pcap_findalldevs(&alldevs, errbuf)){
		return 0;
	}
	for(pcap_if_t *d=alldevs; d!=NULL; d=d->next){
		devset = d->name;
		treev4 = loadFromFile(strcat("./", devset), treev4);
	}
	return getIpCount(treev4, addr);
	//printf("             IP Count\n");
	//printf("%15s %u \n", inet_ntoa(tmp), 	getIpCount(treev4, tmp.s_addr));
}

BTREE getStatIface(char *iface){
	BTREE treev4 = createTree();
	treev4 = loadFromFile(iface, treev4);
	return treev4;
}

BTREE getStatAll(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	BTREE treev4 = createTree();

	if(pcap_findalldevs(&alldevs, errbuf)){
		printf("%s\n", errbuf);
		return treev4;
	}
	for(pcap_if_t *d=alldevs; d!=NULL; d=d->next){
		//printf("daemon: getStatAll new device %s\n", d->name);
		treev4 = loadFromFile(d->name, treev4);
	}
	return treev4;
}

void sendInorder (BTREE tree, struct msgstat msgstat){
	//printf("daemon: inside tree %d\n", tree->ip);
	if (tree != NULL) {
		//printf("daemon: not null\n");
		if (tree->count != 0){
			//printf("daemon: acessing \n");
			msgstat.message.ip = tree->ip;
			msgstat.message.count = tree->count;
			//printf("daemon: send %d %d\n", tree->ip, tree->count);
			msgsnd (msgstat.message.qid, &msgstat, sizeof (struct msg_stat), 0);
		}
		else
			return;
		//printf("daemon: goint into leafs %d %d\n", tree->left, tree->right);
		sendInorder(tree->left, msgstat);
		sendInorder(tree->right, msgstat);
	}
	return;
	//printf("daemon: done leaf %d\n", tree->ip);
}

void sig_handler(int signum){
	if (descr != NULL)
 		pcap_breakloop(descr);
	sigcommand = signum;
}





int main(int argc,char **argv) 
{ 
		struct msgcommand msgcommand;		//1
		struct msgstring msgstring;			//2
		struct msgstat msgstat;					//3

		BTREE sumtreev4;
		char restarting;
		int i = 0;
		char errbuf[PCAP_ERRBUF_SIZE]; 
		struct settings settings;
		pcap_if_t *alldevs;
		pcap_if_t *devinit = NULL; 
		const u_char *packet; 
		struct pcap_pkthdr hdr;
		struct ether_header *eptr;		// net/ethernet.h
		struct bpf_program fp;				// hold compiled program
		bpf_u_int32 maskp;						// subnet mask
		bpf_u_int32 netp;						 // ip 
		bpf_u_int32 ip_dst;
		bpf_u_int32 ip_iface;
		struct in_addr tmp;

		const struct packet_struct* ip;
		u_int length;
		u_int hlen,off,version;
		FILE *f;

		int len;

		key_t msg_queue_key; //ipc msg
    int qid;
    struct msgcommand message;

		struct stat st = {0}; //folder check
		
		if (stat("/etc/istatd/", &st) == -1) {
			if (mkdir("/etc/istatd/", 0755)){
				printf("Can't start istatd. Are you root?\n");
				return 1;
			}
		}
		chdir("/etc/istatd/");
		//changing directory
		//init catching SIGs
		signal(SIGTERM, sig_handler);
 		signal(SIGUSR1, sig_handler);

		i = init_daemon();
		if(i == -1){
			printf("Can't start istatd. Are you root?\n");
			return 0;
		};
		if(i == -2){
			return 0;
		};

		settings.mode = 0; //start by default
		settings.dev = NULL;
		settings.lastdev = NULL;

		if (0 == access(SERVER_KEY_PATHNAME, 0)) { //init IPC
			if (remove(SERVER_KEY_PATHNAME)){
				printf("Can't start istatd. Are you root?\n");
				return -1;
			}
		} 
		
		f = fopen(SERVER_KEY_PATHNAME, "w");
		fclose(f);
		if ((msg_queue_key = ftok (SERVER_KEY_PATHNAME, PROJECT_ID)) == -1) {
      perror ("ftok");
      return 1;
    }
    if ((qid = msgget (msg_queue_key, IPC_CREAT | QUEUE_PERMISSIONS)) == -1) {
      perror ("msgget");
      return 1;
    }
		
		while(1){ //main loop//
			while(1){
				switch (settings.mode){

					case 1: 	//stop          //receiving commands
						pause();
						switch (sigcommand){
							case SIGUSR1:
								sigcommand = 0;
								if (msgrcv(qid, &msgcommand, sizeof (struct msg_command), 1, 0) == -1)
									break;
								settings.mode = msgcommand.message.command;
							break;

							case SIGTERM:
								remove(SERVER_KEY_PATHNAME);
								return 0;
							break;
						}
					break;

					case 2: //show ip count
						settings.mode = 1;
						if (msgrcv(qid, &msgstat, sizeof (struct msg_stat), 3, 0) == -1){
							break;
						};
						sumtreev4 = getStatAll();
						msgstat.message.count = getIpCount(sumtreev4, msgstat.message.ip);
						msgsnd (msgstat.message.qid, &msgstat, sizeof (struct msg_stat), 0);
						deleteTree(sumtreev4);
					break;

					case 3: //set iface
						if (restarting){
							settings.mode = 0;
						}
						else
							settings.mode = 1;
						if (msgrcv(qid, &msgstring, sizeof (struct msg_string), 2, IPC_NOWAIT) == -1)
							break;
						strncpy(settings.dev, msgstring.message.string, 15);
					break;

					case 4: //send stat iface
						if (msgrcv(qid, &msgstring, sizeof (struct msg_string), 2, IPC_NOWAIT) == -1){
							break;
						}
						if (!strncmp(msgstring.message.string, "_1_", 3))
							sumtreev4 = getStatAll();
						else
							sumtreev4 = getStatIface(msgstring.message.string);
						msgstat.message.qid = msgstring.message.qid;
						msgstat.message_type = 3;
						sendInorder(sumtreev4, msgstat);
						msgstat.message.count = 0;
						msgsnd (msgstat.message.qid, &msgstat, sizeof (struct msg_stat), 0);
						deleteTree(sumtreev4);
					break;

					case 5: //send status
						settings.mode = 1;
						msgcommand.message_type = 1;
						msgcommand.message.command = 11;
						msgsnd(msgcommand.message.qid, &msgcommand, sizeof (struct msg_command), 0);
						msgstring.message_type = 2;
						strncpy(msgstring.message.string, settings.dev, 15);
						msgsnd(msgcommand.message.qid, &msgstring, sizeof (struct msg_string), 0);
					break;
				}
				if (settings.mode == 0) //start
					break;
			}

			//get device list
			if(pcap_findalldevs(&alldevs, errbuf)){
				printf("%s\n", errbuf);
				return 1;
			}
			
			//search our device in device list
			restarting = 0;
			devinit = NULL;
			for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
				if (settings.dev == NULL)
					settings.dev = d->name;
				if (strncmp(d->name, settings.dev, 15))
					continue;
				devinit = d;
				break;
			}

			if (devinit == NULL){
				settings.mode=1;
				continue;
			}

			//restoring previous data
			BTREE treev4 = createTree();
			treev4 = loadFromFile(settings.dev, treev4);

			// open device for reading 
			descr = pcap_open_live(settings.dev, BUFSIZ, 0, 0, errbuf); 
			if(descr == NULL) {
					printf("Can't open device for listening. Are you root?\n");
					remove(SERVER_KEY_PATHNAME);
					return 1;
			} 


			//listening
			while(1){
				switch (sigcommand){
					case SIGUSR1:				//receiving command
						sigcommand = 0;
						if (msgrcv(qid, &msgcommand, sizeof (struct msg_command), 1, 0) == -1){
							break;
						};

						switch(msgcommand.message.command){

							case 1: //stop;
								pcap_close(descr);
								saveToFile(settings.dev, treev4);
								settings.mode = 1;
								deleteTree(treev4);
							break;

							case 2: //ip count
								if (msgrcv(qid, &msgstat, sizeof (struct msg_stat), 3, 0) == -1){
									break;
								};
								saveToFile(settings.dev, treev4);
								sumtreev4 = getStatAll();
								msgstat.message.count = getIpCount(sumtreev4, msgstat.message.ip);
								msgsnd (msgstat.message.qid, &msgstat, sizeof (struct msg_stat), 0);
								deleteTree(sumtreev4);
							break;

							case 3: //set iface
								pcap_close(descr);
								saveToFile(settings.dev, treev4);
								settings.mode = 3;
								restarting = 1;
								deleteTree(treev4);
							break;

							case 4: //stat iface
								saveToFile(settings.dev, treev4);
								if (msgrcv(qid, &msgstring, sizeof (struct msg_string), 2, IPC_NOWAIT) == -1){
									break;
								}
								if (!strncmp(msgstring.message.string, "_1_", 3))
									sumtreev4 = getStatAll();
								else
									sumtreev4 = getStatIface(msgstring.message.string);
								msgstat.message.qid = msgstring.message.qid;
								msgstat.message_type = 3;
								sendInorder(sumtreev4, msgstat);
								msgstat.message.count = 0;
								msgsnd (msgstat.message.qid, &msgstat, sizeof (struct msg_stat), 0);
								deleteTree(sumtreev4);
							break;

							case 5: //send status
								msgcommand.message_type = 1;
								msgcommand.message.command = 10;
								msgsnd(msgcommand.message.qid, &msgcommand, sizeof (struct msg_command), 0);
								msgstring.message_type = 2;
								strncpy(msgstring.message.string, settings.dev, 15);
								msgsnd(msgcommand.message.qid, &msgstring, sizeof (struct msg_string), 0);
							break;
						};
					break;

					case SIGTERM:
						saveToFile(settings.dev, treev4);
						remove(SERVER_KEY_PATHNAME);
						remove(".pid");
						return 0;
					break;
				};

				if (settings.mode != 0){				
					break;
				};


				packet = pcap_next(descr, &hdr);
				//printf(".");


				if (packet != NULL){
					length = hdr.len;
					// jump pass the ethernet header 
					ip = (struct packet_struct*)(packet + sizeof(struct ether_header));
					length -= sizeof(struct ether_header); 

					// check to see we have a packet of valid length 
					if (length < sizeof(struct packet_struct))
						continue;

					version = IP_V(ip);// ip version

					// check version 
					if(version != 4)
						continue;

					off = ntohs(ip->ip_off);
					if((off & 0x1fff) == 0 ){// aka no 1's in first 13 bits
						ip_dst = ip->ip_dst.s_addr;
						//compare dest IP with device IPs
						for(pcap_addr_t *a=devinit->addresses; a!=NULL; a=a->next) {
							if(a->addr->sa_family == AF_INET){
								tmp = ((struct sockaddr_in*)a->addr)->sin_addr;
								ip_iface = tmp.s_addr;
								if (ip->ip_dst.s_addr == ip_iface){
									treev4 = addToTree(treev4, ip->ip_src.s_addr, 1);
									break;
								}
							}
						}
					}
				}
			}
		}

		return 0; 
}
