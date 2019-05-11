#include "btree.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h>

#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/file.h>
#include <sys/stat.h>

#define SERVER_KEY_PATHNAME "/tmp/istatd_server_key"
#define PROJECT_ID 'A'

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

int checkLock(){
	int lfp;
	lfp=open("/etc/istatd/.lock",O_RDONLY,0644);
	if (lfp<0) 
		return 0;
	if (lockf(lfp,F_TEST,0)<0){
		close(lfp);
		return 1;
	}
	close(lfp);
	return 0;
}

int getDaemonPID(){
	FILE *f;
	int pid;
	f = fopen("/etc/istatd/.pid", "r");
	if (f != NULL){
		fscanf(f, "%u", &pid);
		fclose(f);
		return pid;
	}
	return 0;
}

void printHelp(){
	printf("\nistatd - cli for istatd service that collects statistic about network traffic\n\n");
	printf("start​ - packets are being sniffed from now on from default iface\n");
	printf("stop​ - packets are not sniffed\n");
	printf("show [ip] count ​- print number of packets received from ip address\n");
	printf("select iface [iface] - select interface for sniffing\n");
	printf("stat​ ​[iface] - ​ show all collected statistics for particular interface, if iface omitted - for all interfaces\n\n");
	printf("stat​us - ​ show current status\n");
	printf("terminate - ​ terminate istatd gracefully\n");
	printf("--help - show usage information\n");
}

int main(int argc,char **argv){
	struct msgcommand msgcommand;
	struct msgstring msgstring;
	struct msgstat msgstat;

	char isActive = 0;
	int i = 0;
	key_t msg_queue_key;
  int qid, qid_server;

	if (checkLock()){ //init IPC if daemon started
    if ((qid = msgget (IPC_PRIVATE, 0660)) == -1) {
        perror ("msgget: myqid");
        return 1;
    }

    if ((msg_queue_key = ftok (SERVER_KEY_PATHNAME, PROJECT_ID)) == -1) {
        perror ("ftok");
        return 1;
    }

    if ((qid_server = msgget (msg_queue_key, 0)) == -1) {
        perror ("msgget: server_qid");
        return 1;
    }
	}

	//reading commans
	if(argc == 1){
		printf("--help - show usage information\n");
		return 0;
	} 
	if (!strcmp(argv[1], "--help")){
		printHelp();
		return 0;
	}

	for (i=1; i<argc; i++){
		if (!strcmp(argv[i], "start")){
			struct stat st = {0}; //folder check
			if (checkLock()){
				if(kill(getDaemonPID(), 0)){
					printf("Can't connect to istatd. Are you root?\n");
					return 1;
				}		
				msgcommand.message_type = 1;
				msgcommand.message.qid = qid;
				msgcommand.message.command = 0;
				msgsnd (qid_server, &msgcommand, sizeof (struct msg_command), 0);
				kill(getDaemonPID(), SIGUSR1);
				return 0;
			};
			if (0 == access("./istatd", 0))
				execvp("./istatd", argv);
			else
				execvp("istatd", argv);
		}

		if (!strcmp(argv[i], "status")){
			if (checkLock()){
				printf("Active\n");
				if(kill(getDaemonPID(), 0)){
					printf("Can't connect to istatd. Are you root?\n");
					return 1;
				}		
				msgcommand.message_type = 1;
				msgcommand.message.qid = qid;
				msgcommand.message.command = 5;
				msgsnd (qid_server, &msgcommand, sizeof (struct msg_command), 0);
				kill(getDaemonPID(), SIGUSR1);
				msgrcv(qid, &msgcommand, sizeof (struct msg_stat), 1, 0);
				msgrcv(qid, &msgstring, sizeof (struct msg_string), 2, 0);
				if(msgcommand.message.command == 10)
					printf("Listening on %s\n", msgstring.message.string);
				if(msgcommand.message.command == 11)
					printf("Stopped on %s\n", msgstring.message.string);
				return 0;
			}
			else
				printf("Inactive\n");
			return 0;
		}

		if (!strcmp(argv[i], "terminate")){
			if (checkLock())
				if (kill(getDaemonPID(), SIGTERM))
					printf("Can't terminate istatd. Are you root?\n");
			return 0;					
		}
	
		if (!strcmp(argv[i], "stop")){
			if (checkLock()) { 
				msgcommand.message_type = 1;
				msgcommand.message.qid = qid;
				msgcommand.message.command = 1;
				msgsnd (qid_server, &msgcommand, sizeof (struct msg_command), 0);
				kill(getDaemonPID(), SIGUSR1);
			}
			return 0;
		}

		if (!strcmp(argv[i], "show")){
			if (!strcmp(argv[i+2], "count")){
				struct in_addr tmp;
				if(!inet_aton(argv[i+1], &tmp)){
					printf("Invalid address\n");
					return 1;
				};
				msgcommand.message_type = 1;
				msgcommand.message.qid = qid;
				msgcommand.message.command = 2;
				msgsnd (qid_server, &msgcommand, sizeof (struct msg_command), 0);

				msgstat.message_type = 3;
				msgstat.message.qid = qid;
				msgstat.message.ip = tmp.s_addr;
				msgsnd (qid_server, &msgstat, sizeof (struct msg_stat), 0);
				kill(getDaemonPID(), SIGUSR1);
				if (msgrcv(qid, &msgstat, sizeof (struct msg_stat), 3, 0) == -1){
					printf("No response from daemon\n");
					return 1;
				};
				tmp.s_addr = msgstat.message.ip;
				printf("             IP Count\n");
				printf("%15s %d\n", inet_ntoa(tmp), msgstat.message.count);
				return 0;
			}
		}

		if (!strcmp(argv[i], "select")){
			if (!strcmp(argv[i+1], "iface")){
				if (argc < 4){
					printf("Missing iface\n");
					return 1;
				}			
				msgcommand.message_type = 1;
				msgcommand.message.qid = qid;
				msgcommand.message.command = 3;
				msgsnd (qid_server, &msgcommand, sizeof (struct msg_command), 0);

				msgstring.message_type = 2;
				msgstring.message.qid = qid;
				strcpy(msgstring.message.string, argv[i+2]);
				msgsnd (qid_server, &msgstring, sizeof (struct msg_string), 0);
				usleep (1000);
				kill(getDaemonPID(), SIGUSR1);
			}
		}

		if (!strcmp(argv[i], "stat")){
				msgcommand.message_type = 1;
				msgcommand.message.qid = qid;
				msgcommand.message.command = 4;
				msgsnd (qid_server, &msgcommand, sizeof (struct msg_command), 0);

				msgstring.message_type = 2;
				msgstring.message.qid = qid;
				if (argc == 3)
					strcpy(msgstring.message.string, argv[i+1]);
				else
					strcpy(msgstring.message.string, "_1_");
				msgsnd (qid_server, &msgstring, sizeof (struct msg_string), 0);
				usleep (1000);
				kill(getDaemonPID(), SIGUSR1);
				BTREE treev4 = createTree();
				while(1){
					if (msgrcv(qid, &msgstat, sizeof (struct msg_stat), 0, 0) == -1){
						printf("No response from daemon\n");
						return 1;
					};
					if((msgstat.message.count == 0))
						break;
					treev4 = addToTree(treev4, msgstat.message.ip, msgstat.message.count);
				}
				printf("             IP Count\n");
				printInorder(treev4);
				return 0;
		}
	}
	return 0;
}
