#include <stdio.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned int IP_TYPE;
typedef unsigned long COUNT_TYPE;

struct node{
	COUNT_TYPE count;
	IP_TYPE ip;
	struct node *left;
	struct node *right;
	unsigned char height;
};

typedef struct node NODE;
typedef NODE *BTREE;

BTREE newNode(void);
BTREE createTree(void);
int deleteTree(BTREE tree);

int height(BTREE tree);
int Max(int a, int b);

BTREE singleRotateWithleft(BTREE K2);
BTREE singleRotateWithright(BTREE K1);
BTREE doubleRotateWithleft(BTREE K3);
BTREE doubleRotateWithright(BTREE K1);

BTREE addToTree(BTREE tree, IP_TYPE ipTarget, COUNT_TYPE addToCount);
COUNT_TYPE getIpCount(BTREE tree, IP_TYPE ipTarget);

int saveInorder(FILE *f, BTREE tree);
int saveToFile(char *pathToFile, BTREE tree);
BTREE loadInorder(FILE *f, BTREE tree);
BTREE loadFromFile(char *pathToFile, BTREE tree);

void printInorder (BTREE tree);

