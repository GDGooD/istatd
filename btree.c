#include "btree.h"
#include <stdio.h> 
#include <stdlib.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>

BTREE newNode(){
	return (BTREE)malloc(sizeof(NODE));
}

BTREE createTree(){
	BTREE tree;
	tree = newNode();
	tree->ip = 1;
	tree->count = 0;
	tree->left = NULL;
	tree->right = NULL; 
	tree->height = 1;
	return tree;
};

int deleteTree(BTREE tree){
	if (tree == NULL)
		return 0;
	deleteTree(tree->left);
	deleteTree(tree->right);
	free(tree);
	return 0;
};


int height(BTREE tree) {
	int leftHeight, rightHeight;
	if( tree == NULL )
		return 0;
	if (tree->left == NULL)
		leftHeight = 0;
	else
		leftHeight = 1 + tree->left->height;
	if (tree->right == NULL)
		rightHeight = 0;
	else
		rightHeight = 1 + tree->right->height;
	return Max(leftHeight, rightHeight);
}

int Max(int a, int b) {
	return a > b ? a : b;
}

BTREE rotateright(BTREE tree)
{
	BTREE y;
	y=tree->left;
	tree->left=y->right;
	y->right=tree;
	tree->height=height(tree);
	y->height=height(y);
	return(y);
}
 
BTREE rotateleft(BTREE tree)
{
	BTREE y;
	y=tree->right;
	tree->right=y->left;
	y->left=tree;
	tree->height=height(tree);
	y->height=height(y);
	
	return(y);
}
 
BTREE RR(BTREE tree)
{
	tree=rotateleft(tree);
	return(tree);
}
 
BTREE LL(BTREE tree)
{
	tree=rotateright(tree);
	return(tree);
}
 
BTREE LR(BTREE tree)
{
	tree->left=rotateleft(tree->left);
	tree=rotateright(tree);
	
	return(tree);
}
 
BTREE RL(BTREE tree)
{
	tree->right=rotateright(tree->right);
	tree=rotateleft(tree);
	return(tree);
}
 
int BF(BTREE tree)
{
	int lh,rh;
	if(tree==NULL)
		return(0);
 
	if(tree->left==NULL)
		lh=0;
	else
		lh=1+tree->left->height;
 
	if(tree->right==NULL)
		rh=0;
	else
		rh=1+tree->right->height;
 
	return(lh-rh);
}

BTREE addToTree(BTREE tree, IP_TYPE ipTarget, COUNT_TYPE addToCount)
{
	if(tree == NULL)
	{
		tree = createTree();
		tree->ip = ipTarget;
		tree->count += addToCount;
	}
	else
	if(ipTarget == tree->ip){
		tree->count += addToCount;
		return tree;
	}
	else
	if(0 == tree->count){
		tree->ip = ipTarget;
		tree->count += addToCount;
		return tree;
	}
	else{
		if(ipTarget > tree->ip)		// insert in right subtree
		{
			tree->right=addToTree(tree->right, ipTarget, addToCount);
			if(BF(tree)==-2){
				if(ipTarget>tree->right->ip)
					tree=RR(tree);
				else
					tree=RL(tree);
			}
		}
		else{
			if(ipTarget<tree->ip)
			{
				tree->left=addToTree(tree->left, ipTarget, addToCount);
				if(BF(tree)==2){
					if(ipTarget < tree->left->ip)
						tree=LL(tree);
					else
						tree=LR(tree);
				}
			}
		}
	}
	tree->height=height(tree);
		
	return(tree);
}

COUNT_TYPE getIpCount(BTREE tree, IP_TYPE ipTarget){
	if (tree == NULL)
		return 0;
	if (ipTarget < tree->ip)
		return getIpCount(tree->left, ipTarget);
	else if (ipTarget > tree->ip)
		return getIpCount(tree->right, ipTarget);
	else
		return tree->count;
};

int saveInorder(FILE *f, BTREE tree){
	struct in_addr tmp;
	if (tree != NULL) {
		saveInorder(f, tree->left);
		tmp.s_addr = tree->ip;
		if (tree->count != 0)
			fprintf(f, "%u %d\n", tree->ip, tree->count);
		saveInorder(f, tree->right);
	}
}

int saveToFile(char *pathToFile, BTREE tree){
	FILE *f;
	f = fopen(pathToFile, "w");
	saveInorder(f, tree);
	fclose(f);
	return 0;
}

BTREE loadInorder(FILE *f, BTREE tree){
	struct in_addr *tmp;
	IP_TYPE ip;
	COUNT_TYPE count;
	while(fscanf(f, "%u %d", &ip, &count)==2) {	
		//printf("loading %d %d\n", (int)ip, count);
		tree = addToTree(tree, (int)ip, count);
		//printf("loaded %d %d %d\n", (int)ip, count, tree->height);
	}
	return tree;
}

BTREE loadFromFile(char *pathToFile, BTREE tree){
	FILE *f;
	//printf("loading from %s\n", pathToFile);
	f = fopen(pathToFile, "r+");
	if (f == NULL){
		//printf("cant load file: %s", pathToFile);
		return tree;
	}
	tree = loadInorder(f, tree);
	fclose(f);
	return tree;
} 

void printInorder (BTREE tree){
	struct in_addr tmp;
	if (tree != NULL) {
		printInorder(tree->left);
		tmp.s_addr = tree->ip;
		if (tree->count != 0)
			printf("%15s %u \n", inet_ntoa(tmp), tree->count);
		printInorder(tree->right);
	}
}
