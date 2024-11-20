#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>

#define SIZE 4096
#define QSIZE 250

typedef struct DNSHeader
{
    char T_ID[2];		//16 
    short unsigned QR;		//1
    short unsigned Opcode;	//4
    short unsigned AA;		//1
    short unsigned TC;		//1
    short unsigned RD;		//1
    short unsigned RA;		//1
    short unsigned Z;		//3
    short unsigned AD;		
    short unsigned CD;
    short unsigned RCODE;	//4
    short unsigned QDCOUNT;	//16
    short unsigned ANCOUNT;	//16
    short unsigned NSCOUNT;	//16
    short unsigned ARCOUNT;	//16
}DNSHeader;

typedef struct DNSQuestion
{
    char QNAME[QSIZE];
    short unsigned qsize;	
    char QTYPE[2];	//16
    char QCLASS[2];	//16
}DNSQuestion;

typedef struct DNSAns
{
    unsigned TTL;
    unsigned short RDLENGTH;
    char RDATA[QSIZE];
}DNSAns;

typedef struct sockConnDetails
{
    int sockfd;
    char query[SIZE];
    struct sockaddr_in clntAddr;
}skDetails;


void identifyHeaderFields(char *queryRecv, DNSHeader *quesHeader)
{

    char byte;

    quesHeader->T_ID[0] = queryRecv[0];
    quesHeader->T_ID[1] = queryRecv[1];

    byte = queryRecv[2];
    quesHeader->QR = (byte & 128) >> 7;
    quesHeader->Opcode = (byte & 120) >> 3;
    quesHeader->AA = (byte & 4) >> 2;
    quesHeader->TC = (byte & 2) >> 1;
    quesHeader->RD = byte & 1;

    byte = queryRecv[3];
    quesHeader->RA = (byte & 128) >> 7;
    quesHeader->Z = (byte & 64) >> 6;
    quesHeader->AD = (byte & 32) >> 5;
    quesHeader->CD = (byte & 16) >> 4;
    quesHeader->RCODE = byte & 15;

    quesHeader->QDCOUNT = queryRecv[4];
    quesHeader->QDCOUNT = (quesHeader->QDCOUNT) << 8;
    quesHeader->QDCOUNT = (quesHeader->QDCOUNT) + queryRecv[5];

    quesHeader->ANCOUNT = queryRecv[6];
    quesHeader->ANCOUNT = (quesHeader->ANCOUNT) << 8;
    quesHeader->ANCOUNT = (quesHeader->ANCOUNT) + queryRecv[7];

    quesHeader->NSCOUNT = queryRecv[8];
    quesHeader->NSCOUNT = (quesHeader->NSCOUNT) << 8;
    quesHeader->NSCOUNT = (quesHeader->NSCOUNT) + queryRecv[9];

    quesHeader->ARCOUNT = queryRecv[10];
    quesHeader->ARCOUNT = (quesHeader->ARCOUNT) << 8;
    quesHeader->ARCOUNT = (quesHeader->ARCOUNT) + queryRecv[11];
}

void findQuestionName(char *qstart, DNSQuestion *qstn)
{
    int i = 0;
    while (qstart[i])
    {
        i = i + (qstart[i] + 1);
    }

    qstn->qsize = i + 1;

    for (i = 0; i < qstn->qsize; ++i)
    {
        qstn->QNAME[i] = qstart[i];
        //printf("%c ", qstn->QNAME[i]);
    }

    //printf("\nQSIZE : %hu\n", qstn->qsize);
}
void getQuestion(char *qStart, DNSQuestion *qstn)
{
    findQuestionName(qStart, qstn);

    qstn->QTYPE[0] = qStart[qstn->qsize];
    qstn->QTYPE[1] = qStart[qstn->qsize + 1];

    qstn->QCLASS[0] = qStart[qstn->qsize + 2];
    qstn->QCLASS[1] = qStart[qstn->qsize + 3];
}

void setAnswerData(int ansParts[100],DNSQuestion *qstn, DNSAns *ans)
{
    ans->TTL = 120;

    if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1) //A Query
    {
        ans->RDLENGTH = 4;

        ans->RDATA[0] = ansParts[0];
        ans->RDATA[1] = ansParts[1];
        ans->RDATA[2] = ansParts[2];
        ans->RDATA[3] = ansParts[3];
    }
    else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1c) //AAAA Query
    {
        ans->RDLENGTH = 16;

	for(int i=0;i<16;i++){
		if(ansParts[i] == '\0')
			ans->RDATA[i] = 0;
		else	
			ans->RDATA[i] = ansParts[i];
	}
       
    }
    else if(qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x2){ //NS Query
	//printf("entered here\n");
	ans->RDLENGTH = 6;
	ans->RDATA[0] = 3;
	ans->RDATA[1] = 110;
        ans->RDATA[2] = 115;
        ans->RDATA[3] = 3;
	ans->RDATA[4] = 6;
        ans->RDATA[5] = 103;
        ans->RDATA[6] = 111;
        ans->RDATA[7] = 111;
        ans->RDATA[8] = 103;
        /*ans->RDATA[9] = 108;
        ans->RDATA[10] = 101;
	ans->RDATA[11] = 3;
        ans->RDATA[12] = 99;
        ans->RDATA[13] = 111;
        ans->RDATA[14] = 109;*/
    }
}

void setResponseHeader(char *response, DNSHeader *head)
{
    response[0] = head->T_ID[0];
    response[1] = head->T_ID[1];

    char byte = 1; //QR = 1 - response; QR = 0 - query

    byte = byte << 4;
    byte = byte | (head->Opcode); //Opcode

    byte = byte << 1;
    byte = byte | (head->AA);  //AA

    byte = byte << 1;
    byte = byte | (head->TC); //TC

    byte = byte << 1;
    byte = byte | (head->RD); //RD

    response[2] = byte; //FLAG 1st 8 bits- QR+Opcode+AA+TC+RD

    byte = 0; //RA
    byte = byte << 7; 
    byte = byte | (head->RCODE); //RCODE

    response[3] = byte; //FLAG 2nd 8 bits- RA+Z+RCODE

    response[5] = head->QDCOUNT; //QDCOUNT
    response[7] = 1; 		 //ANSCOUNT
    response[9] = head->NSCOUNT; //NSCOUNT
    response[11] = head->ARCOUNT; //ARCOUNT
}

void setResponseQuestion(char *qstField, DNSQuestion *qstn)
{
    unsigned i = 0;
    while (i < qstn->qsize)
    {
        qstField[i] = qstn->QNAME[i];
        ++i;
    }
    qstField[i++] = qstn->QTYPE[0];
    qstField[i++] = qstn->QTYPE[1];

    qstField[i++] = qstn->QCLASS[0];
    qstField[i++] = qstn->QCLASS[1];
}

void setResponseAnswer(char *ansField, DNSQuestion *qstn, DNSAns *ans)
{
    unsigned i = 0;

    ansField[i++] = 0xc0;
    ansField[i++] = 0x0c; //NAME

    ansField[i++] = qstn->QTYPE[0];
    ansField[i++] = qstn->QTYPE[1];

    ansField[i++] = qstn->QCLASS[0];
    ansField[i++] = qstn->QCLASS[1];

    ansField[i++] = 0;
    ansField[i++] = 0;
    ansField[i++] = 0;
    ansField[i++] = ans->TTL; 

    ansField[i++] = 0; 
    ansField[i++] = ans->RDLENGTH;

    for (unsigned j = 0; j < ans->RDLENGTH; ++j)
    {
        ansField[i++] = ans->RDATA[j];
    }
}

unsigned createResponse(DNSHeader *head, DNSQuestion *qstn, DNSAns *ans, char *response)
{
    memset(response, 0, SIZE);

    unsigned pos = 0;

    setResponseHeader(response, head);
    pos = 12;

    setResponseQuestion(response + pos, qstn);
    pos += (qstn->qsize) + 4;

    setResponseAnswer(response + pos, qstn, ans);
    pos += 12 + (ans->RDLENGTH);

    return pos;
}

void ipv4Parting(char answer[100],int *ansParts){
	int temp[5];
	int j,exp,num = 0,faceVal = 1,q = 0;
		
	for(int i=0;i<strlen(answer);i++){
		num = 0;
		memset(&temp,'\0',sizeof(temp));
		j = 0;
		while(answer[i] != '.'){
			temp[j] = answer[i] - '0';
			//printf("temp[%d]=%d answer[%d]=%c\n",j,temp[j],i,answer[i]);
			j++;
			i++;
			if(answer[i] == '\0')
				break;
		}
		//printf("j = %d ",j);
		for(int k=j-1;k>=0;k--){
			exp = j - k - 1;
			faceVal = temp[k];
			while(exp>0){
				faceVal = faceVal * 10;
				exp--;
			}
			num = num + faceVal;
		}
		//printf("num=%d\n",num);
		ansParts[q] = num;
		q++;
	}
	/*for(int i=0;i<4;i++){
		printf("%d ",ansParts[i]);
	}
	printf("\n");*/



}

int hextoInt(unsigned char text[100])
{
    //unsigned char text[]="2a";
    int i,length, intValue,digit,p;
    
    length=strlen(text);
    
    intValue=0;
    
    for(i=(length-1),p=0; i>=0; i--,p++){
        if(text[i]>='0' && text[i]<='9'){
            digit=text[i]-0x30;
        }
        else if((text[i]>='A' && text[i]<='F') || (text[i]>='a' && text[i]<='f')){
            switch(text[i])   {
                case 'A': case 'a': digit=10; break;
                case 'B': case 'b': digit=11; break;
                case 'C': case 'c': digit=12; break;
                case 'D': case 'd': digit=13; break;
                case 'E': case 'e': digit=14; break;
                case 'F': case 'f': digit=15; break;
            }
        }
        intValue+= digit*pow(16,p);
    }

    //printf("Integer value is: %d\n",intValue);
    return intValue;
}

void ipv6Parting(char answer[100],int *ansParts){

	char temp[5];
	int j,exp,num = 0,faceVal = 1,q = 0;
	//printf("parsing %s \n",answer);
	int numSeg = 0, segNeeded = 0;
	for(int i=0;i<strlen(answer);i++){
		num = 0;
		memset(&temp,'\0',sizeof(temp));
		j = 0;
		while(answer[i] != ':'){
			temp[j] = answer[i];
			
			//printf("temp[%d]=%d answer[%d]=%c\n",j,temp[j],i,answer[i]);
			j++;
			i++;
			if(answer[i] == '\0')
				break;
		}
		if(strlen(temp) > 0)
			numSeg++;
	}
	//printf("number of segments = %d\n",numSeg);
	segNeeded = 8 - numSeg;
	for(int i=0;i<strlen(answer);i++){
		num = 0;
		memset(&temp,'\0',sizeof(temp));
		j = 0;
		while(answer[i] != ':'){
			temp[j] = answer[i];
			
			//printf("temp[%d]=%d answer[%d]=%c\n",j,temp[j],i,answer[i]);
			j++;
			i++;
			if(answer[i] == '\0')
				break;
		}
		//printf("temp = %s....strlen = %lu\n",temp,strlen(temp));
		char addOn[5];
		//int n = strlen(temp);
		if(strlen(temp) == 0){
			while(segNeeded > 0){
				ansParts[q++] = 0;
				ansParts[q++] = 0;
				segNeeded--;
			}
			
		}

		else{
			while(strlen(temp) < 4){
				memset(&addOn,'\0',sizeof(addOn));
				addOn[0] = '0';
				strcat(addOn,temp);
				strcpy(temp,addOn);
				//n++;
				//printf("strlen = %lu\n",strlen(temp));
			}
			//printf("temp = %s....strlen = %lu\n",temp,strlen(temp));
		
		
		
			int a = 0,intVal;
			char hexByte[4];
			memset(&hexByte,'\0',sizeof(hexByte));
			//printf("\nhere1\n");
			while(a<=1){
				hexByte[a] = temp[a];
				a++;
			}
			//printf("\nhere2\n");
			intVal = hextoInt(hexByte);
			//printf("\nhere3\n");
			//printf("intVal=%d .... ",intVal);
			ansParts[q] = intVal;
			q++;
			memset(&hexByte,'\0',sizeof(hexByte)); 
			//printf("\nhere4\n");
			while(a<=3){
				hexByte[a-2] = temp[a];
				a++;
			}
			intVal = hextoInt(hexByte);
			//printf("intVal=%d \n\n",intVal);	 
			ansParts[q] = intVal;
			q++;	
			//printf("\nhere222\n");
			
		//printf("j = %d ",j);
		
		}
	}
	/*for(int i=0;i<16;i++){
		printf("%d - %d\n",i,ansParts[i]);
	}
	printf("\n");*/
}

void *sendResponsePacket(void *requestPacket, int ansParts[100])
{
    skDetails *reqPkt = (skDetails *)requestPacket;

    DNSHeader reqHeader;
    DNSQuestion reqQstn;
    DNSAns ans;
 
    identifyHeaderFields(reqPkt->query, &reqHeader);
    getQuestion(reqPkt->query + 12, &reqQstn);
    setAnswerData(ansParts,&reqQstn,&ans);

    char response[SIZE];
    unsigned packetSize;
    packetSize = createResponse(&reqHeader, &reqQstn, &ans, response);
	//printf("packetsize = %d\n",packetSize);
	//printf("sendbuf\n");
	/*for(int i = 0;i<sizeof(sendBuf);i++){
		printf("%d- %d\n",i,sendBuf[i]);
	}*/
    if (sendto(reqPkt->sockfd, response, packetSize, 0, (struct sockaddr *)&(reqPkt->clntAddr), sizeof(reqPkt->clntAddr)) < 0)
        perror("sendto() failed");
    else{
        printf("\nResponse Packet sent to client...\n");
    }
    free(reqPkt);
}


int checkCache(char name[2048], int type,char* ansWer){
	//printf("checkCache entered\n");
	FILE *fp;
	fp = fopen("cache.txt","r");
	if(fp == NULL){
		printf("Error opening file.\n");
	}
	char nameType[2048];
	memset(&nameType,'\0',sizeof(nameType));
	strcpy(nameType,name);
	if(type == 1){
		strcat(nameType," 1");
	}
	else if(type == 2){
		strcat(nameType," 2");
	}
	else if(type == 5){
		strcat(nameType," 5");
	}
	else if(type == 28){
		strcat(nameType," 28");
	}
	char c = fgetc(fp);
	int flag = 0, h = 0, j = 0, lineNo = 0;
	char line[2048];
	//printf("here672\n");
	//printf("nameType : %s",nameType);
	while(c!=EOF){
		if(lineNo == 0){
			fclose(fp);
			fp=fopen("cache.txt","r");
		}
		memset(&line,'\0', sizeof(line));
		fscanf(fp,"%[^\n]",line);
		//printf("line = %s ... nameType=%s ... strlen(nameType) = %d\n",line,nameType,strlen(nameType));
		if(strncmp(line,nameType,strlen(nameType)) == 0){
			//printf("entered the cache thing\n");
			flag = 1;
			h = 0;
			j = 0;
			while(h < strlen(nameType)){
				h++;
			}
			while(line[h] != '\0'){
				if(line[h] != ' '){
					ansWer[j] = line[h];
					j++;
				}		
				h++;
			}
			break;
		}
		lineNo++;
		c = fgetc(fp);
	}
	//printf("ansWer = %s\n",ansWer);
	fclose(fp);
	return flag;
	/*int flag = 0;
	DNSRecord *p = NULL;
	while(p != NULL){
		if(strcpy(p->NAME,full) == 0 && p->TYPE == type){
			flag = 1;
			handleLookup(arg,p->ansParts);
			break;
		}
		p = p->next;
	}
	return flag;*/
}




int main(int argc, char **argv)
{
	if(argc != 2){
		printf("Usage: %s <port>\n", argv[0]);
		return EXIT_FAILURE;
	}
	int my_port = atoi(argv[1]);

	int sockfd;
	struct sockaddr_in srvAddr, clntAddr;
	char buffer[100];
	

	//CREATING THE SOCKET
	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd == -1) {
		printf("Socket creation failed\n");
		exit(0);
	}
	else {
		printf("Socket created successfully\n");
	}
	memset(&srvAddr,0,sizeof(srvAddr));

	 int opt = 1;
   	 if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        	perror("setsockopt() failed");

	
	//INITIALIZING PORTS AND IPs
	srvAddr.sin_family = AF_INET;
	srvAddr.sin_addr.s_addr = htonl(INADDR_ANY); //inet_addr("127.0.0.1"); INADDR_ANY; inet_addr("127.0.0.1")
	srvAddr.sin_port = htons(my_port);
	
	//BINDING SOCKET TO SERVER
	if(bind(sockfd,(struct sockaddr*)&srvAddr,sizeof(srvAddr)) < 0){
		printf("Socket binding failed\n");
		exit(0);
	}
	else{
		printf("Socket binding successful\n");
	}

	printf("Waiting for incoming messages....\n\n");
	int n;

	//READING THE QUERY
	//uint8_t hex_representation[512];
	char hex_representation[SIZE];
	int length;
	int clntLen = sizeof(clntAddr);
	if ((length = recvfrom(sockfd, hex_representation, SIZE-1, 0, (struct sockaddr*)&clntAddr, &clntLen)) < 0){
        		printf("Error while receiving\n");
       		 	exit(0);
    	}
	//PRINTING THE QUERY
	/*for(int i = 0;i<50;i++){
		//printf("%d - %d %c\n",i,hex_representation[i],(char*)hex_representation[i]);
		printf("%d - %d %c\n",i,(int*)hex_representation[i],hex_representation[i]);
	}*/
	//printf("\n");
	int i = 12,j = 0,k = 0, count = 0,type = 0;
	char part[100];
	char full[200];
	char setOfParts[20][100];
	memset(&full,'\0',sizeof(full));
	memset(&part,'\0',sizeof(part));
	memset(&setOfParts,'\0',sizeof(setOfParts));
	
	

    	skDetails *reqPkt;
	reqPkt = (skDetails *)malloc(sizeof(skDetails));
            for (int i = 0; i < SIZE; ++i)
            {
                reqPkt->query[i] = hex_representation[i];
            }
            reqPkt->sockfd = sockfd;
            reqPkt->clntAddr = clntAddr;
        

	while(hex_representation[i] != 0){
		count = hex_representation[i];
		i++;
		j = 0;
		while(j<count){
			part[j] = (char*)hex_representation[i];
			j++;
			i++;
		}
			
		strcat(part,".");
		strcpy(setOfParts[k],part);
		k++;
		strcat(full,part);
		memset(part,'\0',sizeof(part));
	}
	while(hex_representation[i] == 0){
		i++;
	}
	type = hex_representation[i];
	//printf("i=%d type = %d\n",i,type);
	//printf("Name = %s\n",full);
	//printf("contents of setOfParts\n");
	/*for(int i = 0;i<k;i++){
		printf("%s\n",setOfParts[i]);
	}*/
	

	char answer[100];
	int ansParts[5];
	
	int res = checkCache(full,type,&answer);
	if(res == 1){
		if(type == 1)
			ipv4Parting(answer,&ansParts);
		else if(type == 28)
			ipv6Parting(answer,&ansParts);
		sendResponsePacket(reqPkt,ansParts);

	}
	else if(res == 0){
	//printf("here345\n");
	memset(&ansParts,'\0',sizeof(ansParts));
	if(type == 1 || type == 2 || type == 5 || type == 28){	
		
		FILE* fp;
		i = k-1;
		char c,line[100], cmd[2048], nameServer[2048], search[2048], temp[2048],cname[2048],ipAddr[100];
		int flag = 0,p = 0,h = 0, lineNo = 0,bytes;

		
		if(type == 5){
			memset(&cmd,'\0',sizeof(cmd));
			//printf("search = %s  nameServer = %s\n",full,nameServer);
			sprintf(cmd,"nslookup -type=cname %s > output.txt",full);
			//printf("Executing the command : %s\n",cmd);
			system(cmd);
			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE---------------
			fseek(fp,0L,SEEK_END);
			bytes = ftell(fp);
			fseek(fp,0L,SEEK_SET);
			memset(&buffer,'\0', sizeof(buffer));
			fread(buffer,sizeof(char),bytes,fp);
			printf("--------------------\n%s\n",buffer);
			fclose(fp);

			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE--------------

			c = fgetc(fp);
			flag = 0;
			while(c!=EOF){
				memset(&line,'\0', sizeof(line));
				fscanf(fp,"%[^\n]",line);
				//printf("line = %s\n",line);
				if(strncmp(line,full,strlen(full)-1) == 0){
					flag = 1;
					h = 0;
					while(line[h] != '='){
						h++;
					}
					h++;
					p = 0;
					memset(&cname,'\0', sizeof(cname));
					while(line[h] != '\0'){
						if(line[h] != ' '){
							cname[p] = line[h];	
							p++;
						}
						h++;
					}
					break;
				}
				memset(&line,'\0', sizeof(line));
				c = fgetc(fp);

			}
			fclose(fp);
		
			sprintf(cmd,"nslookup -type=a %s > output.txt",full);
			//printf("Executing the command : %s\n",cmd);
			system(cmd);
			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE---------------
			fseek(fp,0L,SEEK_END);
			bytes = ftell(fp);
			fseek(fp,0L,SEEK_SET);
			memset(&buffer,'\0', sizeof(buffer));
			fread(buffer,sizeof(char),bytes,fp);
			printf("--------------------\n%s\n",buffer);
			fclose(fp);
			
		}
		if(type != 5){
		memset(&search,'\0',sizeof(search));
		memset(&nameServer,'\0',sizeof(nameServer));
		strcpy(nameServer,"a.root-servers.net.");
		printf("Name Server: %s\n",nameServer);
		strcpy(search,setOfParts[i]);
		flag = 1;
		int final = 0;
		while(flag != 0 && i>=0){	
			
			memset(&cmd,'\0',sizeof(cmd));
			//printf("search = %s  nameServer = %s\n",search,nameServer);
			sprintf(cmd,"nslookup -type=ns %s %s > output.txt",search,nameServer);
			//printf("Executing the command : %s\n",cmd);
			system(cmd);
			//printf("Done\n");
			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE---------------
			c = fgetc(fp);
			//lineNo = 0;
			flag = 0;
			while(c!=EOF){
				memset(&line,'\0', sizeof(line));
				fscanf(fp,"%[^\n]",line);
				
				if(strncmp(line,search,strlen(search)-1) == 0){
					flag = 1;
					h = 0;
					while(line[h] != '='){
						h++;
					}
					h++;
					p = 0;
					memset(&nameServer,'\0', sizeof(nameServer));
					while(line[h] != '\0'){
						if(line[h] != ' '){
							nameServer[p] = line[h];	
							p++;
						}
						h++;
					}
					break;
				}
				memset(&line,'\0', sizeof(line));
				c = fgetc(fp);

			}
			printf("Name Server: %s\n",nameServer);
			fclose(fp);
				
			
			i--;
			if(i>=0 ){
				memset(&temp,'\0', sizeof(temp));
				strcpy(temp,setOfParts[i]);
				strcat(temp,search);
				memset(&search,'\0', sizeof(search));
				strcpy(search,temp);
					
			}
			//printf("search : %s\n",search);
				
		}
		if(type == 2){ 
			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE---------------
			fseek(fp,0L,SEEK_END);
			int bytes = ftell(fp);
			fseek(fp,0L,SEEK_SET);
			memset(&buffer,'\0', sizeof(buffer));
			fread(buffer,sizeof(char),bytes,fp);
			printf("--------------------\n%s",buffer);
			fclose(fp);
			memset(&answer,'\0', sizeof(answer));
			strcpy(answer,nameServer);
		} //2-ns
				
		}//if's }

		//printf("hex = %d\n",type);
		
		if(type == 1 || type == 28){ //1-a and 28-aaaa

			memset(&cmd,'\0',sizeof(cmd));
			//printf("search = %s -- nameServer = %s\n",search,nameServer);
			if(type == 1){
				sprintf(cmd,"nslookup -type=a %s %s > output.txt",search,nameServer);
			}
			else if(type == 28){
				sprintf(cmd,"nslookup -type=aaaa %s %s > output.txt",search,nameServer);
			}
			//printf("Executing the command : %s\n",cmd);
			system(cmd);
			//printf("Done\n");

			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE---------------
			fseek(fp,0L,SEEK_END);
			int bytes = ftell(fp);
			fseek(fp,0L,SEEK_SET);
			memset(&buffer,'\0', sizeof(buffer));
			fread(buffer,sizeof(char),bytes,fp);
			printf("--------------------\n%s",buffer);
			
			fclose(fp);

			fp = fopen("output.txt","r");
			if(fp == NULL){
				printf("Error opening file\n");
				exit(1);
			}
			//----READING THE FILE LINE BY LINE---------------
			c = fgetc(fp);
			flag = 0;
			while(c!=EOF){
				memset(&line,'\0', sizeof(line));
				fscanf(fp,"%[^\n]",line);
				if(strncmp(line,"Address:",strlen("Address:")) == 0){
					if(flag == 0)
						flag = 1;
					else if(flag ==1){
						h = 0;
						while(line[h] != ':'){
							h++;
						}
						h++;
						p = 0;
						memset(&ipAddr,'\0', sizeof(ipAddr));
						while(line[h] != '\0'){
							if(line[h] != ' '){
								ipAddr[p] = line[h];	
								p++;
							}
							h++;
						}
						break;
					}
				}
				memset(&line,'\0', sizeof(line));
				c = fgetc(fp);

			}
			//printf("Address : %s\n",ipAddr);
			memset(&answer,'\0', sizeof(answer));
			strcpy(answer,ipAddr);
			int notNum = 0;
			for(int q=0;q<strlen(answer);q++){
				/*if(answer[q] == ':' ){
					printf("ENTERED INT KDNKVNKBN\n");
					notNum = 1;
					break;
				}*/
				//printf("%d - %c\n",q,answer[q]);
			}
		//	if(notNum == 1){
			if(type == 1 || type == 28){
				fp = fopen("cache.txt","a");
				if (fp == NULL){
					printf("Error while opening file.\n");
				}
				char data[2048];
				memset(&data,'\0',sizeof(data));
				//printf("full = %s type=%d answer=%s\n",full,type,answer);
				sprintf(data,"%s %d %s\n",full,type,answer);
				fprintf(fp,"%s",data);
				if(type == 1){
					ipv4Parting(answer,&ansParts);
				}
				else if(type == 28){
					ipv6Parting(answer,&ansParts);
				}
			}
			
		}
		sendResponsePacket(reqPkt,ansParts);
	}
    		
 }   
    	//CLOSING THE SOCKET
   	close(sockfd);
}




