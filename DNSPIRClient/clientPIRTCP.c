// cc clientPIRTCP.c -o client -lm -lssl -lcrypto
#include<malloc.h>
#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<errno.h>
#include<math.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
#include"mrea.h"
#include"DES_simple.h"

#define MAXLINE 50000
#define LEN 50000


FILE *f1_uname,*f2_pass;
char hexa[2000];

unsigned char pear16(unsigned char *x, int len) {
      int h, i, j;
      unsigned char ch;
 
      struct { // to store h values
         int a;
      } hh[8];
      struct { // 256 values 0-255 in any (random) order suffices
         int a;
      } T[256] = {
       98,  6, 85,150, 36, 23,112,164,135,207,169,  5, 26, 64,165,219, //  1
       61, 20, 68, 89,130, 63, 52,102, 24,229,132,245, 80,216,195,115, //  2
       90,168,156,203,177,120,  2,190,188,  7,100,185,174,243,162, 10, //  3
      237, 18,253,225,  8,208,172,244,255,126,101, 79,145,235,228,121, //  4
      123,251, 67,250,161,  0,107, 97,241,111,181, 82,249, 33, 69, 55, //  5
       59,153, 29,  9,213,167, 84, 93, 30, 46, 94, 75,151,114, 73,222, //  6
      197, 96,210, 45, 16,227,248,202, 51,152,252,125, 81,206,215,186, //  7
       39,158,178,187,131,136,  1, 49, 50, 17,141, 91, 47,129, 60, 99, //  8
      154, 35, 86,171,105, 34, 38,200,147, 58, 77,118,173,246, 76,254, //  9
      133,232,196,144,198,124, 53,  4,108, 74,223,234,134,230,157,139, // 10
      189,205,199,128,176, 19,211,236,127,192,231, 70,233, 88,146, 44, // 11
      183,201, 22, 83, 13,214,116,109,159, 32, 95,226,140,220, 57, 12, // 12
      221, 31,209,182,143, 92,149,184,148, 62,113, 65, 37, 27,106,166, // 13
        3, 14,204, 72, 21, 41, 56, 66, 28,193, 40,217, 25, 54,179,117, // 14
      238, 87,240,155,180,170,242,212,191,163, 78,218,137,194,175,110, // 15
       43,119,224, 71,122,142, 42,160,104, 48,247,103, 15, 11,138,239  // 16
      };
 
      ch=x[0]; // save first byte
      for (j=0; j<8; j++) {
         // standard Pearson hash (output is h)
         h=0;
         for (i=0; i<len; i++) {
            h=T[h ^ x[i]].a;
         }
         hh[j].a=h; // store result
         x[0]=x[0]+1; // increment first data byte by 1
      }
      x[0]=ch; // restore first byte
      // concatenate the 8 stored values of h
      sprintf(hexa,"%02X%02X%02X%02X%02X%02X%02X%02X",
         hh[0].a, hh[1].a,
         hh[2].a, hh[3].a,
         hh[4].a, hh[5].a,
         hh[6].a, hh[7].a);
	
      //RK//return hex;  // output 64-bit 16 hex bytes hash
	printf("\nHEX:%s\n",hexa);
   }



void readentireline(char buff1[])
{
	char c;
	int i=0;
	c=getchar();
	while(c!='\n')
	{
		buff1[i++]=c;
		c=getchar();
	}
	buff1[i]='\0';

}

int main(int argc,char **argv)
{
	int i;
 	/////////////DNS///////////
	
	/////DES//////////////////////////////////////////////////
	int i_uname=0,i_pass=0;	
	char input[200],input_uname[200],input_pass[200];
	char cha[1]="\n";
	char key[]="password";
	char clear[]="www.google.com";
	char *decrypted;
	char *encrypted_uname,*encrypted_pass,*encrypted_dn;
	//////////////////////////////////////////////////////////
	time_t tt;
	//unsigned char p[]="www.google.com",*q=&p[0];	
	int sockfd,n1=0,sz,wz,success=0;
	char content[MAXLINE],buff[MAXLINE],buff1[MAXLINE],a[3000],b[3000],revbuf[LEN];
	struct sockaddr_in servaddr;
	FILE *fp;
	pid_t pid;
	srand((unsigned) time(&tt));
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0)
		printf("socket error...Restart the application\n");\
	
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(53);

	if(inet_pton(AF_INET,"127.0.0.1",&servaddr.sin_addr)<=0)
		printf("\ninet_pton error !\n");
	if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr))<0)
	{
		printf("\n\n\n\t\t\t\t\tconnect error ! Restart the application !\n\n\n\n");
		exit(1);
	}
	KeyGen();
 	printf("\n\n\nEnter the text:  ");
        //scanf("%s",buff1);
	//RK
	readentireline(buff1);
	printf("\nTEXT:%s\n",buff1);
	p1.len_dn=strlen(buff1)+1;
	//RK//pear16(q,strlen(q));
	strcpy(input,buff1);
	pear16(buff1,strlen(buff1));
	mrea_Encrypt();
	strcpy(p1.buff_hash,hexa);
	//send(sockfd,buff1,strlen(buff1),0);
	//////////////1////////////////////////DES/////
	encrypted_dn=malloc(sizeof(input));
	printf("domain name text: %s \n",input);
	memcpy(encrypted_dn,Encrypt(key,input,sizeof(input)), sizeof(input));
	//printf("Encrypted DN text: %s \n",encrypted_dn);
	printf("STRLEN:%d\n",strlen(encrypted_dn));

	
////////////////////2///////////////////////////////
	f1_uname=fopen("uname.txt","r");
        if(f1_uname==NULL)
	{
                printf("\nUserName file not found..\n");
		uname_flag=0;
	}
	else
	{
		uname_flag=1;
	}
		

if(uname_flag==0)
{
	printf(">Enter Username");
//gets(input);
	 f1_uname=fopen("uname.txt","a+");	
 	while(input_uname[0]=getchar())
	{
		if(input_uname[0] == '\n')
			break;
		input[i_uname++]=input_uname[0];
		//fwrite(input_uname[0],sizeof(input_uname),1,f1_uname);
		fputc(input_uname[0],f1_uname);
	}
	input[i_uname]='\0';
	printf("\nInput_uname:%s\n",input);
	//fwrite(cha,sizeof(cha),1,f1_uname);

}
else if(uname_flag==1)
{
	rewind(f1_uname);
	while(!feof(f1_uname))
	{
			input_uname[0]=fgetc(f1_uname);
			if((input_uname[0]==' '))
				break;
			input[i_uname++]=input_uname[0];
	}
	input[i_uname-1]='\0';
	printf("\nInput:Uname:%s\n",input);
}
p1.len_uname=strlen(input)+1;
encrypted_uname=malloc(sizeof(input));
printf("Uname text: %s \n",input);
memcpy(encrypted_uname,Encrypt(key,input,sizeof(input)), sizeof(input));
//printf("Encrypted uname text: %s \n",encrypted_uname);
printf("STRLEN:%d\n",strlen(encrypted_uname));

///////////////////////////////3/////////////////////////

	f2_pass=fopen("pass.txt","r");
        if(f2_pass==NULL)
        {
                printf("\nPassword file not found..\n");
                pass_flag=0;
        }
        else
        {
                pass_flag=1;
        }

if(pass_flag==0)
{
printf(">Enter Password:");
//gets(input);
	 f2_pass=fopen("pass.txt","w");
        while(input_pass[0]=getchar())
        {
                if(input_pass[0] == '\n')
                        break;
                input[i_pass++]=input_pass[0];
                //fwrite(input_pass,sizeof(input_pass),1,f2_pass);
		fputc(input_pass[0],f2_pass);
        }
        input[i_pass]='\0';
        //fwrite(cha,sizeof(cha),1,f2_pass);
}
else
{
	 while(!feof(f2_pass))
        {
                        input_pass[0]=fgetc(f2_pass);
                        if(input_pass[0]=='\n')
                                break;
                        input[i_pass++]=input_pass[0];
        }
        input[i_pass-1]='\0';
        printf("\nInput:Uname:%s\n",input);

}
p1.len_pass=strlen(input)+1;
encrypted_pass=malloc(sizeof(input));
printf("Passwd text: %s \n",input);
memcpy(encrypted_pass,Encrypt(key,input,sizeof(input)), sizeof(input));
//printf("Encrypted passwd text: %s \n",encrypted_pass);
printf("STRLEN:%d\n",strlen(encrypted_pass));
	strcpy(p1.buff_dn,encrypted_dn);
	strcpy(p1.uname,encrypted_uname);
	strcpy(p1.passwd,encrypted_pass);
	/////////////////////////////////////////////
	printf("\n.......PACKET........\n");
	printf("E(HASH):%s\n",p1.buff_hash);
	//printf("E(DN):%s \n",p1.buff_dn);
	
	//printf("STRLEN:%d\n",strlen(p1.buff_dn));
	//printf("E(UNAME):%s\n",p1.uname);
	//printf("E(PASS):%s\n",p1.passwd);
	//printf("KEY:%ju %ju %ju\n",p1.e,p1.n,p1.ua);
	




	//strcpy(hostname,buff1);
	//ngethostbyname(hostname , T_A);
	send(sockfd,&p1,sizeof(p1),0);
        bzero(revbuf,LEN);
	
	sz=recv(sockfd,revbuf,LEN,0);
	revbuf[sz]='\0';
	
	printf("\nReceieved:%s\n",revbuf);
	
	
	close(sockfd);
	return 0;

}



