#include<netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<errno.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/stat.h>
#include<unistd.h>
#include<sys/uio.h>
#include<sys/wait.h>
#include<time.h>
#include<errno.h>
#include"dns_server.h"
#include"DES_simple.h"
#define MAXLINE 50000
#define LEN 50000


 char tmp[200],tmp1[200],tmp2[2];
struct packet
{
	int len_dn,len_uname,len_pass;
   unsigned char buff_hash[4000];
   unsigned char buff_dn[4000];
   unsigned char uname[4000];
   unsigned char passwd[4000];
   uintmax_t e,n,ua;
};
struct packet r1,r2;


ssize_t readline(int fd,void *vptr,size_t maxlen)
{
	ssize_t n,rc;
	char c,*ptr;
	ptr=vptr;
	for(n=1;n<maxlen;n++)
	{
		again:
		if((rc=read(fd,&c,1))==1)
		{
			*ptr++=c;
			if(c=='\n')
				break;
		}	
		else if(rc==0)
		{
			*ptr=0;
			return(n-1);
		}
		else
		{
			if(errno==EINTR)
				goto again;
			return(-1);
		}
		*ptr=0;
		return(n);
	}

}
int checkBlocklist(char *dn)
{
	FILE *f1_bl;
	char buf[200],c;
	int i=0,j=0;
	f1_bl=fopen("Blocklist.txt","r");
	if(f1_bl==NULL)
		printf("\nBlocklist file not found...\n");
	again:
	i=0;
	while(!feof(f1_bl))
	{
		c=fgetc(f1_bl);
		if(c=='\n')
			break;
		buf[i++]=c;		
	}
	buf[i]='\0';
	printf("\nBUFF:%s\n",buf);
	if(strcmp(dn,buf)==0)
	{
		printf("\nMatch found..\n");
		return 1;
	}
	else
	{
		if(!feof(f1_bl))
			goto again;
		else
			return 0;
	}
}

int verify_Uname_Pass(char *uname,char *pass)
{
	FILE *upf1;	
	char c;
	int i=0,j=0;
	upf1=fopen("VerifyTable.txt","r");
	rewind(upf1);
	if(upf1==NULL)
		printf("\nVerify table not present...\n");	
	while(!feof(upf1))
	{
		i=0;
		c=fgetc(upf1);
		while((!feof(upf1)) && (c!=' '))
		{
			tmp[i++]=c;
			c=fgetc(upf1);
		}
		tmp[i]='\0';
		//printf("\ntmp:%s\n",tmp);
		if(strcmp(tmp,uname)==0)
		{
			//printf("\nUname is present..\n");	
			while((!feof(upf1)) && (((c=fgetc(upf1))==' ')||(c=='\t'))) ;
			while((c!=' '))
			{	
				tmp1[j++]=c;
				
				c=fgetc(upf1);
			}		
			tmp1[j]='\0';
			if(strcmp(tmp1,pass)==0)
			{
				//printf("\nPass is present\n");
				while((!feof(upf1)) && (((c=fgetc(upf1))==' ')||(c=='\t'))) ;
				tmp2[0]=c;
				tmp2[1]='\0';
				//printf("\nAccessLevel:%c\n",tmp2[0]);
				return 1;
			}
			else
				return 0;
			
		}
		else
		{
			while( (!feof(upf1)) && ((c=fgetc(upf1))!='\n')) 
					;
			continue;
		}
	}
	fclose(upf1);
}
int accesslevelConfirm()
{
	if(tmp2[0]=='2')
		return 2;
	else if(tmp2[0]=='1')
		return 1;
	else
		return 0;

}

int main(int argc,char **argv)
{
	/////////////////////////////////////////////////DES///
	char *decrypted_dn,*decrypted_uname,*decrypted_pass;
	char key[]="password";
	unsigned char *ptr;
	char clear[]="www.google.com";
	int x,yy;
	/////////////////////////////////////////////////////////


	int i=0,m=0,listenfd,connefd,n=0,sz,ct=0,pp=-1,qq=-1,y=0;
	struct sockaddr_in servaddr;
	char buff[50000],a[MAXLINE],b[10000],buffer[LEN],pass[7];
	pid_t pid;
	FILE *fp,*fp1;
	unsigned char hostname[200];
	listenfd=socket(AF_INET,SOCK_STREAM,0);
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(53);
	bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	listen(listenfd,5);
	printf("\nWaiting for the client requests..\n");
	for(;;)
	{
		connefd=accept(listenfd,(struct sockaddr *)NULL,NULL);
		printf("\nConnetfd:%d\n",connefd);
		if((pid=fork())==0)
		{
		close(listenfd);
		//RK//readline(connefd,buff,5000);
		i = recv(connefd,&r1,sizeof(r1),0);
    		//buff[i]='\0';
		strcpy(buff,r1.buff_hash);
		printf("\n......Packet.....\n");
		printf("E(HASH):%s\n",r1.buff_hash);
	        //printf("E(DN):%s\n",r1.buff_dn);
    	   	//printf("E(UNAME):%s\n",r1.uname);
    		//printf("E(PASS):%s\n",r1.passwd);
                //printf("KEY:%ju %ju %ju\n",r1.e,r1.n,r1.ua);
		////DES/////////////////////////////////////////////////

		//decrypted_dn=malloc(r1.len_dn);
		//ptr= &(r1.buff_dn[0]);
		//memcpy(decrypted_dn,Decrypt(key,ptr,r1.len_dn), r1.len_dn);
		//printf("Decrypted domain text\t : %s \n",decrypted_dn);

		decrypted_uname=malloc(r1.len_uname);
		ptr= &(r1.uname[0]);
		memcpy(decrypted_uname,Decrypt(key,ptr,r1.len_uname), r1.len_uname);
		printf("Decrypted uname text\t : %s \n",decrypted_uname);
	
		decrypted_pass=malloc(r1.len_pass);
		ptr= &(r1.passwd[0]);
		memcpy(decrypted_pass,Decrypt(key,ptr,r1.len_pass), r1.len_pass);
		printf("Decrypted passwd text\t : %s \n",decrypted_pass);
			
		if((x=verify_Uname_Pass(decrypted_uname,decrypted_pass))==1)
		{
			printf("\nBoth Uname and Pass are present in the table.\n");
		}
		else
		{
			printf("\nBoth Uname and Pass are not present in the table.\n");
		}	
		x=accesslevelConfirm();
		if(x==2)
		{
			printf("\nHighest Level\n");
	             decrypted_dn=malloc(r1.len_dn);
	             ptr= &(r1.buff_dn[0]);
        	     memcpy(decrypted_dn,Decrypt(key,ptr,r1.len_dn), r1.len_dn);
               	     printf("Decrypted domain text\t : %s \n",decrypted_dn);

			get_dns_servers();    
                	ngethostbyname(decrypted_dn, T_A);
		}	
		else if (x==1)
		{
			printf("\nMedium Level\n");

				decrypted_dn=malloc(r1.len_dn);
                     		ptr= &(r1.buff_dn[0]);
                     		memcpy(decrypted_dn,Decrypt(key,ptr,r1.len_dn), r1.len_dn);
                     		printf("Decrypted domain text\t : %s \n",decrypted_dn);
                        	if((yy=checkBlocklist(decrypted_dn))!=1)
				{
					get_dns_servers();
                        		ngethostbyname(decrypted_dn, T_A);
				}
				else
				{
			
				}	
		}
		else if(x==0)
		{
			printf("\nNull Access level\n");
		}
		///////////////////////////////////////////DNS////
		//strcpy(hostname, );
		//get_dns_servers();	
		//ngethostbyname(hostname , T_A);
		//////////////////////////////////////////////////
            	if(send(connefd,buff,i,0) < 0)
            	{
                        printf("ERROR: Failed to send\n");
                        exit(1);
            	}
		
            	exit(0);
		}
		printf("\nClient with ID:%d is being served !\n",pid);
	}
		close(connefd);
		return 0;
}
		
