#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<stdlib.h>
#include<math.h>

void hex_to_bin(char *,char *);
char* bin_to_hex(char *);
void permutation(char *,char *);
void make_half(char *,char *,char *);
void single_shift(char *,char *);
void double_shift(char *,char *);
void make_key(char *,char *,char *);
void permutation_32(char *,char *);
void permutation_48(char *,char *);
void permutation_64(char *,char *,char *);

void des_round(char *,char *,char *,char *,char *,char *,char *);
void des_round_decry(char *,char *,char *,char *,char *,char *,char *);
void copy(char *,char *);
void permut_48(char *,char *);
void xor(char *,char *,char *);
void xor_32(char *,char *,char *);
void common_permutation(char *,char *);
void hex_to_plain(char *,char *,int);
int switch_case(char );
char SB[32];

char *bin[]={
"0000",
"0001",
"0010",
"0011",
"0100",
"0101",
"0110",
"0111",
"1000",
"1001",
"1010",
"1011",
"1100",
"1101",
"1110",
"1111"
};

char hex[16]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

int PC1[8][7]={
57,49,41,33,25,17,9,
1,58,50,42,34,26,18,
10,2,59,51,43,35,27,
19,11,3,60,52,44,36,
63,55,47,39,31,23,15,
7,62,54,46,38,30,22,
14,6,61,53,45,37,29,
21,13,5,28,20,12,4
};

int PC2[8][6]={
14,17,11,24,1,5,
3,28,15,6,21,10,
23,19,12,4,26,8,
16,7,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32
};

int IP[8][8]={
58,50,42,34,26,18,10,2,
60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6,
64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,
59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,
63,55,47,39,31,23,15,7};

int E_bit[8][6]={
32,1,2,3,4,5,
4,5,6,7,8,9,
8,9,10,11,12,13,
12,13,14,15,16,17,
16,17,18,19,20,21,
20,21,22,23,24,25,
24,25,26,27,28,29,
28,29,30,31,32,1};

char *look_up[]={
"00",
"01",
"10",
"11"};

int sb_permutation[8][4]={
16,7,20,21,
29,12,28,17,
1,15,23,26,
5,18,31,10,
2,8,24,14,
32,27,3,9,
19,13,30,6,
22,11,4,25};

int s1[4][16]={
14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13};

int s2[4][16]={
15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9};

int s3[4][16]={
10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12};

int s4[4][16]={
7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14};

int s5[4][16]={
2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3};

int s6[4][16]={
12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
10,15,4,2,7,12,9,5,6,1,12,14,0,11,3,8,
9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13};

int s7[4][16]={
4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12};

int s8[4][16]={
13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11};

int ip_inverse[8][8]={
40,8,48,16,56,24,64,32,
39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,
35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,
33,1,41,9,49,17,57,25
};


void hex_to_bin(char *input,char *in)
{
short i,j,k,lim=0;
for(i=0;i<16;i++)
{
for(j=0;j<16;j++)
{
if(*(input+i)==hex[j])
{
for(k=0;k<4;k++)
{
*(in+lim)=bin[j][k];
lim++;
}
}
}
}
}

char* bin_to_hex(char *bit)
{
char tmp[5],*out;
short lim=0,i,j;
out=(char*)malloc(16*sizeof(char));
for(i=0;i<64;i=i+4)
{
tmp[0]=bit[i];
tmp[1]=bit[i+1];
tmp[2]=bit[i+2];
tmp[3]=bit[i+3];
tmp[4]='\0';
for(j=0;j<16;j++)
{
if((strcmp(tmp,bin[j]))==0)
{
out[lim++]=hex[j];
break;
}
}
}
out[lim]='\0';
return out;
}

void hex_to_plain(char *in,char *out,int t)
{
int i,j=0,z,sum;
char temp[3];


for(i=0;i<t;i=i+2)
{
sum=0;
temp[0]=in[i];
if(temp[0]>=65 && temp[0]<=71)
z=switch_case(temp[0]);
else
      z=temp[0]-48;
sum=sum+z*16;

temp[1]=in[i+1];
if(temp[1]>=65 && temp[1]<=71)
z=switch_case(temp[1]);
else
z=temp[1]-48;

sum=sum+z*1;
temp[2]='\0';

*(out+j)=sum;
j++;
}
*(out+j)='\0';

}

int switch_case(char a)
{
switch(a)
{
case 'A':
return(10);
break;

case 'B':
return(11);
break;

case 'C':
return(12);
break;

case 'D':
return(13);
break;

case 'E':
return(14);
break;

case 'F':
return(15);
break;

}
}

void permutation(char *key_bin,char *key_PC1)
{
short i,j,k=0,temp;

for(i=0;i<8;i++)
{
for(j=0;j<7;j++)
{
temp=PC1[i][j]-1;
*(key_PC1+k)=*(key_bin+temp);
k++;
}
}
}

void make_half(char *key_PC1,char *a,char *b)
{
int i,j=0;
for(i=0;i<56;i++)
{
if(i<28)
*(a+i)=*(key_PC1+i);
else
{
*(b+j)=*(key_PC1+i);
j++;
}
}
}

void single_shift(char *p,char *q)
{
int i;
*(q+27)=*(p+0);
for(i=0;i<27;i++)
*(q+i)=*(p+(i+1));
}

void double_shift(char *p,char *q)
{
int i;
*(q+26)=*(p+0);
*(q+27)=*(p+1);
for(i=0;i<26;i++)
*(q+i)=*(p+(i+2));
}

void make_key(char *a,char *b,char *c)
{
int i;
for(i=0;i<28;i++)
*(c+i)=*(a+i);
for(i=28;i<56;i++)
*(c+i)=*(b+(i-28));
}

void permutation_48(char *CD,char *K)
{
short i,j,m=0,temp;

for(i=0;i<8;i++)
{
for(j=0;j<6;j++)
{
temp=PC2[i][j]-1;
*(K+m)=*(CD+temp);
m++;
}
}
}

void permutation_64(char *in,char *L,char *R)
{
int i,j,m=0,temp;
for(i=0;i<4;i++)
{
for(j=0;j<8;j++)
{
temp=IP[i][j]-1;
*(L+m)=*(in+temp);
m++;
}
}
m=0;
for(i=4;i<8;i++)
{
for(j=0;j<8;j++)
{
temp=IP[i][j]-1;
*(R+m)=*(in+temp);
m++;
}
}
}

void des_round(char *L1,char *R1,char *L0,char *R0,char *ER0,char *K1,char *F1)
{
char t[3],tp[5],f[32];
int temp,i,row,column,j,limit=0;
copy(L1,R0);
permut_48(R0,ER0);
/*printf("\nER0 : ");
for(i=0;i<48;i++)
printf("%c",ER0[i]);*/

xor(K1,ER0,F1);

/*printf("\nF1 : ");
for(i=0;i<48;i++)
printf("%c",F1[i]);*/

for(i=0;i<48;i=i+6)
{
t[0]=F1[i];
t[1]=F1[i+5];
t[2]='\0';
for(j=0;j<4;j++)
{
if(strcmp(t,look_up[j])==0)
{
row=j;
/*printf("%d",row);*/
break;
}
}
tp[0]=F1[i+1];
tp[1]=F1[i+2];
tp[2]=F1[i+3];
tp[3]=F1[i+4];
tp[4]='\0';
for(j=0;j<16;j++)
{
if(strcmp(tp,bin[j])==0)
{
column=j;
break;
}
}
switch(i)
{
case 0:
temp=s1[row][column];
break;
case 6:
temp=s2[row][column];
break;
case 12:
temp=s3[row][column];
break;
case 18:
temp=s4[row][column];
break;
case 24:
temp=s5[row][column];
break;
case 30:
temp=s6[row][column];
break;
case 36:
temp=s7[row][column];
break;
case 42:
temp=s8[row][column];
break;
}
for(j=0;j<4;j++)
{
SB[limit]=bin[temp][j];
limit++;
}
}
SB[limit]='\0';
/*printf("\nSB : %s",SB);  */
permutation_32(SB,f);
SB[0]='\0';
xor_32(L0,f,R1);
}

void des_round_decry(char *L1,char *R1,char *L0,char *R0,char *ER0,char *K1,char *F1)
{
char tp[5],f[32];
short temp,i,row,column,j,limit=0;
copy(L1,R0);
permut_48(R0,ER0);
xor(K1,ER0,F1);
for(i=0;i<48;i=i+6)
{
tp[0]=F1[i];
tp[1]=F1[i+5];
tp[2]='\0';
for(j=0;j<4;j++)
{
if(strcmp(tp,look_up[j])==0)
{
row=j;
break;
}
}
tp[0]=F1[i+1];
tp[1]=F1[i+2];
tp[2]=F1[i+3];
tp[3]=F1[i+4];
tp[4]='\0';
for(j=0;j<16;j++)
{
if(strcmp(tp,bin[j])==0)
{
column=j;
break;
}
}
switch(i)
{
case 0:
temp=s1[row][column];
break;
case 6:
temp=s2[row][column];
break;
case 12:
temp=s3[row][column];
break;
case 18:
temp=s4[row][column];
break;
case 24:
temp=s5[row][column];
break;
case 30:
temp=s6[row][column];
break;
case 36:
temp=s7[row][column];
break;
case 42:
temp=s8[row][column];
break;
}
for(j=0;j<4;j++)
{
SB[limit]=bin[temp][j];
limit++;
}
}
SB[limit]='\0';
permutation_32(SB,f);
SB[0]='\0';
xor_32(L0,f,R1);
}

void copy(char *L,char *R)
{
int i;
for(i=0;i<32;i++)
*(L+i)=*(R+i);
}

void permut_48(char *R,char *ER)
{
short i,j,m=0,temp;

for(i=0;i<8;i++)
{
for(j=0;j<6;j++)
{
temp=E_bit[i][j]-1;
*(ER+m)=*(R+temp);
m++;
}
}
}

void xor(char *K,char *ER,char *F)
{
int i,m=0;
for(i=0;i<48;i++)
{
if((*(K+i)=='1' && *(ER+i)=='1') || (*(K+i)=='0' && *(ER+i)=='0'))
{
*(F+m)='0';
m++;
}
else
{
*(F+m)='1';
m++;
}
}
}

void xor_32(char *L0,char *f,char *R1)
{
short i,m=0;
for(i=0;i<32;i++)
{
if((*(L0+i)=='1' && *(f+i)=='1') || (*(L0+i)=='0' && *(f+i)=='0'))
{
*(R1+m)='0';
m++;
}
else
{
*(R1+m)='1';
m++;
}
}
}

void permutation_32(char *SB1,char *f)
{
short i,j,m=0,temp;

for(i=0;i<8;i++)
{
for(j=0;j<4;j++)
{
temp=sb_permutation[i][j]-1;
*(f+m)=*(SB1+temp);
m++;
}
}
}

void common_permutation(char *in,char *out)
{
short i,j,temp,m=0;
for(i=0;i<8;i++)
{
for(j=0;j<8;j++)
{
temp=ip_inverse[i][j]-1;
out[m]=in[temp];
m++;
}
}
}
