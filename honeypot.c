/* pouzite knihovny */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <pjsua-lib/pjsua.h>
#include <curl/curl.h>
#include "cJSON.h"
#include <assert.h>
#include <curses.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "sqlite3.h"
#include <sqlite3.h>
#include <sys/ioctl.h>
#include <net/if.h>



/* deklaracia pouzitych funkcii */

void getCurrentTime();
void zprava(char *, char *, int);
void *GetUris(char *);
bool searchForCallerID(sqlite3 *db, char*);
void MakeCall(pjsua_acc_id acc_id);
void insertRecordToTable(sqlite3 *db, char*,unsigned int);
void updateSuspiciousLevel(sqlite3 *db, char *, unsigned int);
void *mentat_creator(char *, char *, char *,char *,char *, char *, char *, char *);
void *ParseFloodPacket(const u_char*, char *, char *,char*, char*, char*);
void *FloodCheck( void * );
void *FakeSIPcall( void *);
void process_packet(u_char *, const struct pcap_pkthdr *,const u_char *);
void process_ip_packet(const u_char * , int);
void print_udp_packet(const u_char * , int);
void PrintData (const u_char * , int, char *, char*, char*, char*);
void *curling(char *);
void *login();
void *Server();
void *SendToHoneypot(char *);
void *GetDataFromPacket(char *);
static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id,pjsip_rx_data *rdata);
static void on_call_state(pjsua_call_id call_id, pjsip_event *e);
static void on_call_media_state(pjsua_call_id call_id);
static void error_exit(const char *title, pj_status_t status);
static void writeLog(char *sprava);
static void writeMentatLog(char *sprava);
int SearchInBlackList(char *);
int readPipe(int);
int rand_range(int, int);
int CallNumTo();

#define BUFSIZE		1024
#define TRUE		1
#define FALSE		0
#define PORT		8888
#define LOGFILE		"honeypot.log"
#define LOGFILE2	"mentat.log"
#define FILENAME	"hpotconfig.conf"
#define DELIM		"="
#define MAXBUF		1024
#define THIS_FILE 	"log.txt"
#define SQL		"sqlite3.db"
#define logfile5	"pakety.log"


struct string
{
        char *ptr;
        size_t len;
};

struct timeval  tv1, tv2, tv3, tv4;

void init_string(struct string *s)
{
        s->len = 0;
        s->ptr = malloc(s->len+1);
        if (s->ptr == NULL)
        {
                fprintf(stderr, "malloc() failed\n");
                exit(EXIT_FAILURE);
        }
        s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
        size_t new_len = s->len + size*nmemb;
        s->ptr = realloc(s->ptr, new_len+1);
        if (s->ptr == NULL)
        {
                fprintf(stderr, "realloc() failed\n");
                exit(EXIT_FAILURE);
        }
        memcpy(s->ptr+s->len, ptr, size*nmemb);
        s->ptr[new_len] = '\0';
        s->len = new_len;

        return size*nmemb;
}

FILE *logfile, *logfile2;
struct sockaddr_in source,dest;
int tcp = 0 , udp = 0,icmp = 0,others = 0,igmp = 0,total = 0, i, j;
int inv = 0, reg = 0, opt = 0;
char pch[10], pch2[10], pch3[10];

/* struktura premmennych, ktore budu nacitane z konfiguracneho suboru */
/* ich vyznam je popisany v danom subore (hpotconfig.conf) */
struct config
{
	char interface[BUFSIZE];
	char packet_num[BUFSIZE];
	char server_port[BUFSIZE];
	char flood_interval[BUFSIZE];
	char pcap_filter[BUFSIZE];
	char honeypot_numofclients[BUFSIZE];
	char sipdomain[BUFSIZE];
	char honeypot_port[BUFSIZE];
	char honeypot_extension[BUFSIZE];
	char destination_extensions[BUFSIZE];
	char logfile_dir[BUFSIZE];
	char blacklist_dir[BUFSIZE];
	char whois_domain[BUFSIZE];
	char time_min[BUFSIZE];
	char time_max[BUFSIZE];
	char sqlite_dir[BUFSIZE];
	char spit_call_count[BUFSIZE];
	char spit_call_sec[BUFSIZE];

};

/* funkcie pre priradenie hodnot premennym z predchadzajucej struktury */
struct config get_config(char *filename)
{
	struct config configstruct;
	FILE *file = fopen (filename, "r");

	if (file != NULL)
	{
		char line[MAXBUF];
		int i = 0;

		while(fgets(line, sizeof(line), file) != NULL)
		{
			char *cfline;
			cfline = strstr((char *)line,DELIM);
			cfline = cfline + strlen(DELIM);

			if (strstr(line, "interface") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.interface,cfline,strlen(cfline));
			}

			if (strstr(line, "packet_num") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.packet_num,cfline,strlen(cfline));
			}

			if (strstr(line, "server_port") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.server_port,cfline,strlen(cfline));
			}

			if (strstr(line, "flood_interval") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.flood_interval,cfline,strlen(cfline));
			}

			if (strstr(line, "pcap_filter") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.pcap_filter,cfline,strlen(cfline));
			}

			if (strstr(line, "honeypot_numofclients") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.honeypot_numofclients,cfline,strlen(cfline));
			}

 			if (strstr(line, "sipdomain") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.sipdomain,cfline,strlen(cfline));
			}

			if (strstr(line, "honeypot_port") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.honeypot_port,cfline,strlen(cfline));
			}

			if (strstr(line, "honeypot_extension") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.honeypot_extension,cfline,strlen(cfline));
			}

			if (strstr(line, "destination_extensions") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.destination_extensions,cfline,strlen(cfline));
			}

			if (strstr(line, "logfile_dir") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.logfile_dir,cfline,strlen(cfline));
			}

			if (strstr(line, "blacklist_dir") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.blacklist_dir,cfline,strlen(cfline));
			}

			if (strstr(line, "whois_domain") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.whois_domain,cfline,strlen(cfline));
			}

			if (strstr(line, "time_min") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.time_min,cfline,strlen(cfline));
			}

			if (strstr(line, "time_max") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.time_max,cfline,strlen(cfline));
			}

			if (strstr(line, "sqlite_dir") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.sqlite_dir,cfline,strlen(cfline));
			}


			if (strstr(line, "spit_call_count") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.spit_call_count,cfline,strlen(cfline));
			}

			if (strstr(line, "spit_call_sec") != NULL)
			{
				cfline[strlen(cfline)-1] = '\0';
				memcpy(configstruct.spit_call_sec,cfline,strlen(cfline));
			}


			i++;
		}
		fclose(file);
	}
	return configstruct;
}

struct ip_address
{
	char source_ip_address[BUFSIZE];
	char destination_ip_address[BUFSIZE];
};


/* hlavna funkcia, deklaracia a spustenie jednotlivych vlakien */
int main()
{
	char *logmsg;
	pthread_t thread1, thread2, thread3;

	const char *message1 = "Thread 1";
	const char *message2 = "Thread 2";
	const char *message3 = "Thread 3";

	int  iret1, iret2, iret3;

	/* vlakno pre pcap */
	iret1 = pthread_create( &thread1, NULL, FloodCheck, (void*) message1);
	if(iret1)
	{
		zprava("ERROR","pthread_create() thread(1) was not created!", errno);
		exit(EXIT_FAILURE);
	}

	/* vlakno pre pjsua, detekce SPIT, VoIP falosny provoz, konfuiguracia honeypotu */
	iret2 = pthread_create( &thread2, NULL, FakeSIPcall, (void*) message2);
	if(iret2)
	{
		zprava("ERROR", "pthread_create() thread(2) was not created!", errno);
		exit(EXIT_FAILURE);
	}

	/* vlakno pre klient-server komunikaciu */
	iret3 = pthread_create( &thread3, NULL, Server, (void*) message3);
	if(iret3)
	{
		zprava("ERROR", "pthread_create() thread(3) was not created!", errno);
		exit(EXIT_FAILURE);
	}


	zprava("INFO", "pthread_create() for FloodCheck thread - OK! ", iret1);

	zprava("INFO", "pthread_create() for Pjsua thread - OK! ", iret2);

	zprava("INFO", "pthread_create() for Server thread - OK! ", iret3);



	/* Wait till threads are complete before main continues. Unless we  */
	/* wait we run the risk of executing an exit which will terminate   */
	/* the process and all threads before the threads have completed.   */

	pthread_join( thread1, NULL);
	pthread_join( thread2, NULL);
	pthread_join( thread3, NULL);

	exit(EXIT_SUCCESS);
}


/* kontrola a filtracia paketov vyuzitim libpcap knihovny */
void *FloodCheck( void *ptr )
{
	struct config configstruct;
	configstruct = get_config(FILENAME);

	pcap_if_t *alldevsp , *device;
	pcap_t *handle;
	//char filter_exp[] = "portrange 5060-5065";

	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char errbuf[100], *devname  , devs[100][100];
	int count = 1 , n;
	char zbuff[100];

	devname = configstruct.interface;

	/* spustenie sniffingu na rozhrani definovanom v konfiguracnom subore (napr. eth0) */
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	if (handle == NULL)
	{
		zprava("ERROR", "Couldn't open device for sniffing", errno);
		exit(1);
	}
	else
	{
		snprintf(zbuff, 90, "Device [ %s ] was succesfully opened for sniffing", devname);
		zprava("INFO", zbuff, 1);
	}

	/* aktivacia pcap filtra */
	if (pcap_compile(handle, &fp, configstruct.pcap_filter, 0, net) == -1)
	{
		zprava("ERROR", "Couldn't apply pcap filter!", errno);
		return(void*)(2);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		zprava("ERROR", "Couldn't install pcap filter", errno);
		return(void*)(2);
	}

	/* spustenie packet sniffingu v nekonecnej smycke */
	pcap_loop(handle , -1 , process_packet , NULL);

	return 0;
}


void *FakeSIPcall(void *ptr )
{
		struct config configstruct;
		configstruct = get_config(FILENAME);

		pjsua_acc_id acc_id;
		pj_status_t status;

		status = pjsua_create();
		if ( status != PJ_SUCCESS )
		{
			zprava("ERROR", "pjsua_create()", errno);
			error_exit( "Error in pjsua_create()", status );
		}

		pjsua_config cfg;
		pjsua_logging_config log_cfg;

		pjsua_config_default( &cfg );
		cfg.cb.on_incoming_call = &on_incoming_call;
		cfg.cb.on_call_media_state = &on_call_media_state;
		cfg.cb.on_call_state = &on_call_state;

		pjsua_logging_config_default( &log_cfg );
		log_cfg.console_level = 4;
		status = pjsua_init( &cfg, &log_cfg, NULL );
		if ( status != PJ_SUCCESS )
		{
			zprava("ERROR", "pjsua_init()", errno);
			error_exit( "Error in pjsua_init()", status );
		}

		{
			pjsua_transport_config cfg;
			pjsua_transport_config_default( &cfg );
			cfg.port = atoi(configstruct.honeypot_port);
			status = pjsua_transport_create( PJSIP_TRANSPORT_UDP, &cfg, NULL );

			if ( status != PJ_SUCCESS )
			{
				zprava("ERROR","pjsua creating transport", errno);
				error_exit( "Error creating transport", status );
			}
		}

		status = pjsua_start();
		if ( status != PJ_SUCCESS )
		{
			zprava("ERROR","Couldnt start pjsua", errno);
			error_exit( "Error starting pjsua", status );
		}

		{
			pjsua_acc_config cfg;
			pjsua_acc_config_default( &cfg );

			char *adresa1 = (char *) malloc(35);
			char *pmc = (char *) malloc(35);
			char buffer1[180];

			snprintf(adresa1,30,"sip:%s@%s\0",configstruct.honeypot_extension,configstruct.sipdomain);
			/*strcpy(adresa1,"sip:");
			strcat(adresa1, prihlas ); //nacitat struktura
			strcat(adresa1, "@");
			strcat(adresa1, configstruct.sipdomain);
			strcat(adresa1, "\0");*/


			snprintf(pmc,30,"sip:%s\0", configstruct.sipdomain);
			/*strcpy(pmc, "sip:");
			strcat(pmc, configstruct.sipdomain);
			strcat(pmc, "\0");*/

			cfg.id = pj_str(adresa1);
			cfg.reg_uri = pj_str(pmc);
			cfg.cred_count = 1;
			cfg.cred_info[0].realm = pj_str("*" );
			cfg.cred_info[0].scheme = pj_str("asterisk" );
			cfg.cred_info[0].username = pj_str(configstruct.honeypot_extension); //nacitat strukturu
			cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
			cfg.cred_info[0].data = pj_str(configstruct.honeypot_extension); //nacitat strukturu

			status = pjsua_acc_add( &cfg, PJ_TRUE, &acc_id );
			if ( status != PJ_SUCCESS )
			{
				zprava("ERROR", "pjsua adding account", errno);
				error_exit( "Error adding account", status );
			}
			else
			{
				snprintf (buffer1, 160 , "Honeypot successfully registered URI: %s ", adresa1);
				zprava("INFO", buffer1, 1);
			}
		}

	while (TRUE)
	{
		MakeCall(acc_id);
		sleep(10);
	}

	pjsua_destroy();

	return 0;
}

static void on_incoming_call( pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data *rdata )
{

	char buffer[100];
	pjsua_call_info ci;
	PJ_UNUSED_ARG( acc_id );
	PJ_UNUSED_ARG( rdata );
	pjsua_call_get_info( call_id, &ci );

	/* info o prichadzajucom hovoru na honeypot */
	PJ_LOG( 3,( THIS_FILE, "Incoming call from %.*s!!", (int) ci.remote_info.slen, ci.remote_info.ptr ) );
	snprintf(buffer, 100 , "Incoming call from %.*s ",(int) ci.remote_info.slen, ci.remote_info.ptr);
	zprava("INFO", buffer, 1);

	/* posli spravu 180 Ringing po dobu 5 sekund */
	//pjsua_call_answer( call_id, 180, NULL, NULL );
	//sleep(5);
	/* start casu hovoru */
    	gettimeofday(&tv3, NULL);

	/* po piatich sekundach akceptuj hovor spravou 200 OK*/
    	//pjsua_call_answer( call_id, 200, NULL, NULL );

}

/* funkcia pocas aktivneho hovoru */
static void on_call_state( pjsua_call_id call_id, pjsip_event *e )
{
	struct config configstruct;
	configstruct = get_config(FILENAME);

	char *temp = malloc(60 * sizeof(char));
	char *callerid = malloc(60 * sizeof(char));
	char *temp2 = malloc(20 * sizeof(char));

	sqlite3 *dbs;
	char *err_msg = 0;
	sqlite3_stmt *res, *res2;


	pjsua_call_info ci;
	PJ_UNUSED_ARG(e);

	pjsua_call_get_info( call_id, &ci );

	/* informacia o stave hovoru */
	PJ_LOG( 3,( THIS_FILE, "Call %d state=%.*s", call_id, (int) ci.state_text.slen, ci.state_text.ptr ) );
	strncpy(temp2,ci.state_text.ptr,(int) ci.state_text.slen);
	printf("%s\n", temp2);

    	/* pokial bol hovor ukonceny (sprava DISCONNCTD), tak ukonci meranie casu hovoru) */
	if (strcmp(temp2,"DISCONNCTD") == 0)
	{
		printf("%f\n",gettimeofday(&tv4, NULL));

		/* vypocet celkovej doby trvania hovoru */
		float vysledok = (float)((tv4.tv_usec - tv3.tv_usec) / 1000000 + (tv4.tv_sec - tv3.tv_sec));

		printf("********************************\n");
		printf("********************************\n");

		/* porovnanie doby hovoru s nastavenou hodnotou pre detekciu SPIT hovoru */
		/* pokial je vyledok mensi nez nastavena hodnota pravdepodobne sa jedna o SPIT call */
		if ((vysledok > 0) && (vysledok < atof(configstruct.spit_call_sec)))
		{
			//printf("POSSIBLE SPIT CALL  :::  %f\n", vysledok);
			char buffer[100];
			snprintf (buffer, 100 , "Possible SPIT call from %.*s ",(int) ci.remote_info.slen, ci.remote_info.ptr);
			zprava("ATTACK", "Possible SPIT call", 2);

			/* ziskanie CALLERID volajuceho */
			strncpy(temp, ci.remote_info.ptr, (int)ci.remote_info.slen);
			callerid = strtok(temp, "@:");
   			callerid = strtok(NULL, "@:");
			//printf("CALLERID :  %s\n", callerid);

			/* otvor spit databazu podozrivych volajucich */
			int rc = sqlite3_open(SQL, &dbs);
			if (rc != SQLITE_OK)
			{
				zprava("ERROR", "Couldn't open sqlite database", errno);
				sqlite3_close(dbs);
			}

			/* zisti ci sa volajuci nachadza v databaze */
			bool search = searchForCallerID(dbs, callerid);

			/* v pripade ze sa v nej nenechadza, vloz ucastnika do DB a prirad mu hodnotu 0 */
			if (search == 0)
			{
				insertRecordToTable(dbs, callerid, 1);
			}

			/*ak sa v tabulke nachadza, zvys mu hodnotu SPIT value o 1 */
			else if (search == 1)
			{
				char *sql = "SELECT level FROM Suspicious_Table WHERE callerid = ?";

				rc = sqlite3_prepare_v2(dbs, sql, -1, &res, 0);
				if (rc == SQLITE_OK)
				{
					sqlite3_bind_text(res, 1, callerid, -1, SQLITE_STATIC);

					int step = sqlite3_step(res);
		                	if (step == SQLITE_ROW)
					{
						unsigned int level = sqlite3_column_int(res, 0);
						sqlite3_finalize(res);

						printf("Vysledok: %u\n", level);

						/* pokud pocet podozrivych volani nedosiahol prednastavenej hodnoty, zvysuj SPIT level o 1 */
						if (level < atoi(configstruct.spit_call_count))
						{
							char *query = "UPDATE Suspicious_Table set level = ? where callerid = ?";
							sqlite3_prepare_v2(dbs, query, strlen(query), &res2, NULL);
							unsigned int tmp =  level+1;
							sqlite3_bind_int(res2, 1, tmp);
							sqlite3_bind_text(res2, 2, callerid, strlen(callerid), 0);

							int result = sqlite3_step(res2);
							if (result != SQLITE_DONE)
							{
								zprava("ERROR" ,"Cannot update database data!", errno);
							}
							else
							{
								zprava("INFO", "SQLITE DB was successfully UPDATED!", 1);
								sqlite3_finalize(res2);
								sqlite3_close(dbs);
							}
						}

						/* ak level dosiahol prednastavenej hodnoty, jedna sa o SPIT call, vytvor MENTAT string a posli info ostatnym honeypotom */
						if (level == atoi(configstruct.spit_call_count))
						{

							int fd;
							struct ifreq ifr;


							/* ziskanie informacii o ip adresach a pouzitych portoch */
							fd = socket(AF_INET, SOCK_DGRAM, 0);
							ifr.ifr_addr.sa_family = AF_INET;
							strncpy(ifr.ifr_name, configstruct.interface, IFNAMSIZ-1);
							ioctl(fd, SIOCGIFADDR, &ifr);
							close(fd);
							sleep(1);

							//FILE* file = fopen("/etc/asterisk/honey_hlp.txt", "r");
							//char line[256];
							char *check = malloc( 36 * sizeof(char));
							char buf[1024];
							char *source_ip = malloc(24 * sizeof(char));
							char *sp = malloc(40 *sizeof(char));
							char *source_port = malloc(24 *sizeof(char));
							char *from_uri = malloc(36 *sizeof(char));
							char *to_uri = malloc(36 *sizeof(char));
							char *buff = (char *)malloc(100);
							char *id = malloc(90 *sizeof(char));

							/*while (fgets(line, sizeof(line), file))
							{
								source_ip = strtok(line, ";");
								source_port = strtok(NULL, ";");
								call_id = strtok(NULL, ";");
								from_uri = strtok(NULL, ";");
								to_uri = strtok(NULL, ";");
								extension = strtok(NULL, ";");
								extension[strlen(extension)-1] = '\0';
							}
    							fclose(file); */

							snprintf(from_uri, 35, "%.*s ",(int) ci.remote_contact.slen, ci.remote_contact.ptr);
							snprintf(to_uri, 35, "%.*s ",(int) ci.local_contact.slen, ci.local_contact.ptr);
							snprintf(id, 80, "%.*s ",(int) ci.call_id.slen, ci.call_id.ptr);
							snprintf(check, 35, "%.*s ",(int) ci.remote_info.slen, ci.remote_info.ptr);


							strncpy(sp, ci.remote_contact.ptr, (int)ci.remote_contact.slen);
				                        source_port = strtok(sp, ":>");
                        				source_port = strtok(NULL, ":>");
							source_port = strtok(NULL, ":>");

							/* vytvorenie stringu o utoku pre vsetkych pripojenych klientov */
							strcpy(buff, "SPIT");strcat(buff, ";");
							strcat(buff, configstruct.sipdomain);strcat(buff, ";");
							strcat(buff, source_port);strcat(buff, ";");
							strcat(buff, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));strcat(buff, ";");
							strcat(buff, configstruct.honeypot_port);strcat(buff, ";");
							strcat(buff, callerid); strcat(buff, ";");

							/* vytvor MENTAT string */
							//mentat_creator("SPIT ATTACK", configstruct.sipdomain, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), source_port, configstruct.honeypot_port, id, from_uri, to_uri);

							source_ip = strtok(check, "@>");
							source_ip = strtok(NULL, "@>");

							mentat_creator("SPIT ATTACK", source_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), source_port, configstruct.honeypot_port, id, from_uri, to_uri);							

							if ((strcmp(source_ip,"10") == 0)||(strcmp(source_ip,"192"))||(strcmp(source_ip,"172")))
							{
								strcat(buff,"PRIVATE IP ADDRESS");strcat(buff, "\0");
							}

							else
							{
								strcat(buff,curling(source_ip));strcat(buff, "\0");
							}

							/* posli info o utoku klientom */
							SendToHoneypot(buff);
							free(buff);
							snprintf (buf, 100 , "SPIT attack detected from %s ", source_ip);

							zprava("ATTACK", buf, 2);
						}
					}
				}
				else
				{
					//fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(dbs));
					zprava("ERROR", "Failed to execute sqlite statement", errno);
				}
			}
		}

		printf("********************************\n");
		printf("********************************\n");

	}
}

static void on_call_media_state(pjsua_call_id call_id)
{
	pjsua_call_info ci;
	pjsua_call_get_info(call_id, &ci);
	if (ci.media_status == PJSUA_CALL_MEDIA_ACTIVE)
	{
		pjsua_conf_connect(ci.conf_slot, 0);
		pjsua_conf_connect(0, ci.conf_slot);
	}
}


static void error_exit(const char *title, pj_status_t status)
{
	pjsua_perror(THIS_FILE, title, status);
	pjsua_destroy();
	exit(1);
}


static void writeLog(char *sprava)
{
	FILE *f;
	f = fopen(LOGFILE, "a+");

	if (f != NULL)
	{
		fputs(sprava, f);
		fclose(f);
     	}
     	else
	{
		printf("ERROR: Cannot open Log file\n");
	}
}



static void writeMentatLog(char *sprava)
{
        FILE *f;
        f = fopen(LOGFILE2, "a+");

        if (f != NULL)
        {
                fputs(sprava, f);
                fclose(f);
        }
        else
        {
                printf("ERROR: Cannot open Log file\n");
        }
}



/* spracovanie paketov zachytených pomocou pcap */
void process_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *buffer)
{
	int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;

	switch (iph->protocol)
	{
		/* cislo 6 predstavuje cislo TCP paketu */
		case 6:
				++tcp;
				break;

		/* cislo 17 predstavuje cislo UDP paketu */
		case 17:
				++udp;
				/* posli UDP paket na spracovanie, SIP protokol využíva UDP port */
				print_udp_packet(buffer , size);
				break;

		/* ostatne pakety */
		default:
				++others;
				break;
	}
	//printf("TCP : %d   UDP : %d   Others : %d   Total : %d \n", tcp , udp , others , total);
}

/* ziskanie niektorych informacii z UDP packetu */
void print_udp_packet(const u_char *Buffer , int Size)
{
	unsigned short iphdrlen;
	char *s_port = malloc(10 * sizeof(char));
	char *d_port = malloc(10 * sizeof(char));
	char *ip_src = malloc(28 * sizeof(char));


	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	memset(&source, 0, sizeof(source));
    	source.sin_addr.s_addr = iph->saddr;

	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	memset(&dest, 0, sizeof(dest));
    	dest.sin_addr.s_addr = iph->daddr;


	/* zdrojova IP adresa */
	snprintf(ip_src, 28, "%s", (inet_ntoa(source.sin_addr)));
	//printf("%s\n", ip_src);

	/* pouzity zdrojovy port */
	snprintf (s_port, sizeof(s_port), "%d",ntohs(udph->source));

	/* cielovy port */
	snprintf (d_port, sizeof(d_port), "%d",ntohs(udph->dest));

	/* posli data pre dalsie spracovanie funkcii PrintData */

	printf("%s %s %s %s \n", ip_src, inet_ntoa(dest.sin_addr), s_port, d_port);
	PrintData(Buffer + header_size , Size - header_size, ip_src, inet_ntoa(dest.sin_addr), s_port, d_port);
}


/* funkcia PrintData spracuje SIP pakety a kontroluje zda nedochadza k niektorumu z druhov floodingu */
void PrintData (const u_char *data , int Size, char *ipecka, char *ipecka_d, char *source_port, char *destination_port)
{
	struct config configstruct;
	configstruct = get_config(FILENAME);

	char inviteflood[6];
	char optflood[7];
	char regflood[8];
	char buff1[100], buff2[100], buff3[100];
	char *check = malloc(24 * sizeof(char));

	//INVITE FLOOD
	//***********************************************************************/


	strncpy(inviteflood, data, 6);
	inviteflood[6] = '\0';

	/* pokial sa nasla INVITE sprava pokracuj */
	if(strcmp(inviteflood,"INVITE") == 0)
	{
		/* ak to bol prvy INVITE spusti casovac, uloz do premennej hodnotu IP adresy odosielatela INVITE spravy */
		if (inv == 0)
		{
			strcpy(pch, ipecka);
			printf("%f\n",gettimeofday(&tv1, NULL));
		}
		//printf("%d %s\n",inv, pch);

		/* v pripade zhodujucej IP adresy dvoch po sebe iducich INVITE sprav, inkrementuj hodnotu premennej 'inv' */
		if(strcmp(pch, ipecka) == 0)
		{
			++inv;

			/* pokial sa hodnotu premennej inv rovna hodnote poctu paketov nastavenej v conf subore, ukonci meranie casu */
			if (inv == atoi(configstruct.packet_num))
			{

				printf("%f\n",gettimeofday(&tv2, NULL));
				float vysledok = (float)((tv2.tv_usec - tv1.tv_usec) / 1000000 + (tv2.tv_sec - tv1.tv_sec));
				printf("%f < %f\n", vysledok, atof(configstruct.flood_interval));

				/* v pripade ak bol prijaty urcity pocet paketov za cas mensi ako prednastavena hodnota, jedna sa o INVITE flood */
				if(vysledok < atof(configstruct.flood_interval))
				{
					/* parsuj data pre zaslanie dalsim klientom a MENTAT */
					ParseFloodPacket(data,"INVITE", ipecka, ipecka_d, source_port, destination_port);

					/* vynuluj counter ideme odznova */
					inv = 0;
				}
				/* nebola splnena podmienka casoveho limitu, vynuluj counter */
				else
				{
					inv = 0;
				}
			}
		}
		/* nebol dosiahnuty pocet rovnakych za sebou iducich INVITE sprav, vynuluj counter */
		else
		{
			inv = 0;
		}

	}

	/* REGISTER FLOOD, funkcia obdobna s INVITE flood detekciou */
	/***********************************************************************/
	strncpy(regflood, data, 8);
	regflood[8] = '\0';
	if(strcmp(regflood,"REGISTER") == 0)
	{
		if (reg == 0)
		{
				strcpy(pch2, ipecka);
				printf("%f\n",gettimeofday(&tv1, NULL));
		}
		//printf("%d %s\n",reg, pch2);

		if(strcmp(pch2, ipecka) == 0)
		{
			++reg;
			if (reg == atoi(configstruct.packet_num))
			{
				printf("%f\n",gettimeofday(&tv2, NULL));

				float vysledok = (float)((tv2.tv_usec - tv1.tv_usec) / 1000000 + (tv2.tv_sec - tv1.tv_sec));
				printf("%f < %f\n", vysledok, 1.5f);

				if(vysledok < atof(configstruct.flood_interval))
				{
					ParseFloodPacket(data,"REGISTER", ipecka, ipecka_d, source_port, destination_port);
                   			reg = 0;
				}
				else
				{
					reg = 0;
				}
			}
        	}
		else
		{
			reg = 0;
		}

	}


	/* OPTIONS FLOOD, obdobne ako predosle flood detekcne funkcie */
	/**********************************************************************/
	strncpy(optflood, data, 7);
	regflood[7] = '\0';
	if(strcmp(optflood,"OPTIONS") == 0)
	{
		if (opt == 0)
		{
			strcpy(pch3, ipecka);
			gettimeofday(&tv1, NULL);
		}
//		printf("%d %s\n",opt, pch3);

		if(strcmp(pch3, ipecka) == 0)
		{
			++opt;
			if (opt == atoi(configstruct.packet_num))
			{
				gettimeofday(&tv2, NULL);

				float vysledok = (float)((tv2.tv_usec - tv1.tv_usec) / 1000000 + (tv2.tv_sec - tv1.tv_sec));
				printf("%f < %f\n", vysledok, 1.5f);

				if(vysledok < atof(configstruct.flood_interval))
				{

					ParseFloodPacket(data,"OPTIONS", ipecka, ipecka_d, source_port, destination_port);
					opt = 0;
				}
				else
				{
					opt = 0;
				}
			}
		}
		else
		{
			opt = 0;
		}

	}

}

/* funkcia pre WhoIS spracovanie jSON stringu */
void *curling(char *ip)
{
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if(curl)
	{
		struct string m;
		init_string(&m);

		char * adresa = (char *) malloc(100);
		strcpy(adresa, "http://rest.db.ripe.net/search.json?query-string=");
		strcat(adresa, ip);
		strcat(adresa, "&flags=no-filtering");

		printf("%s\n", adresa);

		curl_easy_setopt(curl, CURLOPT_URL, adresa);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
		res = curl_easy_perform(curl);

	 	cJSON *root = cJSON_Parse(m.ptr);
		int i;
	        int j;
      		int x;

		char * buff = (char *) malloc(512);
		strcpy(buff, ip);

		for (i = 0; i < cJSON_GetArraySize(root); i++)
		{
			cJSON *subitem = cJSON_GetArrayItem(root, i);
			char *json_string = cJSON_Print(subitem);

			if(i == 2)
			{
				cJSON* item = cJSON_GetArrayItem(subitem, 0);
				cJSON* item2 = cJSON_GetArrayItem(item, 1);
				cJSON* item3 = cJSON_GetArrayItem(item2, 4);
				cJSON* item4 = cJSON_GetArrayItem(item3, 0);

				printf("%d\n",cJSON_GetArraySize(item4));

				for (j = 0 ; j < cJSON_GetArraySize(item4) ; j++)
				{

					cJSON * subitem = cJSON_GetArrayItem(item4, j);
                                        char *name1 = cJSON_GetObjectItem(subitem, "name") -> valuestring;
                                        if (strcmp(name1, "address") == 0)
                                        {
                                                        char *index1 = cJSON_GetObjectItem(subitem, "value") -> valuestring;
                                                        strcat(buff, ";");
                                                        strcat(buff, index1);

                                        }


				}
				break;
 			}
		}

		free(adresa);
		free(m.ptr);

		cJSON_Delete(root);

		curl_easy_cleanup(curl);
		return(buff);

	}
}


/* funkcie pre login honeypotu asterisk (nahodny vyber username)*/
void *login()
{

	struct config configstruct;
        configstruct = get_config(FILENAME);

	char *random;

	int r = 0;

	char *p = strtok (configstruct.destination_extensions, ",");
	char *array[5];

	while (p != NULL)
	{
		array[r++] = p;
		p = strtok (NULL, ",");
	}

	srand(time(NULL));
	random = array[rand() % ((int)(sizeof(array)/sizeof(array[0])))];
	printf("NAHODNE CISLO: %s\n",random);
	return (void*)random;
}


/* hladaj v blackliste, momentalne nevyuzivane */
int SearchInBlackList(char *str)
{
	FILE *fp;
	int line_num = 1;
	int find_result = 0;
	char* temp = malloc(512 * sizeof(char));

	if((fp = fopen("/home/cesnet/blacklist.txt", "r")) == NULL)
	{
		//return(-1);
	}

	while(fgets(temp, 512, fp) != NULL)
	{
		if((strstr(temp, str)) != NULL)
		{
			//printf("A match found on line: %d\n", line_num);
			//printf("\n%s\n", temp);
			find_result++;
			return 1;
		}

		line_num++;
	}

	if(find_result == 0)
	{
		//printf("\nSorry, couldn't find a match.\n");
		return -1;
	}


	if(fp)
	{
		fclose(fp);
	}
	free(temp);
   	//return(0);
}


/* funkcia serveru, server bude zasielat info o utokoch klientom alebo v pripade prijati info o utoku na klienta rozosle vsetkym info o utoku */ 
void *Server()
{

	int opt = TRUE;
	char ch;
	int result;
	int master_socket , activity, i , valread , sd;
	int max_sd;
	char buffer[1025];
	char buff[BUFSIZE];
	int fd, nfd,n;
	int lens;
	char posli[BUFSIZE];
	char recv[BUFSIZE];
	char buff2[128], buff3[128];

	struct sockaddr_in address;
	struct timeval tv;

	fd_set readfds;

	struct config configstruct;
	configstruct = get_config(FILENAME);

	/* zdielana pamet */
	char * myfifo = "/tmp/pipe";
	fd = open(myfifo, O_RDWR);



	if( ( master_socket = socket( AF_INET, SOCK_STREAM, 0 ) ) == -1 )
	{
		zprava("ERROR","Socket error",errno);
		exit( EXIT_FAILURE );
	}

	bzero(&address, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(atoi(configstruct.server_port));
        inet_pton(AF_INET, configstruct.sipdomain, &address.sin_addr);



	/* vytvor master socket */
	if( connect( master_socket, ( struct sockaddr *  )&address, sizeof( address ) ) < 0 )
	 {
		 zprava("ERROR", "master socket failed", errno);
		 perror("socket failed");
		 exit(EXIT_FAILURE);
	 }


	while(TRUE)
	{
		FD_ZERO(&readfds);
		FD_SET(master_socket, &readfds);
		max_sd = master_socket;
		FD_SET(fd, &readfds);


		activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);
		if ((activity < 0) && (errno!=EINTR))
		{
				zprava("ERROR", "select error", errno);
				printf("select error");
		}

		if (FD_ISSET(fd, &readfds))
		{
			memset(buff, 0, sizeof(buff));
			read(fd, buff, BUFSIZE);
			printf("SERUUUUUUUUUUUUUUUUUUS :::::: %s \n", buff);
			send(master_socket , buff , strlen(buff) , 0);
		}
		if( FD_ISSET(master_socket, &readfds))
		{
			memset(recv, 0, sizeof(recv));
			n = read(master_socket, recv, BUFSIZE);

			if( n == 0 )
			{
				zprava("INFO","Receive ok..", 1);
				break;
			}
			else if( n == -1 )
			{
				zprava("INFO","Recv error!", errno);
				break;
			}
			else
			{
				lens = strlen(recv);
				recv[lens-1] = '\0';
				zprava("ATTACK", recv, 3);
				//write( STDOUT_FILENO, recv, BUFSIZE );
			}

		}

	}

return 0;
}

/* funkcia pre zdielanu pamet, komunikacia medzi jednotlivymi vlaknami */
void *SendToHoneypot(char *flood)
{

	int fd;
	char * myfifo = "/tmp/pipe";

	fd = open(myfifo, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
	{
		printf("open %d \n", errno);
	}

	if(write(fd, flood, strlen(flood)+1) < 0)
	{
		zprava("ERROR","cant write to pipe", errno);
		printf("error %d\n", errno);
	}
	else
	{
		printf("odoslano \n");
	}
	close(fd);

}


/* parsovanie flood paketu */
void *ParseFloodPacket(const u_char *data, char *flood, char *ip, char *ip_dest, char *sport, char *dport)
{

//	printf("IPECKA :  %s\n", data);
	char *buff = (char *)malloc(1024);
	char *target = malloc(60 * sizeof(char));
	char **arr, **arr2 = NULL;
	char *destinationip = malloc(60 * sizeof(char));
	char *sourceip = malloc(60 * sizeof(char));
	char *callid = malloc(60 * sizeof(char));
	char *pole= malloc(24 * sizeof(char));
	char buff1[1024];
        char *check = malloc(24 * sizeof(char));
	int z = 0;
	int o = 0;

	memset(buff,0,100);

	printf("IPECKA  FERKA UTOCNIKA  :%s\n", ip);
        strncpy(pole,ip ,17);strcat(pole, "\0");

        check = strtok(ip, ".");
        if ((strcmp(check,"10") == 0)||(strcmp(check,"192")==0)||(strcmp(check,"172")==0))
        {
        	snprintf(buff1, 90, "%s FLOOD detected !!! %s COUNTRY: %s ",flood, pole, "PRIVATE IP ADDRESS");

        }
        else
        {
	        snprintf(buff1, 1020, "%s FLOOD detected !!! %s COUNTRY: %s ",flood,  pole, curling(pole));
        }


        zprava("ATTACK",buff1, 3);



	//strncpy(sourceip, strstr(data,"From: "), 50);
	//char *s_ip = GetDataFromPacket(sourceip);

	strncpy(callid, strstr(data,"Call-ID: "), 50);
        char *c_id = strtok(callid, ":\r");
	c_id = strtok(NULL,": \r");


	snprintf(buff, 1020, "%s FLOOOD;%s;%s;%s;%s;%s\n", flood, pole, ip_dest, sport, dport, curling(pole) );
	printf("%s\n", buff);


	/* posli dalsim honeypotom */
	SendToHoneypot(buff);


	char *s = GetUris(destinationip);
	char *p = GetUris(sourceip);

	//free(sourceip);
	//free(destinationip);

	/* vytvor mentat string o floodingu */
	//mentat_creator(flood, pole, ip_dest, sport, dport, c_id, s, p);
}


/* spracovanie a ziskanie dat */
void *GetDataFromPacket(char *data2)
{
//	printf("Prichod  %s \n", data2);

	const char *PATTERN1 = "<";
	const char *PATTERN2 = ">";

	char *target = NULL;
	char *start, *end;
	char *buff3 = (char *)malloc(100);

	if (start = strstr(data2,PATTERN1))
	{
		start += strlen(PATTERN1);
		if (end = strstr(start, PATTERN2))
		{
			target = (char*)malloc(end - start + 1);
			memcpy(target, start, end - start);
			target[end - start] = '\0';
      	}
   	}
	memset(buff3, 0, 100);

 	if (target)
	{
		char *ch2 = strtok(target, "@:");

		while (ch2 != NULL)
		{
			strcat(buff3, ch2);
			strcat(buff3, ";");
			ch2 = strtok(NULL, "@:");
		}
	}

	free(target);

	/* vrat vysledny string */
	return (void*)buff3;
}


/* funkcie pre vytvorenie MENTAT stringu */
void *mentat_creator(char *typ, char* zdrojip, char *cielip, char *zdrojport, char *cielport, char * callids, char* uri_s, char *uri_d )
{

/* VZOR */
/***********************************************************/
/***********************************************************/
/*
{
	"Format": "IDEA0",
	"ID": "2E4A3926-B1B9-41E3-89AE-B6B474EB0A54",
	"DetectTime": "2014-03-22T10:12:31Z",
	"Category": ["Recon.Scanning"],
	"ConnCount": 633,
	"Description": "EPMAPPER exploitation attempt",
	"Ref": ["cve:CVE-2003-0605"],
	"Source": [
	{
		"IP4": ["93.184.216.119"],
		"Proto": ["tcp", "epmap"],
		"Port": [24508]
	}
	],
	"Target": [
	{
		"Proto": ["tcp", "epmap"],
		"Port": [135]
	}
	]
}
*/
/***********************************************************/
/***********************************************************/
	struct ip_address r;

	/* ziskanie aktualneho casu */
	time_t rawtime;
	time ( &rawtime );
	struct tm *timeinfo = localtime (&rawtime);

	char buffer[30];

	strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);

	/* vytvorenie jSON stringu pre MENTAT */
	cJSON *root;
	cJSON *fmt;
	cJSON *fmt2, *fmt3, *fmt4, *fmt5;

	root = cJSON_CreateObject();

	cJSON_AddItemToObject(root, "Format", cJSON_CreateString("IDEA0"));
	cJSON_AddItemToObject(root, "ID", cJSON_CreateString(callids));
	cJSON_AddItemToObject(root, "DetectTime", cJSON_CreateString(buffer));
	cJSON_AddItemToObject(root, "Category", cJSON_CreateString("Availability.DoS"));
	cJSON_AddItemToObject(root, "connCount", cJSON_CreateString("633"));
	cJSON_AddItemToObject(root, "Description", cJSON_CreateString(typ));

	cJSON_AddItemToObject(root, "Ref", fmt5 = cJSON_CreateArray());
	cJSON_AddStringToObject(fmt5, "Ref", uri_s);
	cJSON_AddStringToObject(fmt5, "Ref", uri_d);

	cJSON_AddItemToObject(root, "Source", fmt = cJSON_CreateObject());
	cJSON_AddStringToObject(fmt, "IP4", zdrojip);
	cJSON_AddItemToObject(fmt, "Proto", fmt4 = cJSON_CreateArray());
	cJSON_AddStringToObject(fmt4, "Proto", "udp");
	cJSON_AddStringToObject(fmt4, "Proto", "sip");
	cJSON_AddStringToObject(fmt, "Port", zdrojport);


	cJSON_AddItemToObject(root, "Target", fmt2 = cJSON_CreateObject());
	cJSON_AddStringToObject(fmt2, "IP4", cielip);
	cJSON_AddItemToObject(fmt2, "Proto", fmt3 = cJSON_CreateArray());
	cJSON_AddStringToObject(fmt3, "Proto", "udp");
	cJSON_AddStringToObject(fmt3, "Proto", "sip");
	cJSON_AddStringToObject(fmt2, "Port", cielport);


	/* vytlac vysledny string, chyba este funkcia pre odoslanie do MENTAT siete */
	printf("%s\n", cJSON_Print(root));
	writeMentatLog(cJSON_Print(root));

}

/* funkcie pre najdenie CALLERID v databaze, vyuzivana pri detekcii SPITU */
bool searchForCallerID(sqlite3 *db, char* caller)
{
	sqlite3_stmt *statement;
	const char *query = "SELECT COUNT(*) FROM Suspicious_Table WHERE callerid = ?";
	sqlite3_prepare_v2(db, query, strlen(query), &statement, NULL);
	sqlite3_bind_text(statement, 1, caller, -1, SQLITE_STATIC);
	sqlite3_step(statement);
	int founded = sqlite3_column_int(statement, 0);
	sqlite3_finalize(statement);
	return founded > 0;
}


/* funkcia pre vlozenie zaznamu do databaze, SPIT */
void insertRecordToTable(sqlite3 *db, char *id, unsigned int value)
{
	sqlite3_stmt *statement;

	const char *query = "INSERT INTO Suspicious_Table (callerid, level) VALUES (?, ?)";

	sqlite3_prepare_v2(db, query, strlen(query), &statement, NULL);
	sqlite3_bind_text(statement, 1, id, -1, SQLITE_STATIC);
	sqlite3_bind_int(statement, 2, value);

	int result = sqlite3_step(statement);

	if (result != SQLITE_DONE)
	{
		zprava("ERROR", "sqlite error", errno);
		printf("ERROR: Error!\n");
	}
	else
	{
		printf("OK\n");
	}
	sqlite3_finalize(statement);
}


/* funkce pre vytvorenie hovoru v ramci falosneho VoIP provozu */
void MakeCall(pjsua_acc_id acc_id)
{
	struct config configstruct;
	configstruct = get_config(FILENAME);
	char *buff = malloc(100 * sizeof(char));
	char *buff2 = malloc(100 * sizeof(char));

	snprintf(buff, 90, "sip:%s@%s\0", login(), configstruct.sipdomain);

	srand(time(NULL));

	/* vykonaj hovor v zadanom casovom intervale, definovanom v konfiguracnom subore */
	sleep(rand_range(atoi(configstruct.time_min),atoi(configstruct.time_max)));

	pjsua_set_null_snd_dev();
	snprintf(buff2, 90 , "Making fake call to %s", buff);

	zprava ("INFO", buff2 , 1);
	free(buff2);

	pj_str_t uri = pj_str(buff);
	pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, NULL);
}

int rand_range(int min_n, int max_n)
{
    return rand() % (max_n - min_n + 1) + min_n;
}

void *GetUris(char *data2)
{
//      printf("Prichod  %s \n", data2);

        const char *PATTERN1 = "<";
        const char *PATTERN2 = ">";

        char *target = NULL;
        char *start, *end;
        char *buff3 = (char *)malloc(100);
	 memset(buff3, 0, 100);

        if (start = strstr(data2,PATTERN1))
        {
                start += strlen(PATTERN1);
                if (end = strstr(start, PATTERN2))
                {
                        target = (char*)malloc(end - start + 1);
                        memcpy(target, start, end - start);
                        target[end - start] = '\0';
        }
        }
        memset(buff3, 0, 100);

        return target;
}

void zprava(char *druh, char *msg, int error)
{
	char *buffer = malloc(1024 * sizeof(char));

	time_t rawtime;
        time ( &rawtime );
        struct tm *timeinfo = localtime (&rawtime);

        char buff[30];

        strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", timeinfo);



	if (strcmp(druh, "ERROR") == 0)
	{
		snprintf (buffer, 160 , "%s	%s:	%s error_num: %d\n", buff, druh, msg, error);
		writeLog(buffer);
		free(buffer);
	}

	if(strcmp(druh, "ATTACK") == 0)
	{
		snprintf (buffer, 1020 , "%s	%s:    %s\n", buff ,druh, msg);
		writeLog(buffer);
		free(buffer);
	}

	if(strcmp(druh, "INFO") == 0)
	{
		snprintf (buffer, 160 , "%s	%s:    %s \n" , buff, druh, msg);
		writeLog(buffer);
		free(buffer);
	}

}

int CallNumTo()
{
        struct config configstruct;
        configstruct = get_config(FILENAME);

        int  random;
	char *array[2];

        array[0] = strtok (configstruct.destination_extensions, "-");
        array[1] = strtok (NULL, "-");

        srand(time(NULL));
        random = rand() % (atoi(array[1]) + 1 - atoi(array[0])) + atoi(array[0]);

        return random;
}

