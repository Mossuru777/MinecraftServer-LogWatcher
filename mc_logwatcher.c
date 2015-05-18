#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <netdb.h>
#include <curl/curl.h>
#include <ctype.h>
#include <unistd.h>

//inotifyイベント受信用構造体・バッファ長定義
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

//プロトタイプ
void sigproc(int);
void sendMessage(int *, struct sockaddr_in *,char *, const unsigned char);
void sendtoKayac(char *);
void urlEncode(char *, const char *);

//グローバル変数
static unsigned char isLoop = 1;       //ループ状態判定
static char *kayac_post_url = NULL;    //im.kayac.com POSTURL
static char *kayac_urlscheme = NULL;   //im.kayac.com URLEncoded URLScheme
static CURL *curl = NULL;              //libcurl

int main(int argc, char *argv[]) {
	//引数チェック
	if(argc < 4 || argc > 6){
		printf("Usage: ./%s LogPath UDPMC_GroupAddr UDPMC_Port [Kayac_UserName] [Kayac_URLScheme]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* im.kayac.com 設定 */
		if(argc >= 5) {
			//im.kayac.comは宛先ユーザーをURLで指定するため、ユーザー名をPOST URLにセット
			kayac_post_url = (char *)malloc(29 + strlen(argv[4]) + 1);
			if(kayac_post_url == NULL) {
				printf("メモリを確保できません");
				exit(EXIT_FAILURE);
			}
			sprintf(kayac_post_url, "http://im.kayac.com/api/post/%s", argv[4]);
		}

		if(argc == 6) {
			//iPhoneで通知を開く際のURLSchemeを引数から受け取りURLエンコード
			kayac_urlscheme = (char *)malloc( (strlen(argv[5]) * 4) + 1); //UTF-8で1文字あたり最大4バイトなので
			if(kayac_urlscheme == NULL) {
				printf("メモリを確保できません");
				exit(EXIT_FAILURE);
			}
			urlEncode(kayac_urlscheme, (const char *)argv[5]);
		}

	//シグナル受け取り時の処理を設定
	signal(SIGHUP, sigproc);
	signal(SIGINT, sigproc);
	signal(SIGQUIT, sigproc);
	signal(SIGABRT, sigproc);
	signal(SIGTERM, sigproc);

	/* メッセージを作成する際の一時変数 */
		//送信メッセージ
		char msg[4096];

		//行読み込みバッファ
		char line[1024];

		//ログ(イン|アウト)時の接続元IPアドレスのドット付き10進表記
		char ip_buf[15];
		
		//ログ(イン|アウト)時の接続元IPアドレスのinetアドレス構造体
		struct in_addr conv_addr;
		
		//inetアドレスからホスト名を解決をしたあとに格納するホスト構造体
		struct hostent *conv_host;

		//初期化
		memset(msg, '\0', sizeof(msg));
		memset(line, '\0', sizeof(line));
		memset(ip_buf, '\0', sizeof(ip_buf));

	/* UDPマルチキャストソケットの準備 */
		//正規表現のマッチ設定
		size_t     regex_match_count = 4; //最大マッチ数
		regmatch_t regex_match[regex_match_count]; //最大マッチ数の分、マッチした文字列を格納する配列を用意


		//UDPソケット
		int sock = socket(AF_INET, SOCK_DGRAM, 0); 

		//宛先inetアドレス構造体
		struct sockaddr_in addr; 
		addr.sin_family = AF_INET;
		addr.sin_port = htons(atoi((const char *)argv[3]));
		addr.sin_addr.s_addr = inet_addr((const char *)argv[2]);

		//発信元インターフェイス
		in_addr_t localif_ipaddr = inet_addr("0.0.0.0");

		//ソケットにマルチキャストとして、宛先・発信元を設定
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localif_ipaddr, sizeof(localif_ipaddr)) != 0) {
			perror("setsockopt(UDPMultiCast)");
			exit(EXIT_FAILURE);
		}

	/* ログメッセージ正規表現のコンパイル */
		//ログメッセージのコンパイル済み正規表現
		regex_t login_regex;    //ログイン時
		regex_t logout_regex;   //ログアウト時
		regex_t startup_regex;  //サーバー起動時
		regex_t shutdown_regex; //サーバー停止時

		//ログイン時
		if(regcomp(&login_regex, "(.*) \\[INFO\\] (.*) ?\\[/([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}):[0-9]{1,5}\\] logged in.*", REG_EXTENDED) != 0 ){
			perror("regcomp");
			exit(EXIT_FAILURE);
		}

		//ログアウト時
		if(regcomp(&logout_regex, "(.*) \\[INFO\\] (.*) ?lost connection: .*", REG_EXTENDED) != 0 ){
			perror("regcomp");
			exit(EXIT_FAILURE);
		}

		//サーバー起動時
		if(regcomp(&startup_regex, "(.*) \\[INFO\\] Done \\(.*s\\)!.*", REG_EXTENDED) != 0 ){
			perror("regcomp");
			exit(EXIT_FAILURE);
		}
	
		//サーバー停止時
		if(regcomp(&shutdown_regex, "(.*) \\[INFO\\] Stopping server", REG_EXTENDED) != 0 ){
			perror("regcomp");
			exit(EXIT_FAILURE);
		}

	/* inotify設定 */
		//inotifyディスクリプタ及びバッファ
		int fd, wd;
		char buffer[EVENT_BUF_LEN];
		
		//inotifyインスタンス初期化
		fd = inotify_init();
		if ( fd < 0 ) {
			perror("inotify_init");
		}

		//ログファイルオープン
		FILE *log = fopen(argv[1], "r");
		if( log == NULL ) {
			perror("log file");
			exit(EXIT_FAILURE);
		}
		
		//ログの最終行までポインタを送る
		fseek(log, 0, SEEK_END);
		
		//inotifyインスタンスにログファイルのモニタリングを追加
		wd = inotify_add_watch( fd, argv[1], IN_MODIFY );


	//初期化メッセージ送信
	strcat(msg, "Minecraftログファイルの監視を開始しました。");
	sendMessage((int *)&sock, (struct sockaddr_in *)&addr, msg, 0);

	/* メインループ */
	while(isLoop){
		//バッファの初期化
		memset(msg, '\0', sizeof(msg));
		memset(line, '\0', sizeof(line));
		
		//ここはファイル変更時までブロックされる
		read( fd, buffer, EVENT_BUF_LEN );
		
		//ファイル変更行読み取り
		while( fgets ( line, sizeof(line), log ) != NULL){
			if( regexec(&login_regex, line, regex_match_count, regex_match, 0) == 0 ){
				//日付と時刻
				strncpy((char *)&msg[strlen(msg)], (const char *)&line[regex_match[1].rm_so], (regex_match[1].rm_eo - regex_match[1].rm_so));
				strcat(msg, "\n");

				//ユーザー名
				strncpy((char *)&msg[strlen(msg)], (const char *)&line[regex_match[2].rm_so], (regex_match[2].rm_eo - regex_match[2].rm_so));
				
				/* 接続元ホスト */
					//ドット付き10進表記のIPアドレスの部分だけ抜き出し
					strcat(msg, " (");
					strncpy((char *)(&ip_buf), (const char *)&line[regex_match[3].rm_so], (regex_match[3].rm_eo - regex_match[3].rm_so));
					
					//ホスト名解決
					conv_addr.s_addr = inet_addr(ip_buf); //inetアドレス構造体のアドレス部に10進表記の接続元IPアドレスを渡す
					conv_host = gethostbyaddr((const char *)&conv_addr.s_addr, sizeof(conv_addr.s_addr), AF_INET ); //解決してみる
					if ( conv_host != NULL ) {
						//成功したらホスト名を格納
						strcpy(&msg[strlen(msg)], (const char *)conv_host->h_name); 
					} else {
						//失敗したらIPアドレスをそのまま格納
						herror("gethostbyaddr");
						strncpy((char *)&msg[strlen(msg)], (const char *)&line[regex_match[3].rm_so], (regex_match[3].rm_eo - regex_match[3].rm_so));
					}
					strcat(msg, ")\nログインしています。");

				//メッセージ送信
				sendMessage((int *)&sock, (struct sockaddr_in *)&addr, msg, 1);
				
				//接続元IPアドレス10進表記 char配列の初期化
				memset(ip_buf, '\0', sizeof(ip_buf));
			} else if( regexec(&logout_regex, (const char *)line, regex_match_count, regex_match, 0) == 0 ) {
				//日付と時刻
				strncpy((char *)&msg[strlen(msg)], (const char *)&line[regex_match[1].rm_so], (regex_match[1].rm_eo - regex_match[1].rm_so));
				strcat(msg, "\n");

				//ユーザー名
				strncpy((char *)&msg[strlen(msg)], (const char *)&line[regex_match[2].rm_so], (regex_match[2].rm_eo - regex_match[2].rm_so));
				strcat(msg, "  ログアウトしました。");

				//メッセージ送信
				sendMessage((int *)&sock, (struct sockaddr_in *)&addr, msg, 1);
			} else if( regexec(&startup_regex, (const char *)line, regex_match_count, regex_match, 0) == 0 ) {
				//メッセージ送信
				strcat(msg, "Minecraftサーバー 起動しました。");
				sendMessage((int *)&sock, (struct sockaddr_in *)&addr, msg, 1);
			} else if( regexec(&shutdown_regex, (const char *)line, regex_match_count, regex_match, 0) == 0 ) {
				//メッセージ送信
				strcat(msg, "Minecraftサーバー 停止しました。");
				sendMessage((int *)&sock, (struct sockaddr_in *)&addr, msg, 1);
			}
		}
	}

	//終了メッセージ送信
	strcat(msg, "Minecraftログファイルの監視を停止しています。");
	sendMessage((int *)&sock, (struct sockaddr_in *)&addr, msg, 0);

	//inotifyモニタリストから削除
	inotify_rm_watch( fd, wd );

	//inotifyインスタンスを閉じる
	close( fd );

	//ログファイルハンドルを閉じる
	fclose( log );

	//UDPマルチキャストソケットを閉じる
	close( sock );

	//コンパイル済み正規表現の解放
	regfree((regex_t *)&startup_regex);
	regfree((regex_t *)&shutdown_regex);
	regfree((regex_t *)&login_regex);
	regfree((regex_t *)&logout_regex);
	
	//mallocで確保した領域の開放
	free(kayac_post_url);
	free(kayac_urlscheme);

	return 0;
}

//シグナルを処理
void sigproc(int sig){
	switch(sig) {
		case SIGINT :
		case SIGQUIT :
		case SIGABRT :
		case SIGTERM :
			isLoop = 0; //ループを外すことで正常終了させる
			break;
		case SIGKILL : //異常終了時
			exit(EXIT_FAILURE);
		default : //それ以外のシグナルは無視
			break;
	}
}

//UDPマルチキャストでメッセージを送信
//フラッグが立っている場合、im.kayac.comにも送信
void sendMessage(int *sock, struct sockaddr_in *addr, char *msg, const unsigned char kayacFlag){
	//UDPマルチキャストで送信
	if( sendto(*sock, msg, strlen(msg), 0, (const struct sockaddr *)addr, (socklen_t)sizeof(*addr)) == -1){
		perror("sendto");
	}
	
	//im.kayac.comへ送信flagが立っていたら送信
	if(kayacFlag){
		sendtoKayac(msg);
	}
}

//im.kayac.comにメッセージを送信
void sendtoKayac(char *msg){
	if(kayac_post_url != NULL){
		//CURL初期化
		curl_global_init(CURL_GLOBAL_ALL);
		curl = curl_easy_init();
		
		//CURLが使用可能であれば
		if(curl){
			//メッセージのURLエンコード
			char *urlEncodedMsg = (char *)malloc( (strlen(msg) * 4) + 1); //UTF-8で1文字あたり最大4バイトなので
			if(urlEncodedMsg == NULL){
				printf("メモリを確保できません");
				exit(EXIT_FAILURE);
			}
			urlEncode(urlEncodedMsg, (const char *)msg);

			//POSTデータ作成
			char *postdata;
			if(kayac_urlscheme != NULL){
				//17 = strlen("message=") + strlen("&") + strlen("handler=");
				postdata = malloc(17 + strlen(urlEncodedMsg) + strlen(kayac_urlscheme) + 1);
				sprintf(postdata, "message=%s&handler=%s", urlEncodedMsg, kayac_urlscheme);
			} else {
				//8 = strlen("message=")
				postdata = malloc(8 + strlen(urlEncodedMsg) + 1);
				sprintf(postdata, "message=%s", urlEncodedMsg);
			}
			free(urlEncodedMsg);

			//CURLで送信
			curl_easy_setopt(curl, CURLOPT_URL, kayac_post_url);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
			curl_easy_setopt(curl, CURLOPT_POST, 1);
			curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
			curl_easy_perform(curl);

			//POSTデータ mallocした領域の解放
			free(postdata);

			//CURL解放
			curl_easy_cleanup(curl);
			curl_global_cleanup();
		}
	}
}

void urlEncode( char *urlEncoded, const char *urlSrc ){
	const char *tmp_urlSrc = urlSrc;
	
	//文字がある間ループ
	while( *tmp_urlSrc ){
		if ( isalnum((int)*tmp_urlSrc) || (*tmp_urlSrc=='-') || (*tmp_urlSrc=='.') || (*tmp_urlSrc=='_') || (*tmp_urlSrc=='~') ){
			//英数字であったり、RFCに規定されているURLエンコードの
			//除外文字である場合はそのままコピってポインタを進める
			*(urlEncoded++) = *(tmp_urlSrc++);
		} else {
			sprintf( (char*)urlEncoded, "%%%02X", (unsigned char)*tmp_urlSrc );
			urlEncoded += 3; //3文字分進めた(%FF)ので、ポインタもその分進める
			tmp_urlSrc++; //こちらは1バイト単位でポインタを進める
		}
	}
	*urlEncoded = '\0'; //最後にnull文字を付加
}

