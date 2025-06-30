# libuvhttp

## 概要

`libuvhttp`は、`libuv`と`llhttp`をベースにした、シンプルで高性能なHTTPサーバーライブラリです。TLS（OpenSSLを使用）もサポートしており、セキュアな通信が可能です。

このライブラリは、ヘッダーファイルと実装ファイルを1つにまとめた、いわゆる "Single-Header" スタイルで提供されます。

## 依存関係

*   **libuv**: 非同期I/Oライブラリ
*   **OpenSSL**: TLSサポート用
*   **llhttp**: HTTPパーサー

## ビルド方法

`libuvhttp` を利用するプロジェクトをビルドするには、libuv と OpenSSL のライブラリをリンクする必要があります。

以下に `gcc` を使用したビルドコマンドの例を示します。

```bash
gcc your_app.c -I/path/to/libuv/include -I/path/to/openssl/include -L/path/to/libuv/lib -L/path/to/openssl/lib -luv -lssl -lcrypto -o your_app
```

## APIの基本的な使い方

### 1. サーバーの設定と作成

`http_server_config_t` 構造体を初期化し、`http_server_create` 関数でサーバーインスタンスを作成します。

```c
#include "uvhttp.h"
#include <stdio.h>
#include <string.h>

// リクエストハンドラ
void my_handler(http_request_t* req) {
    // レスポンスを作成
    http_response_t* res = http_response_init();
    http_response_status(res, 200);
    http_response_header(res, "Content-Type", "text/plain");
    const char* body = "Hello, World!";
    http_response_body(res, body, strlen(body));

    // レスポンスを送信
    http_respond(req, res);

    // レスポンスオブジェクトを破棄
    http_response_destroy(res);
}

int main() {
    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = 8080,
        .handler = my_handler,
        .tls_enabled = 0 // TLSを無効にする場合
    };

    http_server_t* server = http_server_create(&config);
    if (!server) {
        fprintf(stderr, "Failed to create server.\n");
        return 1;
    }
```

### 2. サーバーの待受開始

`http_server_listen` 関数で、設定したホストとポートでリクエストの待受を開始します。

```c
    printf("Server listening on http://%s:%d\n", config.host, config.port);
    http_server_listen(server);
```

### 3. サーバーの破棄

アプリケーションの終了時に `http_server_destroy` でサーバーリソースを解放します。

```c
    http_server_destroy(server);
    return 0;
}
```

### 4. リクエスト情報の取得

リクエストハンドラ内では、`http_request_*`系の関数を使って、メソッド、URL、ヘッダー、ボディなどの情報を取得できます。

```c
void my_handler(http_request_t* req) {
    printf("Method: %s\n", http_request_method(req));
    printf("Target: %s\n", http_request_target(req));

    const char* user_agent = http_request_header(req, "User-Agent");
    if (user_agent) {
        printf("User-Agent: %s\n", user_agent);
    }

    // ...
}
```

### 5. TLSの有効化

TLSを有効にするには、`http_server_config_t` で `tls_enabled` を `1` に設定し、証明書ファイルと秘密鍵ファイルのパスを指定します。

```c
    http_server_config_t config = {
        .host = "0.0.0.0",
        .port = 8443,
        .handler = my_handler,
        .tls_enabled = 1,
        .cert_file = "path/to/your/cert.pem",
        .key_file = "path/to/your/key.pem"
    };
```

## llhttp由来のコードについて

`api.c`, `http.c`, `llhttp.c`, `llhttp.h` は、HTTPパーサーライブラリである `llhttp` から取り込まれたコードです。`libuvhttp` は内部で `llhttp` を利用してHTTPリクエストの解析を行っています。

## コミットメッセージの規約

本プロジェクトでは、コミットメッセージの規約として [Conventional Commits](https://www.conventionalcommits.org/) を採用します。

コミットメッセージは以下のフォーマットに従ってください。

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Type

*   **feat**: 新機能の追加
*   **fix**: バグ修正
*   **docs**: ドキュメントのみの変更
*   **style**: コードの意味に影響を与えない変更（空白、フォーマット、セミコロンの欠落など）
*   **refactor**: バグ修正でも機能追加でもないコードの変更
*   **perf**: パフォーマンスを向上さ���るコードの変更
*   **test**: 不足しているテストの追加や既存のテストの修正
*   **build**: ビルドシステムや外部依存関係に影響を与える変更（gulp、broccoli、npmなど）
*   **ci**: CI設定ファイルやスクリプトの変更（Travis, Circle, BrowserStack, SauceLabsなど）
*   **chore**: 上記のいずれにも当てはまらないその他の変更
*   **revert**: 以前のコミットを元に戻す場合
