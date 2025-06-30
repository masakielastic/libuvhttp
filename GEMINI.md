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
`max_body_size` を設定することで、リクエストボディの最大サイズを制限できます（0は無制限）。

```c
#include "uvhttp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
        .tls_enabled = 0, // TLSを無効にする場合
        .max_body_size = 8 * 1024 * 1024 // 8MB
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

### 4. リクエスト情報の取得 (ゼロコピーAPI)

リクエストハンドラ内では、`http_request_*`系の関数を使って、メソッド、URL、ヘッダーなどの情報を**ゼロコピー**で取得できます。これらの関数は `uvhttp_string_slice_t` という構造体を返します。これは、受信バッファ内のデータを直接指すポインタ (`at`) とその長さ (`length`) を保持します。

**重要:** スライスが指すデータは、リクエストハンドラのスコープ内でのみ有効です。

```c
void my_handler(http_request_t* req) {
    printf("Request received: ");

    // メソッドを取得して表示
    uvhttp_string_slice_t method = http_request_method(req);
    uvhttp_slice_print(&method);

    printf(" ");

    // ターゲット(URL)を取得して表示
    uvhttp_string_slice_t target = http_request_target(req);
    uvhttp_slice_print(&target);

    printf("\n");

    // "User-Agent"ヘッダーを取得
    uvhttp_string_slice_t user_agent = http_request_header(req, "User-Agent");
    if (user_agent.at != NULL) {
        printf("User-Agent: ");
        uvhttp_slice_print(&user_agent);
        printf("\n");
    }

    // スライスをC文字列と比較
    if (uvhttp_slice_cmp(&method, "POST") == 0) {
        // POSTリクエストの処理...
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
        .key_file = "path/to/your/key.pem",
        .max_body_size = 8 * 1024 * 1024
    };
```

## llhttp由来のコードについて

`api.c`, `http.c`, `llhttp.c`, `llhttp.h` は、HTTPパーサーライブラリである `llhttp` から取り込まれたコードです。`libuvhttp` は内部で `llhttp` を利用してHTTPリクエストの解析を行っています。

```

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
