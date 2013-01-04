keepass-emacs
http://code.google.com/p/keepass-emacs/

概要:
emacsからKeePassを利用するためのインターフェースです。
HMACを利用すると平文のパスワードはELispからアクセスできないので、
安全に管理できます。

機能:
+ GnusのHMACベースの認証方式(rfc2104-hash)に対応しています。
+ KeePass本体と同様にSecureデスクトップをサポートしています。
  KeePassデータベースのパスワードをキーロガーなどのスパイウェ
  アから保護します。

必要な物:
+ GNU Emacs(Win64版) (ダイナミックライブラリサポート)
+ KeePass 2.20.1 (コンパイル済みdllはバージョンに非常に敏感です)
+ https://github.com/langmartin/site-lisp/blob/master/srfi-2.el
+ GMAILを使用する場合はパイプ対応版OpenSSLを用意してください。
  https://gist.github.com/4443189

インストール:
0 KeePassをインストールします。KeePass.exeを
  c:/Program Files/GNU/emac23/binにコピーします。
1 keepass.dllをc:/Program Files/GNU/emac23/binにコピーします。
2 keepass.el,keepass.elcをload-pathの通ったディレクトリにコピーします
  https://github.com/langmartin/site-lisp/blob/master/srfi-2.elを
  load-pathの通ったディレクトリにコピーします
3 初期化ファイル(.emacs)に以下を記述します
  (add-to-list 'after-load-alist
               '(rfc2104 (require 'keepass)))
  (add-to-list 'after-load-alist
	     '(imap
	       (require 'keepass)))

利用法:
Gnusで以下の形式の文字列をパスワードとしてあたえます。
.authinfoなどに記述する事ができます。
keepass:keepassデータベースファイル名?グループ0/グループ1/エントリ属性名1=エントリ属性値1&エントリ属性名2=エントリ属性値2
記述例:
~/.authinfo
machine localhost login username password keepass:~/Database.kdbx?Database/eMail/UserName=username@localhost port imap
注) 1行/1ホストで記述
カスタムフィールドに格納したパスワードを指定できます。
GMAILなど、CRAM-MD5認証に対応していない場合に有用です。
machine localhost login username password keepass:~/Database.kdbx?Database/eMail/UserName=username@localhost#field-name port 993

オブジェクト:
keepass-groupオブジェクトとkeepass-entryオブジェクトを実装しています。
keepass-groupは配下にあるkeepass-groupまたはkeepass-entryを検索するために利用します。
keepass-entryはフィールド値の取得、HMACの計算を行います。

関数:
keepass-open
(keepass-open FILENAME AUTHPARAM &optional VISIBLE-FIELDS)
FILENAMEをオープンします。
AUTHPARAMはデータベースの認証情報です。nil, t, 文字列, リストを与えます。
+ nilまたはtの場合はKeePassのファイルオープンダイアログでデータベースを開きます。
  tの場合はKeePass本体と同様にSecureデスクトップを利用します。
+ 文字列が与えられた場合はデータベースパスワードです。
+ リストの場合は(password keyfile . userauth)でなければいけません
  password,keyfileは文字列またはnil, userauthはboolとして使われます。
VISIBLE-FIELDSはELispからアクセス可能なフィールド名のリストです。
nilの場合はデフォルト("Title" "UserName" "URL" "Notes")が使われます。
戻り値はKeePassデータベースのルートグループオブジェクトです。

keepass-group-entry
(keepass-group-entry GROUP ENTRY-SPEC)
group以下にあるENTRY-SPECのオブジェクトを検索します。
ENTRY-SPECはUUID形式(KeePassエントリのProtertyタブのUUID)の文字列または
((エントリフィールドリスト) グループ名-0 グループ名-1 グループ名-2)で与えます。
関数keepass-parse-entry-specを利用するとエントリを表す文字列から生成する事が出来ます。

keepass-parse-entry-spec:
(keepass-parse-entry-spec STR)
以下の形式の文字列からentry-specを生成します。
group-0/group-1/group-2/field1=value1&field2=value2
=> (((field1 . value1) (field2 . value2)) group-0 group-1 group-2)

keepass-entry-hmac:
(keepass-entry-hmac ENTRY MECHANISM DATA)
ENTRYのパスワードフィールド値をキーとしてHMACを計算します。
利用可能なMECHANISMはmd5, ripemd160, sha1, sha256, sha384, sha512です。
HMACの計算はC++/CLIモジュール内で行われ、パスワードフィールドをELispから
アクセスしません。(keepass-openのデフォルト)
