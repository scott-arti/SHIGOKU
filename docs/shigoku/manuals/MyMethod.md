---
task_id: SGK-2026-0010
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

## 流れ
1. レポートされた脆弱性を読んでどんな脆弱性がDupeになるかを知っておく。
	1. ソースコードとすでに開示済みのレポートはリソースになる。例えば、db.txtを見つけたという開示レポートがあった場合、すでに非公開だが、WAYBACK, archive ORGを見てみる。
	2. aiで過去レポからどんなサイトかイメージを持つ。
2. Recon開始
	1. bbotやSubrinder、subdominizer, subdominator, amass、Dorksでサブドメインを収集
	2. urlscan.io でパッシブスキャン。IPアドレスや未発見のAPIエンドポイントやパラメータ。[ガイド](https://systemweakness.com/secret-dork-hunting-methodology-part1-6f06b5c47931
	3. Google Dorksでサブドメインを探す。
			1. `xnldorker -l target.com -v -sb`
	4. Shodan・Censys・fofaでドメインとIPアドレスを探す。
		1. ターゲット.devを探す
		2. Censysのクエリ：`(services.tls.certificates.leaf_data.names: anywebsite.dev) and not "login" and not "password"` [引用元](https://osintteam.blog/the-500-vulnerability-how-censys-search-led-me-to-a-quick-bug-bounty-afabeec7a176)
		3. dnsxでPTRレコードからIPアドレスのリストを探す。
	5. IPアドレスからサブドメインを探す。
	6. ASNからIPアドレスを探す。
	7. PureDNSでLiveドメインを確認してスコープならリストに追加
	8. Additionalで手動でurlscan.ioやdnsdumpster.comを使う
	9. SecurityTrailsでHistorical Dataを取る
	10. [DNSDumpster - Find & lookup dns records for recon & research](https://dnsdumpster.com)
	11. サブドメインをIPアドレスに変換して、より詳細な分析(共有ホスティング、ASN追跡など)を行います。
3. LiveHostか確認
	1. httpx でtech-detectも行う `httpx -title -status-code -tech-detect -o alive-subs.txt`
		1. サブドメインに[ポートスキャン](obsidian://open?vault=Obsidian&file=1.Bub%2F000_%E9%96%8B%E5%A7%8B%2F%E3%83%9D%E3%83%BC%E3%83%88%E3%82%B9%E3%82%AD%E3%83%A3%E3%83%B3) （naabu + nmap）IPアドレスにしたらやばいのでやめとく。
			1. nmap時に-sVと-sCを行う
			2. 非標準ポートを探す。
			3. Dead SubDomainにも行う。Portが空いている可能性があるため。
			4. テクノロジーがわかったら既知の脆弱性を探す。
		2. これをGoogle Spreadsheetにまとめる。
		3. サブドメインを見てpermutationリストを作ってブルートフォース（alterx）
			1. URLもヒントに作る。基本的にはURLからも作る。ChatGPTを頼る。
	2. IPアドレスを調査する。一時的にDNSサーバーから削除していたり更新されているだけだったり、WAFで隠したりすることがある。逆引き検索する。
			2. サブドメインのブルートフォース
			3. サブドメインのサブドメインへのブルートフォース
		4. 複数の角度でLiveHostを分析
			4. CNAMEレコードでWAFの存在がわかる。WAFなしはチャンス。スクリプトを書く。
			5. Response コードをリストに追加。
			6. これをGoogle Spreadsheetにまとめる。
	3. Dead サブドメインにSubzy,Subjackやnucleiを使ってテイクオーバーをチェック。
	4. CNAMEレコードがAWSなどに注目
	5. Visual Reconを実施して結果を分析
		1. GoWitnessを実行。
			1. デフォルトクレデンシャルとsqli(ブール値とエラーベース)LiveHostで初期ブルートフォース（超重要ディレクトリ）
			2. htmlで見る。ログインページと登録ページを特定する。
	6. Techに基づいたブルートフォース Google Dorks で機密情報を探す。pdfとかも。
	7. IPアドレスをもとにVhostをブルートフォース
	8. csprecon -l liveHosts.txt でさらなるサブドメインを取り出す。
4.  LHF（自動でそのまま脆弱性）
	1. ドメインが多い場合 gau+katanta→qsreplace→freqで高速にXSSを探す。 [50+ XSS: Mass Hunting 🚀. Hey everyone! 👋 | by Abhijeet kumawat | Infosec Matrix | Feb, 2025 | Medium](https://medium.com/infosecmatrix/50-xss-mass-hunting-37e51fce5369)
	2. nucleiで既知の脆弱性を探す
	3. niktoで古い既知の脆弱性を探す
		1. `interlace -tL ./targets.txt -threads 5 -c "nikto --host _target_ > ./_target_-nikto.txt" -v`
	4. subzy, socialhunter
	5. **SQLiできるツールある？** freqはどうやって判断するんだ？
	6. XSS Dalfox。GFつかうかそのままqsreplace使うかは迷い中。
	7. Google Dorks で機密情報を探す。
	8. {URL}/.git/ か {URL}/.git/config を探る
5. Middle Hanging Fruits（少し手動で調べたら報告可能なもの）
	1. gau＆katana の URL リストから
		1. .git, config, ini, admin, .git, .zip, .bak, .log, tar.gz, .sql, .env, pdf などを探す
			1. envはDB_HOST, DB_USERNAME, DB_PASSWORDなどがある
		2. JavaScript ファイルを探す
		3. API エンドポイントを探す
		4. 管理画面・開発環境・デバッグ環境`/admin`, `/login`, `/dev`, `/staging`, `/test`
			1. `http://admin.target.com:8443/FUZZ`のようにファジングをする
		5. 認証が絡むページ (`/admin`, `/login`, `/dashboard`)
		6. パスワードリセット・登録ページ (`/forgot`, `/reset-password`, `/signup`)
		7. 内部っぽいドメインを手動で見る。→ターゲットを絞る・決める。
	2. Google DorksでJuicy Filesを探す。
		8. - Google Dorks (`site:target.com ext:pdf` など)
		    1. `site:target.com intitle:"index of"`
		    2. `site:target.com filetype:log`
		    3. `site:target.com inurl:/phpinfo.php`
		    4. `site:target.com ext:pdf OR ext:doc OR ext:xlsx`
		9. Shodan/Censys
		    1. `ssl:"t**arget.com"`
		    2. `http.html:"admin panel"`
	3. `gowitness` で `-f 403,401,500` を含むページをリストアップ
		1. ツールで401, 403バイパスを試す。メモを残す。Mindmapか。
		2. `nuclei` の `admin-panels` テンプレートを実行 (`nuclei -t admin-panels`)
			1. tips: 結果はHTMLでまとめてみるのが高速。ログインページと登録ページを探す
			2. 403, 401 (アクセス制限系)：IDOR, SSRF
			3. 500(内部エラー）：SQLi, SSTI, XXE などサーバーサイドVisual Reconでエラーページ。URLでhtmlへ反映しているものがあるか。
	4. Google Dorksで探す。Confidential, クレデンシャル、APIキー、pdf、MyPhpAdmin など。もっと調べる。テーマごとにやる。半手動で。Yandexなども。
		1. pdfなどはツールでファイル内を探索
	5. APIをFFUFで探す。反応があれば、見る。Juicyなもののみに絞るか？できる？
	6. 半自動でスクリプト＋Caidoでサイトマップを作成しつつ、XSSの反映を見る。
	7. スコープなら）DNSのMXレコードを調べて DMARCの有無を調べる。
	8. Bash＋Loxsを使ってXSSの自動テストを行う。 [Find XSS Vulnerabilities in Just 2 Minutes | by coffinxp | Dec, 2024 | OSINT Team](https://osintteam.blog/find-xss-vulnerabilities-in-just-2-minutes-d14b63d000b1)
	9. Nucleiの-dastを使ってヘッドレスでXSSのリフレクトを見て、手動で確認
	10. Juicy な サブドメインをgrepして分類して確認。スクリプトで作成
		- **管理画面・開発環境・デバッグ環境**
		    - `admin`, `login`, `dev`, `staging`, `test`
		    - `dev.target.com`, `staging.target.com`, `admin.target.com`
		- **企業が気付きにくいもの**
		    - `beta.target.com`, `legacy.target.com`, `backup.target.com`
		    - `old.target.com`, `demo.target.com`
		    - `api.target.com`（APIのバグは報酬が高い傾向）
	11. Swaggerファイルが公開されていないか。（APIのドキュメントがある）
	12. waybackurlsで探す。
		1. `waybackurls https://google.com |grep --color -E "(1.xls |.tar.gz|.bak|.xml|.xlsx|.json|.rar|.pdf|.sql|.doc|.docx|.pptx|.txt|.zip|.tgz|.7z|.old|.zip|.env)"`
	13. TechがわかるならTechの重要ポートを調べてポートスキャン
	14. Googleでも同じのを探す。
6. ここからターゲットサブドメインを決めてContent Discovery開始、gauでJuicyなディレクトリを探す。
	1. Debug モードで動作しないか？**プロのヒント**: `**?format=json**` または `**?api_version=2**` を使用してください。一部のエンドポイントでは、「デバッグ」モードの制限が高くなります。
	2. LiveHostでJuicyなサブドメインがないか確認
		1. /login, /admin, /Dev
		2. 同時にrobots.txtを調べる
	3. パラメータ系を探す。
		1. パラメータ探し。パラメーター収集。arjun、paramspider。でリスト化。
		2. 自動探索(XSS, OpenRedirect, SSRF)
	4. ディレクトリ探索
		1. Caidoをオンにして各機能を試す。
		2. 自動検出（API、ID、KEY、PASSWORD、ID、ハッシュ値、
		3. APIを探す。
		4. Javascript を探す。
			1. Gospider,Katana
			2. katanaでヘッドレスモードを利用するとレンダリングはしないけど Javascript は展開する。
			3. 除外リストを作ってからFFUFでブルートフォース
				1. プライベートプログラムの場合、[ここの記事](https://kalawy.medium.com/there-is-no-subdomain-with-no-usage-how-understanding-this-rule-led-to-5-criticals-59e815ca6df2)でかいてあるよう
		5. パスブルートフォースで合致するディレクトリがあればブルートフォースを実施。
		6. 詳細分析 （手動。探索は２つ以上のツールを使う）
			1. 過去の脆弱性レポートを参照する。Linkedin, Hackerone
			2. 手動で各ドメインを触っていく
				1. その際.gitの公開がないかを確認してアラートを上げるルールを設定する。
				2. それか、ブラウザエクステンションのDotGitをオンににする。
		7. Javascript ファイルの探索と分析→エンドポイントの追加。APIキーの探索。
			1. JSからドメインを探す。→ 意味があるはずなので手動で調査。
			2. SecretFinderで機密情報を探す。他のツールは？
			3. 同じくDons Js scanner で探す
			4. クロール済みなのでJSファイルを探す。
		8. 怪しいエンドポイントが見つかったら、そのパスはhttpx --path /vx/env など他のサブドメインでも試す。
		9. DOMベースのXSSを探す。スクリプト＋Caido。次点：Katana（動的コンテンツを探す）。
			1. arjunで隠れたパラメータを探す。
			2. まとめてやるならスクリプト＋Caido。
			3. DOMシンクをgrepで探す。
			4. サブドメインまるごとスパイダリングやるならGospider。ただし動的解析はしない。
			5. フィルターがあった場合とか→スプ氏へ
		10. Blind XSSを探す。
		11. APIを探す。Cariddiで自動的にAPIを総合的に探す。Kiterunner
			1. キーを見つけたらstreaakで検証
		12. 手動探索Caido ウォークスルー
			2. ハッキング以前に、超超超つねにInspectorのNetworkを開いて新しいページを開いたら見てWebページが何をしているのか見る。
			3. ルール、プラグインで探索
				1. APIキー
				2. アクセストークン
				3. JWT
			4. CSP、ヘッダーを自動で探す。
			5. Match & Replace でハイライトする。
			6. ロジックバグ
		13. ログインページを探す
			1. 登録、Forgot me, Updateページ
			2. Business Logic
				1. 複数ユーザー
				2. IDOR
				3. Mass Assignment
		14. WAFバイパス
			1. **要調査）WAF調査**
			2. WAFW00F
		15. SSO
			1. SAML
		16. 手動XSS
			2. CSP
			3. XSStrike
			4. Blind XSS
		17. ソースコード
			1. https://publicwww.com
		18. JWT があるか。
		19. ※cookieの属性名は？
		20. パスワードリセット
			1. パスワード変更リンクの再利用
			2. パスワード変更しても元のCookieが無効にならない
			3. Hostヘッダーを改ざんするとリセットリンクが攻撃者のサイト（evil.com)に向く
		21. Cookie管理不備
			1. ログアウトしてもCookieが無効にならない
			2. ログインしてもCookieが変わらない
		22. Registerページ
			1. 開発者サイトで登録の制御が甘い。
			2. otpのレート制限
		23. Cache Poisoning
			1. Hostヘッダーに基づいてキャッシュする場合、リクエストのHostをevil.comにして確認すると悪意あるコンテンツを見せることができる。
		24. SSRF
			2. Hostヘッダーを127.0.0.1にして Request を送信する。
		25. ffufでJuicy Filesを探す
			1. pdf, document, video, api エンドポイント
				1. `curl -L 'https://web.archive.org/cdx/search/cdx?url={*.target.com}/*&output=text&fl=original&collapse=urlkey' > urls.txt`でURLを取得する
				2. ファイルを取得するサブドメインを特定（`files.target.com`)
				3. ファジングでPDFを取得するディレクトリを発見(`files.target.com/reports`)
				4. アーカイブされたURLを抽出して結果を手動で確認。機密 $10,000
			2. ログファイルの公開
				1. google dorks (`site:target.com -www -shop -documentation "logs"`)
				2. - `access.logs``error-logs``error-ssl.logs`なんかを覗いてヤバそうなら報告。
		26. （未対応）S3とかクラウド系
		27. # LDAP Null Bind（p3eqsy）
		28. HTTPパラメータポリューション
		29. LFI ブラウザコンソールからコマンド実行
