# SHIGOKU ワードリストディレクトリ

このディレクトリにワードリストを配置してください。
各サブディレクトリにメタデータ（metadata.yaml）を作成すると、SHIGOKU が自動選択できます。

## ディレクトリ構造

```
wordlists/
├── subdomain/     # サブドメイン列挙用
├── directory/     # ディレクトリブルートフォース用
├── api/           # APIエンドポイント用
├── params/        # パラメータ用
└── common/        # 汎用
```

## ワードリスト配置例

```
wordlists/subdomain/
├── metadata.yaml           # メタデータ定義
├── seclists-top5000.txt   # SecLists
├── jhaddix-all.txt        # JHaddix
└── assetnote-best.txt     # AssetNote
```
