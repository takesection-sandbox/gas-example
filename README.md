Google Apps Script のサンプル
===

## clasp のインストール

```
npm i -g @google/clasp
```

## webpack 等のインストール

```
npm i --save-dev webpack webpack-cli gas-webpack-plugin
```

## package.json の scripts に webpack を追加

```javascript
scripts: {
    "webpack": "webpack",
}
```

## webpack.config.js ファイルの作成

```javascript
const path = require('path');
const GasPlugin = require('gas-webpack-plugin');

module.exports = {
    mode: 'production',
    entry: {
        main: path.resolve('./src', 'Code.js')
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'Code.js',
        library: {
            name: 'Code',
            type: 'var'
        }
    },
    plugins: [new GasPlugin()]
}
```

## テスト

```
AWS_ACCESS_KEY_ID=<YOUR ACCESS KEY> AWS_SECRET_ACCESS_KEY=<YOUR SECRET ACCESS KEY> ROLE_ARN=<YOUR ROLE ARN> npm test
```

## デプロイ

```
(cd dist; clasp pull); npm run webpack; (cd dist; clasp push)
```

## 参考

- [smithy545/aws-apps-scripts](https://github.com/smithy545/aws-apps-scripts)
