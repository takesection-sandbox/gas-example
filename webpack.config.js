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
