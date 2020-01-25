/* global process */

const path = require('path');
const webpack = require('webpack');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const CopyPlugin = require('copy-webpack-plugin');
const childProcess = require('child_process');
const packageVersion = require("./package.json").version;
const buildVersion = childProcess.execSync('git rev-list HEAD --count').toString();

function makeConfig(mode) {
  let config = {
        entry: ['./src/js/app.js', './src/scss/app.scss'],

        target: 'web',

        output: {
          path: path.resolve('dist'),
          filename: 'js/main.js'
        },

        module: {
          rules: [
            {
              test: /\.(png|woff|woff2|eot|ttf|svg)(\?v=[0-9]\.[0-9]\.[0-9])?$/,
              use: [ { loader: 'url-loader' } ]
            },
            {
              test: /\.scss$/,
              use: ['style-loader',
                    {
                      loader: MiniCssExtractPlugin.loader,
                      options: {
                        hmr: mode === 'development',
                      },
                    },
                    'css-loader', 'sass-loader']
            }]
        },
        plugins: [
          new CopyPlugin([
            { from: 'src/index.html', to: 'index.html' },
          ]),

          /* use jQuery as Global */
          new webpack.ProvidePlugin({
            jQuery: "jquery",
            $: "jquery",
            'window.jQuery': 'jquery',
            Popper: ['popper.js', 'default']
          }),
          new MiniCssExtractPlugin({
            filename: 'css/[name].css'
          }),
          new webpack.DefinePlugin({
            BUILD_VERSION: JSON.stringify(packageVersion + '.' + buildVersion)
          })
        ]
      };

  if (mode === 'development') {
    config.devtool = 'source-map';
    config.output.sourceMapFilename = '[file].map';
  }

  return config;
}


module.exports = (env, argv) => {
  return makeConfig(argv.mode);
};
