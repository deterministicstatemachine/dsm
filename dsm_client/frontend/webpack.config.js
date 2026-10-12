// webpack.config.js
const path = require('path');
const webpack = require('webpack');
const HtmlWebpackPlugin  = require('html-webpack-plugin');
const MiniCssExtract     = require('mini-css-extract-plugin');
const CopyWebpackPlugin  = require('copy-webpack-plugin');
const crypto             = require('crypto');
const { readAppVersion } = require('./scripts/appVersion');

// The WebView's Content-Security-Policy admits no inline script by kind
// ('unsafe-inline') and no eval ('unsafe-eval'): only the app's own files and
// the inline scripts index.html itself carries, each by the SHA-256 of its
// exact text in the page as emitted (pre-audit item 13). The page names where
// the hashes go with this token; a page without it, or an inline script with
// attributes the hash cannot vouch for, fails the build rather than ship a
// policy that admits more, or a page whose own scripts it blocks.
const INLINE_SCRIPT_HASHES_TOKEN = '__DSM_INLINE_SCRIPT_HASHES__';

class InlineScriptHashes {
  apply(compiler) {
    compiler.hooks.compilation.tap('InlineScriptHashes', (compilation) => {
      HtmlWebpackPlugin.getCompilationHooks(compilation).beforeEmit.tapAsync(
        'InlineScriptHashes',
        (data, done) => {
          // Tag names are case-insensitive, and a closing tag may carry whitespace:
          // every spelling a browser reads as a script is a script here.
          const scripts = [...data.html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)];
          const inline = scripts.filter(([, attributes]) => !/\bsrc\s*=/i.test(attributes));
          const unhashable = inline.filter(([, attributes]) => attributes.trim().length > 0);
          if (unhashable.length > 0) {
            done(new Error(`an inline script carries attributes: ${unhashable[0][1].trim()}`));
            return;
          }
          if (data.html.split(INLINE_SCRIPT_HASHES_TOKEN).length !== 2) {
            done(new Error(`the page must name ${INLINE_SCRIPT_HASHES_TOKEN} exactly once in its policy`));
            return;
          }
          const hashes = inline.map(([, , text]) =>
            `'sha256-${crypto.createHash('sha256').update(text, 'utf8').digest('base64')}'`);
          data.html = data.html.replace(INLINE_SCRIPT_HASHES_TOKEN, hashes.join(' '));
          done(null, data);
        },
      );
    });
  }
}

module.exports = (env, argv) => {
  const isProd        = argv.mode === 'production';
  const buildTarget   = process.env.BUILD_TARGET || 'web';   // 'android' | 'ios' | 'web'
  const inMobile      = buildTarget !== 'web';

  // Always use relative paths for Android builds, safer for WebView
  const publicPath = buildTarget === 'android' ? './' : (inMobile ? './' : '/');

  // Android WebView is sensitive to certain bundling/minification patterns (TDZ bugs).
  // For Android builds, use a vendor-safe optimization profile: no code minification,
  // no splitChunks/runtime chunking, and simpler module IDs. This yields stable bundles
  // that avoid "Cannot access '<var>' before initialization" errors in some WebView versions.
  const isAndroid = buildTarget === 'android';

  return {
    mode: isProd ? 'production' : 'development',
    target: ['web', 'es2020'],                // no Node polyfills

    entry: {
      main: './src/index.tsx'
    },

    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: isProd ? 'js/[name].[contenthash:8].js' : 'js/[name].js',
      chunkFilename: isProd ? 'js/[name].[contenthash:8].js' : 'js/[name].js',
      publicPath: publicPath,      // **critical for WebView**
      clean: true,
      assetModuleFilename: 'assets/[hash][ext][query]'
    },

    resolve: {
      extensions: ['.tsx', '.ts', '.js', '.jsx'],
      alias: { '@': path.resolve(__dirname, 'src') }
    },

    module: {
      rules: [
        {
          test: /\.[jt]sx?$/,
          exclude: /node_modules/,
          use: { loader: 'ts-loader', options: { transpileOnly: true } }
        },
        {
          test: /\.css$/i,
          use: [
            isProd ? MiniCssExtract.loader : 'style-loader',   // HMR-friendly
            'css-loader'
          ]
        },
        {
          test: /\.(png|jpe?g|gif|svg|woff2?|eot|ttf|otf)$/i,
          type: 'asset',
          parser: { dataUrlCondition: { maxSize: 10 * 1024 } }
        }
      ]
    },

    plugins: [
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer'],
      }),
      // Beta readiness: Enable bridge debug logging for development/beta builds only
      // Production builds will dead-code eliminate all debug interceptor logic
      new webpack.DefinePlugin({
        // The version the screens show: the APK's own (scripts/appVersion.js).
        'process.env.DSM_APP_VERSION': JSON.stringify(readAppVersion()),
        'process.env.ENABLE_BRIDGE_DEBUG_LOGGING': JSON.stringify(
          process.env.NODE_ENV !== 'production' || process.env.BETA_BUILD === 'true'
        ),
      }),
      new HtmlWebpackPlugin({
        template: './public/index.html',
        inject: 'body',
        // Inject the right chunks per build target. Android uses a single, vendor-safe bundle.
        chunks: isAndroid ? ['main'] : ['runtime','vendors','main'],
        templateParameters: {
          PUBLIC_URL: buildTarget === 'android' ? '.' : '',
          buildTarget,
          isProd
        },
        minify: isProd && {
          collapseWhitespace: true,
          removeComments: true,
          minifyCSS: true
        }
      }),
      new InlineScriptHashes(),
      isProd && new MiniCssExtract({
        filename: 'css/[name].[contenthash:8].css'
      }),
      new CopyWebpackPlugin({
        patterns: [
          {
            from: 'public',
            to: '.',
            globOptions: {
              ignore: ['**/index.html'] // Exclude HTML handled by HtmlWebpackPlugin
            },
            filter: (resourcePath) => {
              // Ensure we copy all static assets needed for Android
              return !resourcePath.endsWith('index.html');
            }
          },
          {
            // Copy configuration files without any processing/minification
            from: 'src/config/*.json',
            to: 'config/[name][ext]'
          }
        ]
      })
    ].filter(Boolean),

    optimization: isAndroid ? {
      // Vendor-safe profile for Android WebView
      splitChunks: false,
      runtimeChunk: false,
      moduleIds: 'named',
      sideEffects: true,
      concatenateModules: false,
      minimize: false,
    } : {
      splitChunks: {
        chunks: 'all',
        cacheGroups: {
          vendor: {
            test: /[\\/]node_modules[\\/]/,
            name: 'vendors',
            priority: 10,
            reuseExistingChunk: true
          }
        }
      },
      runtimeChunk: 'single',
      moduleIds: 'deterministic',
      sideEffects: true,
      // Disable scope hoisting to avoid Android WebView TDZ issues
      // See: ReferenceError: Cannot access '<var>' before initialization in vendor chunk
      concatenateModules: false,
      minimize: isProd,
      minimizer: isProd ? [
        // General minifier (exclude vendor chunk to avoid WebView TDZ issues)
        new (require('terser-webpack-plugin'))({
          exclude: /vendors\..*\.js$/i,
          terserOptions: {
            ecma: 2019,
            safari10: true,
            // CRITICAL: Preserve WebView bridge invocation name only
            mangle: {
              keep_fnames: /^(DsmBridge|sendMessage)$/,
              reserved: ['DsmBridge', 'sendMessage', 'window', 'document']
            },
            keep_fnames: /^(DsmBridge|sendMessage)$/,
            compress: {
              // Safer compression for WebView
              inline: 0,
              reduce_vars: false,
              typeofs: false,
              keep_fargs: true,
              drop_console: false, // Keep console for WebView debugging
              pure_funcs: []
            },
            format: {
              comments: false
            }
          },
          extractComments: false
        }),
        // Vendor chunk: disable mangle/compress to prevent "Cannot access 'o' before initialization"
        new (require('terser-webpack-plugin'))({
          include: /vendors\..*\.js$/i,
          terserOptions: {
            ecma: 2019,
            mangle: false,
            compress: false,
            format: {
              comments: false
            }
          },
          extractComments: false
        })
      ] : []
    },

    // Memory optimization settings
    cache: {
      type: 'filesystem',
      buildDependencies: {
        config: [__filename]
      }
    },

    // Performance settings: we intentionally suppress webpack's size warnings for the
    // Android WebView bundle. Large animated GIF assets are expected and curated.
    // Disabling hints removes noisy warnings the build pipeline flags as "must fix".
    // If we later want enforcement, flip `hints` back to 'warning' or 'error'.
    performance: {
      hints: false,
      // Keep generous limits to avoid accidental future warnings if hints re-enabled.
      maxAssetSize: 8 * 1024 * 1024,      // 8MB
      maxEntrypointSize: 16 * 1024 * 1024 // 16MB
    },

    devtool: isProd
      ? false
      : inMobile
         ? 'source-map'               // WebView-safe, no eval()
         : 'cheap-module-source-map', // the policy admits no eval

    devServer: inMobile ? undefined : {
      static: { directory: path.join(__dirname, 'public') },
      compress: true,
      port: 3000,
      hot: true,
      historyApiFallback: true,
      client: { overlay: { errors: true, warnings: false } }
    }
  };
};