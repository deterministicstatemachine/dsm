#!/bin/bash

# DSM Frontend Development Helper Script

echo "🚀 DSM Frontend Development Tools"
echo "=================================="

case "$1" in
  "build")
    echo "📦 Building frontend..."
    npm run build:webpack
    ;;
  "dev")
    echo "🔧 Starting development server..."
    npm start
    ;;
  "test")
    echo "🧪 Running tests..."
    npm test
    ;;
  "lint")
    echo "🔍 Running linter..."
    npm run lint
    ;;
  "type-check")
    echo "📝 Running TypeScript type check..."
    npm run type-check
    ;;
  "clean")
    echo "🧹 Cleaning build artifacts..."
    npm run clean
    ;;
  "android-build")
    echo "🤖 Building for Android..."
    npm run build:android
    ;;
  "check-bridge")
    echo "🔗 Checking native bridge..."
    echo "ℹ️  Using MCP Browser Adapter (single path)"
    ;;
  "serve-test")
    echo "🌐 Serving test page..."
    if [ ! -d "dist" ]; then
      echo "❌ dist directory not found. Run 'build' first."
      exit 1
    fi
    cd dist && python3 -m http.server 8080
    ;;
  *)
    echo "Usage: $0 {build|dev|test|lint|type-check|clean|android-build|check-bridge|serve-test}"
    echo ""
    echo "Commands:"
    echo "  build         - Build the frontend for production"
    echo "  dev           - Start development server"
    echo "  test          - Run unit tests"
    echo "  lint          - Run ESLint"
    echo "  type-check    - Run TypeScript type checking"
    echo "  clean         - Clean build artifacts"
    echo "  android-build - Build for Android deployment"
    echo "  check-bridge  - Verify bridge files exist"
    echo "  serve-test    - Serve test page on port 8080"
    ;;
esac
